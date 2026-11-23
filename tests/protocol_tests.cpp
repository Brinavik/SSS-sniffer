// Protocol and filter tests. Frames are synthesized in memory, so the tests run
// without Npcap, without a network adapter and without capturing anything.
//
//   sss_tests    exits 0 when every check passes

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstring>

#include "filter/FilterExpression.h"
#include "model/PacketRecord.h"
#include "protocol/Dissector.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const QString &what)
{
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::printf("FAIL: %s\n", what.toLocal8Bit().constData());
    }
}

void appendU16(QByteArray &buffer, quint16 value)
{
    buffer.append(static_cast<char>((value >> 8) & 0xFF));
    buffer.append(static_cast<char>(value & 0xFF));
}

void appendU32(QByteArray &buffer, quint32 value)
{
    buffer.append(static_cast<char>((value >> 24) & 0xFF));
    buffer.append(static_cast<char>((value >> 16) & 0xFF));
    buffer.append(static_cast<char>((value >> 8) & 0xFF));
    buffer.append(static_cast<char>(value & 0xFF));
}

QByteArray ethernet(const QByteArray &payload, quint16 etherType)
{
    QByteArray frame;
    for (int i = 0; i < 6; ++i) {
        frame.append(static_cast<char>(0x10 + i)); // destination MAC
    }
    for (int i = 0; i < 6; ++i) {
        frame.append(static_cast<char>(0x20 + i)); // source MAC
    }
    appendU16(frame, etherType);
    frame.append(payload);
    return frame;
}

QByteArray ipv4(quint8 protocol, const QByteArray &payload, int declaredTotalLength = -1)
{
    QByteArray ip;
    ip.append(static_cast<char>(0x45));
    ip.append(static_cast<char>(0x00));
    const int total = (declaredTotalLength >= 0) ? declaredTotalLength : (20 + payload.size());
    appendU16(ip, static_cast<quint16>(total));
    appendU16(ip, 0x1234);
    appendU16(ip, 0x4000);
    ip.append(static_cast<char>(64));
    ip.append(static_cast<char>(protocol));
    appendU16(ip, 0);
    ip.append(static_cast<char>(192));
    ip.append(static_cast<char>(168));
    ip.append(static_cast<char>(1));
    ip.append(static_cast<char>(10));
    ip.append(static_cast<char>(93));
    ip.append(static_cast<char>(184));
    ip.append(static_cast<char>(216));
    ip.append(static_cast<char>(34));
    ip.append(payload);
    return ip;
}

QByteArray tcp(quint16 sourcePort, quint16 destinationPort, const QByteArray &payload = {})
{
    QByteArray segment;
    appendU16(segment, sourcePort);
    appendU16(segment, destinationPort);
    appendU32(segment, 1000);
    appendU32(segment, 2000);
    segment.append(static_cast<char>(0x50));
    segment.append(static_cast<char>(0x18));
    appendU16(segment, 64240);
    appendU16(segment, 0);
    appendU16(segment, 0);
    segment.append(payload);
    return segment;
}

QByteArray udp(quint16 sourcePort, quint16 destinationPort, const QByteArray &payload)
{
    QByteArray datagram;
    appendU16(datagram, sourcePort);
    appendU16(datagram, destinationPort);
    appendU16(datagram, static_cast<quint16>(8 + payload.size()));
    appendU16(datagram, 0);
    datagram.append(payload);
    return datagram;
}

QByteArray icmpEcho(quint8 type)
{
    QByteArray message;
    message.append(static_cast<char>(type));
    message.append(static_cast<char>(0));
    appendU16(message, 0);
    appendU16(message, 1);
    appendU16(message, 7);
    message.append("abcdefgh");
    return message;
}

// Base IPv6 header. `nextHeader` is the first header after the fixed 40 bytes.
QByteArray ipv6(quint8 nextHeader, const QByteArray &payload)
{
    QByteArray header;
    header.append(static_cast<char>(0x60));
    header.append(static_cast<char>(0x00));
    header.append(static_cast<char>(0x00));
    header.append(static_cast<char>(0x00));
    appendU16(header, static_cast<quint16>(payload.size()));
    header.append(static_cast<char>(nextHeader));
    header.append(static_cast<char>(64));
    for (int i = 0; i < 15; ++i) {
        header.append(static_cast<char>(0x00));
    }
    header.append(static_cast<char>(0x01)); // source ::1
    for (int i = 0; i < 15; ++i) {
        header.append(static_cast<char>(0x00));
    }
    header.append(static_cast<char>(0x01)); // destination ::1
    header.append(payload);
    return header;
}

QByteArray ipv6FragmentHeader(quint8 nextHeader, quint16 offsetInBytes, bool moreFragments)
{
    QByteArray header;
    header.append(static_cast<char>(nextHeader));
    header.append(static_cast<char>(0x00));
    quint16 field = static_cast<quint16>((offsetInBytes / 8) << 3);
    if (moreFragments) {
        field = static_cast<quint16>(field | 0x0001);
    }
    appendU16(header, field);
    appendU32(header, 0xCAFEBABE);
    return header;
}

// BSD loopback header: a 4 byte host order address family in front of the frame.
QByteArray loopback(quint32 family, const QByteArray &payload)
{
    QByteArray frame;
    frame.append(static_cast<char>(family & 0xFF));
    frame.append(static_cast<char>((family >> 8) & 0xFF));
    frame.append(static_cast<char>((family >> 16) & 0xFF));
    frame.append(static_cast<char>((family >> 24) & 0xFF));
    frame.append(payload);
    return frame;
}

sss::protocol::Dissection dissect(const QByteArray &frame, int linkType = 1)
{
    return sss::protocol::dissectFrame(reinterpret_cast<const uchar *>(frame.constData()),
                                       static_cast<int>(frame.size()),
                                       static_cast<int>(frame.size()),
                                       linkType,
                                       1,
                                       QDateTime::currentDateTime());
}

sss::model::PacketRecord httpRecord()
{
    sss::model::PacketRecord record;
    record.protocol = QStringLiteral("HTTP");
    record.source = QStringLiteral("127.0.0.1");
    record.destination = QStringLiteral("127.0.0.1");
    record.sourcePort = 52312;
    record.destinationPort = 80;
    record.length = 200;
    record.info = QStringLiteral("GET /index.html HTTP/1.1");
    record.ipVersion = 4;
    record.ipProtocol = 6;
    return record;
}

void testEthernetTcp()
{
    const QByteArray frame = ethernet(ipv4(6, tcp(52312, 80)), 0x0800);
    const auto result = dissect(frame);

    check(result.protocol == QStringLiteral("TCP"), QStringLiteral("IPv4/TCP protocol"));
    check(result.source == QStringLiteral("192.168.1.10"), QStringLiteral("IPv4/TCP source"));
    check(result.destination == QStringLiteral("93.184.216.34"), QStringLiteral("IPv4/TCP destination"));
    check(result.sourcePort == 52312, QStringLiteral("IPv4/TCP source port"));
    check(result.destinationPort == 80, QStringLiteral("IPv4/TCP destination port"));
    check(result.ipVersion == 4, QStringLiteral("IPv4/TCP version"));
    check(!result.details.isEmpty(), QStringLiteral("IPv4/TCP detail tree"));
}

void testHttp()
{
    const QByteArray request =
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    const QByteArray frame = ethernet(ipv4(6, tcp(52312, 80, request)), 0x0800);
    const auto result = dissect(frame);

    check(result.protocol == QStringLiteral("HTTP"), QStringLiteral("HTTP protocol"));
    check(result.info.startsWith(QStringLiteral("GET /index.html")), QStringLiteral("HTTP info line"));
    check(result.destinationPort == 80, QStringLiteral("HTTP destination port"));
}

void testDns()
{
    QByteArray query;
    appendU16(query, 0x1a2b);
    appendU16(query, 0x0100);
    appendU16(query, 1);
    appendU16(query, 0);
    appendU16(query, 0);
    appendU16(query, 0);
    for (const char *label : {"example", "com"}) {
        const int length = static_cast<int>(std::strlen(label));
        query.append(static_cast<char>(length));
        query.append(label);
    }
    query.append(static_cast<char>(0));
    appendU16(query, 1);
    appendU16(query, 1);

    const QByteArray frame = ethernet(ipv4(17, udp(52312, 53, query)), 0x0800);
    const auto result = dissect(frame);

    check(result.protocol == QStringLiteral("DNS"), QStringLiteral("DNS protocol"));
    check(result.info.contains(QStringLiteral("example.com")), QStringLiteral("DNS query name"));
    check(result.info.contains(QStringLiteral("0x1a2b")), QStringLiteral("DNS transaction id"));
}

void testIcmp()
{
    const QByteArray frame = ethernet(ipv4(1, icmpEcho(8)), 0x0800);
    const auto result = dissect(frame);

    check(result.protocol == QStringLiteral("ICMP"), QStringLiteral("ICMP protocol"));
    check(result.info.contains(QStringLiteral("Echo")), QStringLiteral("ICMP echo info"));
    check(result.ipProtocol == 1, QStringLiteral("ICMP protocol number"));
}

void testArp()
{
    QByteArray arp;
    appendU16(arp, 1);       // hardware type
    appendU16(arp, 0x0800);  // protocol type
    arp.append(static_cast<char>(6));
    arp.append(static_cast<char>(4));
    appendU16(arp, 1);       // request
    for (int i = 0; i < 6; ++i) {
        arp.append(static_cast<char>(0xAA));
    }
    arp.append(static_cast<char>(192));
    arp.append(static_cast<char>(168));
    arp.append(static_cast<char>(1));
    arp.append(static_cast<char>(10));
    for (int i = 0; i < 6; ++i) {
        arp.append(static_cast<char>(0x00));
    }
    arp.append(static_cast<char>(192));
    arp.append(static_cast<char>(168));
    arp.append(static_cast<char>(1));
    arp.append(static_cast<char>(1));

    const QByteArray frame = ethernet(arp, 0x0806);
    const auto result = dissect(frame);

    check(result.protocol == QStringLiteral("ARP"), QStringLiteral("ARP protocol"));
    check(result.source == QStringLiteral("192.168.1.10"), QStringLiteral("ARP sender address"));
    check(result.destination == QStringLiteral("192.168.1.1"), QStringLiteral("ARP target address"));
    check(result.info.contains(QStringLiteral("Who has")), QStringLiteral("ARP info"));
}

void testIpv6Tcp()
{
    const auto result = dissect(loopback(24, ipv6(6, tcp(443, 52312))), 0);

    check(result.protocol == QStringLiteral("TCP"), QStringLiteral("IPv6/TCP protocol"));
    check(result.ipVersion == 6, QStringLiteral("IPv6 version"));
    check(result.source == QStringLiteral("::1"), QStringLiteral("IPv6 compressed source"));
    check(result.destinationPort == 52312, QStringLiteral("IPv6/TCP destination port"));
}

void testIpv6Fragment()
{
    // Non-first fragment: the transport header is not present, so the dissector
    // must not invent TCP fields from the payload.
    QByteArray payload = ipv6FragmentHeader(6, 1480, false);
    payload.append(QByteArray(32, static_cast<char>(0x5A)));
    const auto fragment = dissect(loopback(24, ipv6(44, payload)), 0);

    check(fragment.protocol != QStringLiteral("TCP"), QStringLiteral("IPv6 fragment not parsed as TCP"));
    check(fragment.protocol != QStringLiteral("UDP"), QStringLiteral("IPv6 fragment not parsed as UDP"));
    check(fragment.sourcePort == 0 && fragment.destinationPort == 0,
          QStringLiteral("IPv6 fragment has no invented ports"));
    check(fragment.info.contains(QStringLiteral("fragment")), QStringLiteral("IPv6 fragment info"));

    // First fragment still carries the transport header and must be parsed.
    QByteArray firstPayload = ipv6FragmentHeader(6, 0, true);
    firstPayload.append(tcp(52312, 80));
    const auto first = dissect(loopback(24, ipv6(44, firstPayload)), 0);
    check(first.protocol == QStringLiteral("TCP"), QStringLiteral("IPv6 first fragment parses TCP"));
    check(first.destinationPort == 80, QStringLiteral("IPv6 first fragment port"));
}

void testMalformedIpv4()
{
    // total length smaller than the header length
    const QByteArray frame = ethernet(ipv4(6, tcp(1, 2), 8), 0x0800);
    const auto result = dissect(frame);
    check(result.protocol == QStringLiteral("Malformed"), QStringLiteral("IPv4 bad total length flagged"));
    check(result.sourcePort == 0, QStringLiteral("IPv4 bad total length has no ports"));
}

void testFilters()
{
    const sss::model::PacketRecord http = httpRecord();

    QString error;
    auto matches = [&](const QString &text) {
        error.clear();
        const auto expression = sss::filter::FilterExpression::parse(text, &error);
        return error.isEmpty() && expression.matches(http);
    };

    check(matches(QString()), QStringLiteral("filter: empty matches"));
    check(matches(QStringLiteral("http")), QStringLiteral("filter: http keyword"));
    check(matches(QStringLiteral("tcp")), QStringLiteral("filter: tcp keyword applies to HTTP"));
    check(!matches(QStringLiteral("udp")), QStringLiteral("filter: udp keyword"));
    check(!matches(QStringLiteral("not tcp")), QStringLiteral("filter: not"));
    check(matches(QStringLiteral("http and ip.src == 127.0.0.1")), QStringLiteral("filter: and + ip.src"));
    check(!matches(QStringLiteral("http and ip.src == 8.8.8.8")), QStringLiteral("filter: and mismatch"));
    check(matches(QStringLiteral("port == 80")), QStringLiteral("filter: port"));
    check(matches(QStringLiteral("dstport == 80")), QStringLiteral("filter: dstport"));
    check(!matches(QStringLiteral("dstport == 443")), QStringLiteral("filter: dstport mismatch"));
    check(matches(QStringLiteral("len > 100")), QStringLiteral("filter: len"));
    check(!matches(QStringLiteral("len < 100")), QStringLiteral("filter: len mismatch"));
    check(matches(QStringLiteral("info contains GET")), QStringLiteral("filter: contains"));
    check(!matches(QStringLiteral("info contains POST")), QStringLiteral("filter: contains mismatch"));
    check(matches(QStringLiteral("(http or dns) and len >= 200")), QStringLiteral("filter: parentheses"));
    // "and" binds tighter than "or": http || (dns && len < 100)
    check(matches(QStringLiteral("http or dns and len < 100")), QStringLiteral("filter: precedence"));

    error.clear();
    sss::filter::FilterExpression::parse(QStringLiteral("http and"), &error);
    check(!error.isEmpty(), QStringLiteral("filter: incomplete expression rejected"));

    error.clear();
    sss::filter::FilterExpression::parse(QStringLiteral("bogus"), &error);
    check(!error.isEmpty(), QStringLiteral("filter: unknown keyword rejected"));

    error.clear();
    sss::filter::FilterExpression::parse(QStringLiteral("len == abc"), &error);
    check(!error.isEmpty(), QStringLiteral("filter: non numeric length rejected"));

    error.clear();
    sss::filter::FilterExpression::parse(QStringLiteral("(tcp"), &error);
    check(!error.isEmpty(), QStringLiteral("filter: missing parenthesis rejected"));
}

} // namespace

int main()
{
    testEthernetTcp();
    testHttp();
    testDns();
    testIcmp();
    testArp();
    testIpv6Tcp();
    testIpv6Fragment();
    testMalformedIpv4();
    testFilters();

    std::printf("checks=%d failures=%d\n", g_checks, g_failures);
    std::printf("RESULT: %s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
