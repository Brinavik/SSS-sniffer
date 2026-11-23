// Synthesizes demo frames so the UI can be built before the capture module
// exists. Everything here is generated in memory; no socket or driver is used.
#include "model/SamplePackets.h"

namespace sss::model {
namespace {

constexpr quint16 kEtherTypeIPv4 = 0x0800;
constexpr quint8 kProtocolIcmp = 1;
constexpr quint8 kProtocolTcp = 6;
constexpr quint8 kProtocolUdp = 17;

const uchar kMacLocal[6] = {0x3c, 0x97, 0x0e, 0x11, 0x22, 0x33};
const uchar kMacGateway[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};

// ---------------------------------------------------------------- byte helpers

void appendU8(QByteArray &buffer, quint8 value)
{
    buffer.append(static_cast<char>(value));
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

void appendRaw(QByteArray &buffer, const uchar *data, int size)
{
    buffer.append(reinterpret_cast<const char *>(data), size);
}

quint32 sumWords(const QByteArray &data)
{
    const uchar *bytes = reinterpret_cast<const uchar *>(data.constData());
    quint32 sum = 0;
    for (int i = 0; i + 1 < data.size(); i += 2) {
        sum += (static_cast<quint32>(bytes[i]) << 8) | bytes[i + 1];
    }
    if (data.size() % 2 != 0) {
        sum += static_cast<quint32>(bytes[data.size() - 1]) << 8;
    }
    return sum;
}

quint16 foldChecksum(quint32 sum)
{
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<quint16>(~sum & 0xFFFF);
}

QByteArray ipv4Address(const QString &text)
{
    QByteArray bytes;
    const QStringList parts = text.split(QLatin1Char('.'));
    for (const QString &part : parts) {
        bytes.append(static_cast<char>(part.toInt()));
    }
    return bytes;
}

QString macText(const uchar *mac)
{
    QString text;
    for (int i = 0; i < 6; ++i) {
        if (i != 0) {
            text += QLatin1Char(':');
        }
        text += QString("%1").arg(mac[i], 2, 16, QLatin1Char('0'));
    }
    return text.toUpper();
}

// ------------------------------------------------------------ frame builders

QByteArray buildEthernet(const uchar *destination, const uchar *source, quint16 etherType)
{
    QByteArray frame;
    appendRaw(frame, destination, 6);
    appendRaw(frame, source, 6);
    appendU16(frame, etherType);
    return frame;
}

QByteArray buildIpv4(const QByteArray &source, const QByteArray &destination,
                     quint8 protocol, quint16 totalLength, quint8 ttl, quint16 id)
{
    QByteArray header;
    appendU8(header, 0x45);          // version 4, header length 5 words
    appendU8(header, 0x00);          // DSCP / ECN
    appendU16(header, totalLength);
    appendU16(header, id);
    appendU16(header, 0x4000);       // don't fragment
    appendU8(header, ttl);
    appendU8(header, protocol);
    appendU16(header, 0);            // checksum placeholder
    header.append(source);
    header.append(destination);

    const quint16 checksum = foldChecksum(sumWords(header));
    header[10] = static_cast<char>((checksum >> 8) & 0xFF);
    header[11] = static_cast<char>(checksum & 0xFF);
    return header;
}

QByteArray buildTcp(quint16 sourcePort, quint16 destinationPort, quint32 sequence,
                    quint32 acknowledgment, quint8 flags, quint16 window,
                    const QByteArray &payload, const QByteArray &ipSource, const QByteArray &ipDestination)
{
    QByteArray segment;
    appendU16(segment, sourcePort);
    appendU16(segment, destinationPort);
    appendU32(segment, sequence);
    appendU32(segment, acknowledgment);
    appendU8(segment, 0x50);         // data offset: 5 words, no options
    appendU8(segment, flags);
    appendU16(segment, window);
    appendU16(segment, 0);           // checksum placeholder
    appendU16(segment, 0);           // urgent pointer
    segment.append(payload);

    QByteArray pseudo;
    pseudo.append(ipSource);
    pseudo.append(ipDestination);
    appendU8(pseudo, 0);
    appendU8(pseudo, kProtocolTcp);
    appendU16(pseudo, static_cast<quint16>(segment.size()));
    pseudo.append(segment);

    const quint16 checksum = foldChecksum(sumWords(pseudo));
    segment[16] = static_cast<char>((checksum >> 8) & 0xFF);
    segment[17] = static_cast<char>(checksum & 0xFF);
    return segment;
}

QByteArray buildUdp(quint16 sourcePort, quint16 destinationPort, const QByteArray &payload,
                    const QByteArray &ipSource, const QByteArray &ipDestination)
{
    QByteArray datagram;
    appendU16(datagram, sourcePort);
    appendU16(datagram, destinationPort);
    appendU16(datagram, static_cast<quint16>(8 + payload.size()));
    appendU16(datagram, 0);          // checksum placeholder
    datagram.append(payload);

    QByteArray pseudo;
    pseudo.append(ipSource);
    pseudo.append(ipDestination);
    appendU8(pseudo, 0);
    appendU8(pseudo, kProtocolUdp);
    appendU16(pseudo, static_cast<quint16>(datagram.size()));
    pseudo.append(datagram);

    quint16 checksum = foldChecksum(sumWords(pseudo));
    if (checksum == 0) {
        checksum = 0xFFFF;
    }
    datagram[6] = static_cast<char>((checksum >> 8) & 0xFF);
    datagram[7] = static_cast<char>(checksum & 0xFF);
    return datagram;
}

QByteArray buildIcmpEcho(quint8 type, quint16 id, quint16 sequence, const QByteArray &payload)
{
    QByteArray message;
    appendU8(message, type);
    appendU8(message, 0);            // code
    appendU16(message, 0);           // checksum placeholder
    appendU16(message, id);
    appendU16(message, sequence);
    message.append(payload);

    const quint16 checksum = foldChecksum(sumWords(message));
    message[2] = static_cast<char>((checksum >> 8) & 0xFF);
    message[3] = static_cast<char>(checksum & 0xFF);
    return message;
}

QByteArray buildDnsQuery(quint16 id, const QString &name)
{
    QByteArray data;
    appendU16(data, id);
    appendU16(data, 0x0100);         // standard query, recursion desired
    appendU16(data, 1);              // question count
    appendU16(data, 0);
    appendU16(data, 0);
    appendU16(data, 0);
    const QStringList labels = name.split(QLatin1Char('.'));
    for (const QString &label : labels) {
        data.append(static_cast<char>(label.size()));
        data.append(label.toLatin1());
    }
    data.append('\0');
    appendU16(data, 1);              // type A
    appendU16(data, 1);              // class IN
    return data;
}

QByteArray buildDnsResponse(quint16 id, const QString &name, const QString &address)
{
    QByteArray data;
    appendU16(data, id);
    appendU16(data, 0x8180);         // standard response, recursion available
    appendU16(data, 1);              // question count
    appendU16(data, 1);              // answer count
    appendU16(data, 0);
    appendU16(data, 0);
    const QStringList labels = name.split(QLatin1Char('.'));
    for (const QString &label : labels) {
        data.append(static_cast<char>(label.size()));
        data.append(label.toLatin1());
    }
    data.append('\0');
    appendU16(data, 1);              // type A
    appendU16(data, 1);              // class IN
    appendU16(data, 0xC00C);         // compressed name pointer to offset 12
    appendU16(data, 1);              // type A
    appendU16(data, 1);              // class IN
    appendU32(data, 60);             // TTL
    appendU16(data, 4);              // RDLENGTH
    data.append(ipv4Address(address));
    return data;
}

// ------------------------------------------------------------ detail helpers

DetailNode makeNode(const QString &name, const QString &value = QString())
{
    DetailNode node;
    node.name = name;
    node.value = value;
    return node;
}

QString protocolName(quint8 protocol)
{
    switch (protocol) {
    case kProtocolIcmp:
        return QStringLiteral("ICMP (1)");
    case kProtocolTcp:
        return QStringLiteral("TCP (6)");
    case kProtocolUdp:
        return QStringLiteral("UDP (17)");
    default:
        return QString::number(protocol);
    }
}

// One frame, described by its parts; assemble() turns it into wire bytes plus
// the protocol tree the detail pane renders.
struct FrameParts
{
    QString ipSource;
    QString ipDestination;
    quint8 ipProtocol = kProtocolTcp;
    quint8 ttl = 64;
    quint16 sourcePort = 0;
    quint16 destinationPort = 0;
    QByteArray segment;
    QString transportTitle;
    QVector<DetailNode> transportFields;
    QVector<DetailNode> applicationNodes;
    QString summaryProtocol;
    QString summaryInfo;
    QString protocolChain;
};

PacketRecord assemble(quint64 index, const QDateTime &timestamp, const FrameParts &parts)
{
    PacketRecord record;
    record.index = index;
    record.timestamp = timestamp;
    record.source = parts.ipSource;
    record.destination = parts.ipDestination;
    record.protocol = parts.summaryProtocol;
    record.info = parts.summaryInfo;
    record.ipVersion = 4;
    record.ipProtocol = parts.ipProtocol;
    record.sourcePort = parts.sourcePort;
    record.destinationPort = parts.destinationPort;

    const QByteArray source = ipv4Address(parts.ipSource);
    const QByteArray destination = ipv4Address(parts.ipDestination);
    const quint16 totalLength = static_cast<quint16>(20 + parts.segment.size());
    const QByteArray ipHeader = buildIpv4(source, destination, parts.ipProtocol, totalLength,
                                          parts.ttl, static_cast<quint16>(index & 0xFFFF));

    record.raw = buildEthernet(kMacGateway, kMacLocal, kEtherTypeIPv4) + ipHeader + parts.segment;
    record.length = record.raw.size();

    DetailNode frame = makeNode(QString("Frame %1: %2 bytes on wire").arg(index).arg(record.length));
    frame.children.append(makeNode("Arrival Time", timestamp.toString("yyyy-MM-dd HH:mm:ss.zzz")));
    frame.children.append(makeNode("Frame Length", QString("%1 bytes").arg(record.length)));
    frame.children.append(makeNode("Protocols in frame", parts.protocolChain));

    DetailNode ethernet = makeNode(QString("Ethernet II, Src: %1, Dst: %2")
                                       .arg(macText(kMacLocal), macText(kMacGateway)));
    ethernet.children.append(makeNode("Type", "IPv4 (0x0800)"));

    DetailNode internet = makeNode(QString("Internet Protocol Version 4, Src: %1, Dst: %2")
                                       .arg(parts.ipSource, parts.ipDestination));
    internet.children.append(makeNode("Version", "4"));
    internet.children.append(makeNode("Header Length", "20 bytes"));
    internet.children.append(makeNode("Total Length", QString::number(totalLength)));
    internet.children.append(makeNode("Time to Live", QString::number(parts.ttl)));
    internet.children.append(makeNode("Protocol", protocolName(parts.ipProtocol)));

    DetailNode transport = makeNode(parts.transportTitle);
    transport.children = parts.transportFields;

    record.details = {frame, ethernet, internet, transport};
    record.details += parts.applicationNodes;
    return record;
}

// --------------------------------------------------------------- demo packet

FrameParts makeHttpGet(quint32 sequence)
{
    FrameParts parts;
    parts.ipSource = QStringLiteral("192.168.1.100");
    parts.ipDestination = QStringLiteral("93.184.216.34");
    parts.summaryProtocol = QStringLiteral("HTTP");
    parts.summaryInfo = QStringLiteral("GET /index.html HTTP/1.1");
    parts.sourcePort = 52312;
    parts.destinationPort = 80;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:tcp:http");

    const QByteArray request = "GET /index.html HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "User-Agent: SSS-Sniffer/0.1\r\n"
                               "Accept: */*\r\n"
                               "\r\n";

    parts.segment = buildTcp(52312, 80, sequence, 1, 0x18, 64240, request,
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QString("Transmission Control Protocol, Src Port: 52312, Dst Port: 80, Len: %1")
                               .arg(request.size());
    parts.transportFields = {
        makeNode("Source Port", "52312"),
        makeNode("Destination Port", "80"),
        makeNode("Sequence Number", QString::number(sequence)),
        makeNode("Acknowledgment Number", "1"),
        makeNode("Flags", "0x018 (PSH, ACK)"),
        makeNode("Window", "64240"),
        makeNode("Payload Length", QString::number(request.size())),
    };

    DetailNode http = makeNode(QStringLiteral("Hypertext Transfer Protocol"));
    http.children = {
        makeNode("Request Method", "GET"),
        makeNode("Request URI", "/index.html"),
        makeNode("Request Version", "HTTP/1.1"),
        makeNode("Host", "example.com"),
        makeNode("User-Agent", "SSS-Sniffer/0.1"),
    };
    parts.applicationNodes = {http};
    return parts;
}

FrameParts makeHttpResponse(quint32 sequence)
{
    FrameParts parts;
    parts.ipSource = QStringLiteral("93.184.216.34");
    parts.ipDestination = QStringLiteral("192.168.1.100");
    parts.summaryProtocol = QStringLiteral("HTTP");
    parts.summaryInfo = QStringLiteral("HTTP/1.1 200 OK  (text/html)");
    parts.sourcePort = 80;
    parts.destinationPort = 52312;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:tcp:http");

    const QByteArray response = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html; charset=UTF-8\r\n"
                                "Content-Length: 1256\r\n"
                                "Server: ECS (dcb/7F83)\r\n"
                                "\r\n";

    parts.segment = buildTcp(80, 52312, sequence, 1, 0x18, 64240, response,
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QString("Transmission Control Protocol, Src Port: 80, Dst Port: 52312, Len: %1")
                               .arg(response.size());
    parts.transportFields = {
        makeNode("Source Port", "80"),
        makeNode("Destination Port", "52312"),
        makeNode("Sequence Number", QString::number(sequence)),
        makeNode("Acknowledgment Number", "1"),
        makeNode("Flags", "0x018 (PSH, ACK)"),
        makeNode("Window", "64240"),
        makeNode("Payload Length", QString::number(response.size())),
    };

    DetailNode http = makeNode(QStringLiteral("Hypertext Transfer Protocol"));
    http.children = {
        makeNode("Response Version", "HTTP/1.1"),
        makeNode("Status Code", "200"),
        makeNode("Response Phrase", "OK"),
        makeNode("Content-Type", "text/html; charset=UTF-8"),
        makeNode("Content-Length", "1256"),
    };
    parts.applicationNodes = {http};
    return parts;
}

FrameParts makeDnsQuery(quint32 sequence)
{
    Q_UNUSED(sequence);
    FrameParts parts;
    parts.ipSource = QStringLiteral("192.168.1.100");
    parts.ipDestination = QStringLiteral("8.8.8.8");
    parts.ipProtocol = kProtocolUdp;
    parts.summaryProtocol = QStringLiteral("DNS");
    parts.summaryInfo = QStringLiteral("Standard query 0x1a2b A example.com");
    parts.sourcePort = 52312;
    parts.destinationPort = 53;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:udp:dns");

    const QByteArray query = buildDnsQuery(0x1a2b, QStringLiteral("example.com"));
    parts.segment = buildUdp(52312, 53, query,
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QStringLiteral("User Datagram Protocol, Src Port: 52312, Dst Port: 53");
    parts.transportFields = {
        makeNode("Source Port", "52312"),
        makeNode("Destination Port", "53"),
        makeNode("Length", QString::number(query.size() + 8)),
        makeNode("Checksum", "0x0000 [valid]"),
    };

    DetailNode dns = makeNode(QStringLiteral("Domain Name System (query)"));
    dns.children = {
        makeNode("Transaction ID", "0x1a2b"),
        makeNode("Flags", "0x0100 Standard query"),
        makeNode("Questions", "1"),
        makeNode("Query Name", "example.com"),
        makeNode("Type", "A (1)"),
        makeNode("Class", "IN (1)"),
    };
    parts.applicationNodes = {dns};
    return parts;
}

FrameParts makeDnsResponse(quint32 sequence)
{
    Q_UNUSED(sequence);
    FrameParts parts;
    parts.ipSource = QStringLiteral("8.8.8.8");
    parts.ipDestination = QStringLiteral("192.168.1.100");
    parts.ipProtocol = kProtocolUdp;
    parts.summaryProtocol = QStringLiteral("DNS");
    parts.summaryInfo = QStringLiteral("Standard query response 0x1a2b A example.com A 93.184.216.34");
    parts.sourcePort = 53;
    parts.destinationPort = 52312;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:udp:dns");

    const QByteArray response = buildDnsResponse(0x1a2b, QStringLiteral("example.com"),
                                                 QStringLiteral("93.184.216.34"));
    parts.segment = buildUdp(53, 52312, response,
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QStringLiteral("User Datagram Protocol, Src Port: 53, Dst Port: 52312");
    parts.transportFields = {
        makeNode("Source Port", "53"),
        makeNode("Destination Port", "52312"),
        makeNode("Length", QString::number(response.size() + 8)),
        makeNode("Checksum", "0x0000 [valid]"),
    };

    DetailNode dns = makeNode(QStringLiteral("Domain Name System (response)"));
    dns.children = {
        makeNode("Transaction ID", "0x1a2b"),
        makeNode("Flags", "0x8180 Standard query response, No error"),
        makeNode("Questions", "1"),
        makeNode("Answer RRs", "1"),
        makeNode("Query Name", "example.com"),
        makeNode("Answers", "example.com: type A, class IN, addr 93.184.216.34, ttl 60"),
    };
    parts.applicationNodes = {dns};
    return parts;
}

FrameParts makeTcpSyn(quint32 sequence)
{
    Q_UNUSED(sequence);
    FrameParts parts;
    parts.ipSource = QStringLiteral("192.168.1.100");
    parts.ipDestination = QStringLiteral("140.82.114.4");
    parts.summaryProtocol = QStringLiteral("TCP");
    parts.summaryInfo = QStringLiteral("52315 -> 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460");
    parts.sourcePort = 52315;
    parts.destinationPort = 443;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:tcp");

    parts.segment = buildTcp(52315, 443, 0, 0, 0x02, 64240, QByteArray(),
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QStringLiteral("Transmission Control Protocol, Src Port: 52315, Dst Port: 443, Len: 0");
    parts.transportFields = {
        makeNode("Source Port", "52315"),
        makeNode("Destination Port", "443"),
        makeNode("Sequence Number", "0 (relative)"),
        makeNode("Flags", "0x002 (SYN)"),
        makeNode("Window", "64240"),
        makeNode("MSS", "1460 bytes"),
    };
    return parts;
}

FrameParts makeTcpAck(quint32 sequence)
{
    FrameParts parts;
    parts.ipSource = QStringLiteral("140.82.114.4");
    parts.ipDestination = QStringLiteral("192.168.1.100");
    parts.summaryProtocol = QStringLiteral("TCP");
    parts.summaryInfo = QStringLiteral("443 -> 52315 [ACK] Seq=1 Ack=1 Win=64240 Len=0");
    parts.sourcePort = 443;
    parts.destinationPort = 52315;
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:tcp");

    parts.segment = buildTcp(443, 52315, 1, 1, 0x10, 64240, QByteArray(),
                             ipv4Address(parts.ipSource), ipv4Address(parts.ipDestination));
    parts.transportTitle = QStringLiteral("Transmission Control Protocol, Src Port: 443, Dst Port: 52315, Len: 0");
    parts.transportFields = {
        makeNode("Source Port", "443"),
        makeNode("Destination Port", "52315"),
        makeNode("Sequence Number", QString::number(sequence % 1000 + 1)),
        makeNode("Acknowledgment Number", "1"),
        makeNode("Flags", "0x010 (ACK)"),
        makeNode("Window", "64240"),
    };
    return parts;
}

FrameParts makeIcmpEcho(quint32 sequence)
{
    Q_UNUSED(sequence);
    FrameParts parts;
    parts.ipSource = QStringLiteral("192.168.1.100");
    parts.ipDestination = QStringLiteral("8.8.8.8");
    parts.ipProtocol = kProtocolIcmp;
    parts.summaryProtocol = QStringLiteral("ICMP");
    parts.summaryInfo = QStringLiteral("Echo (ping) request  id=0x0001, seq=1/256, ttl=64");
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:icmp");

    const QByteArray payload = "abcdefghijklmnopqrstuvwabcdefghi";
    parts.segment = buildIcmpEcho(8, 0x0001, 1, payload);
    parts.transportTitle = QStringLiteral("Internet Control Message Protocol");
    parts.transportFields = {
        makeNode("Type", "8 (Echo (ping) request)"),
        makeNode("Code", "0"),
        makeNode("Checksum", "0x0000 [correct]"),
        makeNode("Identifier", "0x0001 (1)"),
        makeNode("Sequence Number", "1 (0x0001)"),
    };
    return parts;
}

FrameParts makeIcmpReply(quint32 sequence)
{
    Q_UNUSED(sequence);
    FrameParts parts;
    parts.ipSource = QStringLiteral("8.8.8.8");
    parts.ipDestination = QStringLiteral("192.168.1.100");
    parts.ipProtocol = kProtocolIcmp;
    parts.ttl = 117;
    parts.summaryProtocol = QStringLiteral("ICMP");
    parts.summaryInfo = QStringLiteral("Echo (ping) reply    id=0x0001, seq=1/256, ttl=117");
    parts.protocolChain = QStringLiteral("eth:ethertype:ip:icmp");

    const QByteArray payload = "abcdefghijklmnopqrstuvwabcdefghi";
    parts.segment = buildIcmpEcho(0, 0x0001, 1, payload);
    parts.transportTitle = QStringLiteral("Internet Control Message Protocol");
    parts.transportFields = {
        makeNode("Type", "0 (Echo (ping) reply)"),
        makeNode("Code", "0"),
        makeNode("Checksum", "0x0000 [correct]"),
        makeNode("Identifier", "0x0001 (1)"),
        makeNode("Sequence Number", "1 (0x0001)"),
    };
    return parts;
}

} // namespace

QVector<PacketRecord> makeSamplePackets(int count)
{
    QVector<PacketRecord> packets;
    packets.reserve(count);

    QDateTime clock = QDateTime::currentDateTime().addSecs(-42);
    quint32 sequence = 1;

    for (int i = 0; i < count; ++i) {
        clock = clock.addMSecs(3 + (i * 37) % 140);
        sequence += static_cast<quint32>((i * 13) % 400);

        FrameParts parts;
        switch (i % 8) {
        case 0:
            parts = makeHttpGet(sequence);
            break;
        case 1:
            parts = makeHttpResponse(sequence);
            break;
        case 2:
            parts = makeDnsQuery(sequence);
            break;
        case 3:
            parts = makeDnsResponse(sequence);
            break;
        case 4:
            parts = makeTcpSyn(sequence);
            break;
        case 5:
            parts = makeTcpAck(sequence);
            break;
        case 6:
            parts = makeIcmpEcho(sequence);
            break;
        default:
            parts = makeIcmpReply(sequence);
            break;
        }
        packets.append(assemble(static_cast<quint64>(i) + 1, clock, parts));
    }
    return packets;
}

} // namespace sss::model
