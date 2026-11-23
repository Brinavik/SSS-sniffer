#include "protocol/Dissector.h"

#include <QStringList>

#include <cstring>

#include "protocol/ProtocolHelpers.h"
#include "protocol/TransportDissector.h"

namespace sss::protocol {
namespace {

using detail::hex16;
using detail::ipProtocolText;
using detail::ipv4Text;
using detail::ipv6Text;
using detail::macText;
using detail::node;
using detail::readU16;
using detail::readU32;

constexpr quint16 kEtherTypeIpv4 = 0x0800;
constexpr quint16 kEtherTypeIpv6 = 0x86DD;
constexpr quint16 kEtherTypeArp = 0x0806;
constexpr quint16 kEtherTypeVlan = 0x8100;
constexpr quint16 kEtherTypeQinQ = 0x88A8;

constexpr int kLinkNull = 0;
constexpr int kLinkEthernet = 1;
constexpr int kLinkRaw = 101;
constexpr int kLinkIpv4 = 228;
constexpr int kLinkIpv6 = 229;

QString etherTypeText(quint16 type)
{
    switch (type) {
    case kEtherTypeIpv4:
        return QStringLiteral("IPv4 (0x0800)");
    case kEtherTypeIpv6:
        return QStringLiteral("IPv6 (0x86dd)");
    case kEtherTypeArp:
        return QStringLiteral("ARP (0x0806)");
    case kEtherTypeVlan:
        return QStringLiteral("802.1Q (0x8100)");
    default:
        return QString("0x%1").arg(type, 4, 16, QLatin1Char('0'));
    }
}

// BSD loopback stores the address family in host byte order. Npcap documents 24
// for IPv6, while Windows itself uses 23 (AF_INET6) and other BSDs use 28 / 30.
// Accept every known value so no IPv6 frame is dropped because of the link type.
bool isIpv6Family(quint32 family)
{
    return family == 23 || family == 24 || family == 28 || family == 30;
}

QString ipv4FlagsText(quint16 flagsAndOffset)
{
    QStringList flags;
    if ((flagsAndOffset & 0x4000) != 0) {
        flags << QStringLiteral("DF");
    }
    if ((flagsAndOffset & 0x2000) != 0) {
        flags << QStringLiteral("MF");
    }
    if (flags.isEmpty()) {
        flags << QStringLiteral("none");
    }
    return flags.join(QLatin1Char(','));
}

class Parser
{
public:
    Parser(const uchar *data, int capturedLength, int wireLength, int linkType,
           quint64 index, const QDateTime &timestamp)
        : m_data(data)
        , m_captured(capturedLength)
        , m_wire(wireLength)
        , m_linkType(linkType)
        , m_index(index)
        , m_timestamp(timestamp)
    {
    }

    Dissection run();

private:
    bool has(int offset, int length) const
    {
        return offset >= 0 && length >= 0 && offset + length <= m_captured;
    }

    void fail(const QString &reason);

    void parseEthernet();
    void parseLoopback();
    void parseArp(int offset);
    void parseIpv4(int offset);
    void parseIpv6(int offset);

    sss::model::DetailNode buildFrameNode() const;

    const uchar *m_data = nullptr;
    int m_captured = 0;
    int m_wire = 0;
    int m_linkType = 0;
    quint64 m_index = 0;
    QDateTime m_timestamp;

    Dissection m_out;
    QStringList m_chain;
};

void Parser::fail(const QString &reason)
{
    m_out.info = reason;
    if (m_out.protocol.isEmpty() || m_out.protocol == QStringLiteral("RAW")) {
        m_out.protocol = QStringLiteral("Malformed");
    }
}

sss::model::DetailNode Parser::buildFrameNode() const
{
    sss::model::DetailNode frame =
        node(QString("Frame %1: %2 bytes on wire").arg(m_index).arg(m_wire));
    frame.children.append(node(QStringLiteral("Arrival Time"),
                               m_timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))));
    frame.children.append(node(QStringLiteral("Frame Length"), QString("%1 bytes").arg(m_wire)));
    frame.children.append(node(QStringLiteral("Captured Length"), QString("%1 bytes").arg(m_captured)));
    if (!m_chain.isEmpty()) {
        frame.children.append(node(QStringLiteral("Protocols in frame"),
                                   m_chain.join(QLatin1Char(':'))));
    }
    return frame;
}

Dissection Parser::run()
{
    m_out.source = QStringLiteral("-");
    m_out.destination = QStringLiteral("-");
    m_out.protocol = QStringLiteral("RAW");
    m_out.info = QString("%1 bytes on wire").arg(m_wire);

    if (m_data != nullptr && m_captured > 0) {
        switch (m_linkType) {
        case kLinkEthernet:
            parseEthernet();
            break;
        case kLinkNull:
            parseLoopback();
            break;
        case kLinkRaw:
        case kLinkIpv4:
        case kLinkIpv6: {
            m_chain << QStringLiteral("raw");
            const int version = (m_data[0] >> 4);
            if (version == 4) {
                m_chain << QStringLiteral("ip");
                parseIpv4(0);
            } else if (version == 6) {
                m_chain << QStringLiteral("ipv6");
                parseIpv6(0);
            } else {
                fail(QStringLiteral("Raw frame with unknown IP version"));
            }
            break;
        }
        default:
            m_out.info = QString("Unsupported link type %1").arg(m_linkType);
            break;
        }
    }

    m_out.details.prepend(buildFrameNode());
    return m_out;
}

void Parser::parseEthernet()
{
    if (!has(0, 14)) {
        fail(QStringLiteral("Truncated Ethernet header"));
        return;
    }

    const QString destinationMac = macText(m_data);
    const QString sourceMac = macText(m_data + 6);
    quint16 etherType = readU16(m_data + 12);
    int offset = 14;

    sss::model::DetailNode ethernet =
        node(QString("Ethernet II, Src: %1, Dst: %2").arg(sourceMac, destinationMac));

    while ((etherType == kEtherTypeVlan || etherType == kEtherTypeQinQ) && has(offset, 4)) {
        const quint16 tagControl = readU16(m_data + offset);
        etherType = readU16(m_data + offset + 2);
        ethernet.children.append(
            node(QStringLiteral("802.1Q Virtual LAN"),
                 QString("PCP: %1, DEI: %2, VID: %3")
                     .arg((tagControl >> 13) & 0x07)
                     .arg((tagControl >> 12) & 0x01)
                     .arg(tagControl & 0x0FFF)));
        offset += 4;
        m_chain << QStringLiteral("vlan");
    }

    ethernet.children.append(node(QStringLiteral("Type"), etherTypeText(etherType)));
    m_out.details.append(ethernet);
    m_chain << QStringLiteral("eth");

    // Fallback addressing for frames that carry no IP header at all.
    m_out.source = sourceMac;
    m_out.destination = destinationMac;

    switch (etherType) {
    case kEtherTypeArp:
        parseArp(offset);
        return;
    case kEtherTypeIpv4:
        m_chain << QStringLiteral("ip");
        parseIpv4(offset);
        return;
    case kEtherTypeIpv6:
        m_chain << QStringLiteral("ipv6");
        parseIpv6(offset);
        return;
    default:
        m_out.protocol = QStringLiteral("ETH");
        m_out.info = QString("EtherType %1").arg(etherTypeText(etherType));
        return;
    }
}

void Parser::parseLoopback()
{
    if (!has(0, 4)) {
        fail(QStringLiteral("Truncated loopback header"));
        return;
    }

    quint32 family = 0;
    std::memcpy(&family, m_data, sizeof(family));

    sss::model::DetailNode loopback = node(QStringLiteral("Loopback"));
    loopback.children.append(node(QStringLiteral("Family"), QString::number(family)));
    m_out.details.append(loopback);
    m_chain << QStringLiteral("loopback");

    if (family == 2) {
        m_chain << QStringLiteral("ip");
        parseIpv4(4);
        return;
    }
    if (isIpv6Family(family)) {
        m_chain << QStringLiteral("ipv6");
        parseIpv6(4);
        return;
    }

    m_out.protocol = QStringLiteral("LOOP");
    m_out.info = QString("Loopback frame, family %1").arg(family);
}

void Parser::parseArp(int offset)
{
    if (!has(offset, 8)) {
        fail(QStringLiteral("Truncated ARP header"));
        return;
    }

    const quint16 hardwareType = readU16(m_data + offset);
    const quint16 protocolType = readU16(m_data + offset + 2);
    const quint8 hardwareLength = m_data[offset + 4];
    const quint8 protocolLength = m_data[offset + 5];
    const quint16 operation = readU16(m_data + offset + 6);

    const int body = offset + 8;
    if (hardwareLength != 6 || protocolLength != 4 || !has(body, 20)) {
        fail(QStringLiteral("Unsupported or truncated ARP body"));
        return;
    }

    const uchar *senderMac = m_data + body;
    const uchar *senderIp = senderMac + hardwareLength;
    const uchar *targetMac = senderIp + protocolLength;
    const uchar *targetIp = targetMac + hardwareLength;

    const QString senderIpText = ipv4Text(senderIp);
    const QString targetIpText = ipv4Text(targetIp);

    if (operation == 1) {
        m_out.info = QString("Who has %1? Tell %2").arg(targetIpText, senderIpText);
    } else if (operation == 2) {
        m_out.info = QString("%1 is at %2").arg(senderIpText, macText(senderMac));
    } else {
        m_out.info = QString("ARP operation %1").arg(operation);
    }

    m_out.protocol = QStringLiteral("ARP");
    m_chain << QStringLiteral("arp");

    // ARP advertisements name hosts by IP, so prefer IP over the MAC fallback.
    m_out.source = senderIpText;
    m_out.destination = targetIpText;

    sss::model::DetailNode arp =
        node(QString("Address Resolution Protocol (%1)")
                 .arg(operation == 1 ? QStringLiteral("request")
                                     : (operation == 2 ? QStringLiteral("reply")
                                                       : QStringLiteral("unknown"))));
    arp.children.append(node(QStringLiteral("Hardware Type"),
                             QString("Ethernet (%1)").arg(hardwareType)));
    arp.children.append(node(QStringLiteral("Protocol Type"), etherTypeText(protocolType)));
    arp.children.append(node(QStringLiteral("Hardware Size"), QString::number(hardwareLength)));
    arp.children.append(node(QStringLiteral("Protocol Size"), QString::number(protocolLength)));
    arp.children.append(node(QStringLiteral("Opcode"), QString::number(operation)));
    arp.children.append(node(QStringLiteral("Sender MAC"), macText(senderMac)));
    arp.children.append(node(QStringLiteral("Sender IP"), senderIpText));
    arp.children.append(node(QStringLiteral("Target MAC"), macText(targetMac)));
    arp.children.append(node(QStringLiteral("Target IP"), targetIpText));
    m_out.details.append(arp);
}

void Parser::parseIpv4(int offset)
{
    if (!has(offset, 20)) {
        fail(QStringLiteral("Truncated IPv4 header"));
        return;
    }

    const uchar *ip = m_data + offset;
    const int version = ip[0] >> 4;
    const int headerLength = (ip[0] & 0x0F) * 4;
    if (version != 4 || headerLength < 20) {
        fail(QStringLiteral("Malformed IPv4 header"));
        return;
    }
    if (!has(offset, headerLength)) {
        fail(QStringLiteral("Truncated IPv4 options"));
        return;
    }

    const int totalLength = readU16(ip + 2);
    // A total length smaller than the header would make the transport length
    // negative. Report it here instead of leaking a bogus number downstream.
    if (totalLength < headerLength) {
        fail(QStringLiteral("Invalid IPv4 total length"));
        return;
    }

    const int declaredPayload = totalLength - headerLength;
    const int capturedPayload = qMin(declaredPayload, m_captured - offset - headerLength);

    const quint16 flagsAndOffset = readU16(ip + 6);
    const int fragmentOffset = flagsAndOffset & 0x1FFF;

    m_out.ipVersion = 4;
    m_out.ipProtocol = ip[9];
    m_out.source = ipv4Text(ip + 12);
    m_out.destination = ipv4Text(ip + 16);
    m_out.protocol = QStringLiteral("IPv4");

    sss::model::DetailNode internet =
        node(QString("Internet Protocol Version 4, Src: %1, Dst: %2")
                 .arg(m_out.source, m_out.destination));
    internet.children.append(node(QStringLiteral("Version"), QStringLiteral("4")));
    internet.children.append(node(QStringLiteral("Header Length"), QString("%1 bytes").arg(headerLength)));
    internet.children.append(node(QStringLiteral("Differentiated Services"),
                                  QString("0x%1").arg(ip[1], 2, 16, QLatin1Char('0'))));
    internet.children.append(node(QStringLiteral("Total Length"), QString::number(totalLength)));
    internet.children.append(node(QStringLiteral("Identification"), hex16(readU16(ip + 4))));
    internet.children.append(node(QStringLiteral("Flags"), ipv4FlagsText(flagsAndOffset)));
    internet.children.append(node(QStringLiteral("Fragment Offset"), QString::number(fragmentOffset)));
    internet.children.append(node(QStringLiteral("Time to Live"), QString::number(ip[8])));
    internet.children.append(node(QStringLiteral("Protocol"), ipProtocolText(ip[9])));
    internet.children.append(node(QStringLiteral("Header Checksum"), hex16(readU16(ip + 10))));
    m_out.details.append(internet);

    if (fragmentOffset != 0) {
        // Only the first fragment carries the transport header.
        m_out.info = QString("IPv4 fragment, offset %1").arg(fragmentOffset);
        return;
    }

    detail::TransportInput input;
    input.sourceAddress = m_out.source;
    input.destinationAddress = m_out.destination;
    input.protocol = ip[9];
    input.ipVersion = 4;
    input.header = m_data + offset + headerLength;
    input.capturedBytes = capturedPayload;
    input.declaredBytes = declaredPayload;

    detail::dissectTransport(input, m_out);
    m_chain << m_out.protocol.toLower();
}

void Parser::parseIpv6(int offset)
{
    if (!has(offset, 40)) {
        fail(QStringLiteral("Truncated IPv6 header"));
        return;
    }

    const uchar *ip = m_data + offset;
    if ((ip[0] >> 4) != 6) {
        fail(QStringLiteral("Malformed IPv6 header"));
        return;
    }

    const quint8 trafficClass = static_cast<quint8>(((ip[0] & 0x0F) << 4) | (ip[1] >> 4));
    const quint32 flowLabel = (static_cast<quint32>(ip[1] & 0x0F) << 16)
                              | (static_cast<quint32>(ip[2]) << 8)
                              | static_cast<quint32>(ip[3]);
    const quint16 payloadLength = readU16(ip + 4);
    quint8 nextHeader = ip[6];
    const quint8 hopLimit = ip[7];

    m_out.ipVersion = 6;
    m_out.ipProtocol = nextHeader;
    m_out.source = ipv6Text(ip + 8);
    m_out.destination = ipv6Text(ip + 24);
    m_out.protocol = QStringLiteral("IPv6");

    sss::model::DetailNode internet =
        node(QString("Internet Protocol Version 6, Src: %1, Dst: %2")
                 .arg(m_out.source, m_out.destination));
    internet.children.append(node(QStringLiteral("Version"), QStringLiteral("6")));
    internet.children.append(node(QStringLiteral("Traffic Class"), QString::number(trafficClass)));
    internet.children.append(node(QStringLiteral("Flow Label"), QString::number(flowLabel)));
    internet.children.append(node(QStringLiteral("Payload Length"), QString::number(payloadLength)));
    internet.children.append(node(QStringLiteral("Next Header"), ipProtocolText(nextHeader)));
    internet.children.append(node(QStringLiteral("Hop Limit"), QString::number(hopLimit)));
    m_out.details.append(internet);

    int cursor = offset + 40;
    int remaining = qMin<int>(payloadLength, m_captured - cursor);

    bool isFragment = false;
    int fragmentOffset = 0;

    // Walk the extension header chain; only the final protocol reaches L4.
    for (int guard = 0; guard < 8; ++guard) {
        int headerBytes = 0;
        sss::model::DetailNode extension;

        if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60) {
            if (remaining < 8) {
                fail(QStringLiteral("Truncated IPv6 extension header"));
                return;
            }
            headerBytes = (m_data[cursor + 1] + 1) * 8;
            const QString name = (nextHeader == 0)
                                     ? QStringLiteral("Hop-by-Hop Options")
                                     : (nextHeader == 43 ? QStringLiteral("Routing Header")
                                                         : QStringLiteral("Destination Options"));
            extension = node(name);
        } else if (nextHeader == 44) {
            if (remaining < 8) {
                fail(QStringLiteral("Truncated IPv6 fragment header"));
                return;
            }
            headerBytes = 8;
            isFragment = true;
            const quint16 fragmentField = readU16(m_data + cursor + 2);
            fragmentOffset = fragmentField >> 3;
            extension = node(QStringLiteral("Fragment Header"));
            extension.children.append(node(QStringLiteral("Fragment Offset"),
                                           QString("%1 bytes").arg(fragmentOffset * 8)));
            extension.children.append(node(QStringLiteral("More Fragments"),
                                           (fragmentField & 0x0001) != 0
                                               ? QStringLiteral("Yes")
                                               : QStringLiteral("No")));
            extension.children.append(
                node(QStringLiteral("Identification"),
                     QString("0x%1").arg(static_cast<qulonglong>(readU32(m_data + cursor + 4)),
                                         8,
                                         16,
                                         QLatin1Char('0'))));
        } else if (nextHeader == 51) {
            if (remaining < 8) {
                fail(QStringLiteral("Truncated IPv6 authentication header"));
                return;
            }
            headerBytes = (m_data[cursor + 1] + 2) * 4;
            extension = node(QStringLiteral("Authentication Header"));
        } else {
            break;
        }

        if (headerBytes <= 0 || headerBytes > remaining) {
            fail(QStringLiteral("Malformed IPv6 extension header"));
            return;
        }

        extension.children.prepend(node(QStringLiteral("Next Header"), ipProtocolText(m_data[cursor])));
        extension.value = QString("%1 bytes").arg(headerBytes);
        m_out.details.append(extension);

        nextHeader = m_data[cursor];
        cursor += headerBytes;
        remaining -= headerBytes;
    }

    // A non-first fragment carries no transport header: everything after the
    // fragment header is payload. Parsing it as TCP/UDP would invent ports and
    // sequence numbers, so report the fragment and stop, mirroring IPv4.
    if (isFragment && fragmentOffset != 0) {
        m_out.info = QString("IPv6 fragment, offset %1").arg(fragmentOffset * 8);
        m_out.ipProtocol = nextHeader;
        return;
    }

    m_out.ipProtocol = nextHeader;

    detail::TransportInput input;
    input.sourceAddress = m_out.source;
    input.destinationAddress = m_out.destination;
    input.protocol = nextHeader;
    input.ipVersion = 6;
    input.header = m_data + cursor;
    input.capturedBytes = qMax(0, remaining);
    input.declaredBytes = qMax(0, static_cast<int>(payloadLength) - (cursor - offset - 40));

    detail::dissectTransport(input, m_out);
    m_chain << m_out.protocol.toLower();
}

} // namespace

Dissection dissectFrame(const uchar *data,
                        int capturedLength,
                        int wireLength,
                        int linkType,
                        quint64 index,
                        const QDateTime &timestamp)
{
    Parser parser(data, capturedLength, wireLength, linkType, index, timestamp);
    return parser.run();
}

} // namespace sss::protocol
