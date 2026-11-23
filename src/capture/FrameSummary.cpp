#include "capture/FrameSummary.h"

#include <QStringList>

#include <cstring>

namespace sss::capture {
namespace {

constexpr quint16 kEtherTypeIpv4 = 0x0800;
constexpr quint16 kEtherTypeIpv6 = 0x86DD;
constexpr quint16 kEtherTypeArp = 0x0806;

constexpr int kLinkTypeNull = 0;      // BSD loopback, Npcap "NPF_Loopback"
constexpr int kLinkTypeEthernet = 1;  // Ethernet
constexpr int kLinkTypeRawIp = 101;   // Raw IP

quint16 readU16(const uchar *data)
{
    return static_cast<quint16>((data[0] << 8) | data[1]);
}

quint32 readU32(const uchar *data)
{
    return (static_cast<quint32>(data[0]) << 24)
           | (static_cast<quint32>(data[1]) << 16)
           | (static_cast<quint32>(data[2]) << 8)
           | static_cast<quint32>(data[3]);
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

QString ipv4Text(const uchar *address)
{
    return QString("%1.%2.%3.%4")
        .arg(address[0])
        .arg(address[1])
        .arg(address[2])
        .arg(address[3]);
}

sss::model::DetailNode node(const QString &name, const QString &value = QString())
{
    sss::model::DetailNode item;
    item.name = name;
    item.value = value;
    return item;
}

QString etherTypeText(quint16 type)
{
    switch (type) {
    case kEtherTypeIpv4:
        return QStringLiteral("IPv4 (0x0800)");
    case kEtherTypeIpv6:
        return QStringLiteral("IPv6 (0x86dd)");
    case kEtherTypeArp:
        return QStringLiteral("ARP (0x0806)");
    default:
        return QString("0x%1").arg(type, 4, 16, QLatin1Char('0'));
    }
}

QString tcpFlagsText(quint8 flags)
{
    QStringList names;
    if ((flags & 0x02) != 0) {
        names << QStringLiteral("SYN");
    }
    if ((flags & 0x10) != 0) {
        names << QStringLiteral("ACK");
    }
    if ((flags & 0x08) != 0) {
        names << QStringLiteral("PSH");
    }
    if ((flags & 0x01) != 0) {
        names << QStringLiteral("FIN");
    }
    if ((flags & 0x04) != 0) {
        names << QStringLiteral("RST");
    }
    if ((flags & 0x20) != 0) {
        names << QStringLiteral("URG");
    }
    if (names.isEmpty()) {
        return QString("0x%1").arg(flags, 2, 16, QLatin1Char('0'));
    }
    return names.join(QLatin1Char(','));
}

QString ipProtocolText(quint8 protocol)
{
    switch (protocol) {
    case 1:
        return QStringLiteral("ICMP (1)");
    case 6:
        return QStringLiteral("TCP (6)");
    case 17:
        return QStringLiteral("UDP (17)");
    default:
        return QString("IP protocol %1").arg(protocol);
    }
}

QString icmpTypeText(quint8 type, quint8 code)
{
    switch (type) {
    case 0:
        return QStringLiteral("Echo (ping) reply");
    case 3:
        return QString("Destination unreachable (code %1)").arg(code);
    case 8:
        return QStringLiteral("Echo (ping) request");
    case 11:
        return QString("Time-to-live exceeded (code %1)").arg(code);
    default:
        return QString("Type %1, code %2").arg(type).arg(code);
    }
}

} // namespace

FrameSummary summarizeFrame(const uchar *data,
                            int capturedLength,
                            int wireLength,
                            int linkType,
                            quint64 index,
                            const QDateTime &timestamp)
{
    FrameSummary summary;
    summary.source = QStringLiteral("-");
    summary.destination = QStringLiteral("-");
    summary.protocol = QStringLiteral("RAW");
    summary.info = QString("%1 bytes on wire").arg(wireLength);

    sss::model::DetailNode frame = node(QString("Frame %1: %2 bytes on wire").arg(index).arg(wireLength));
    frame.children.append(node(QStringLiteral("Arrival Time"),
                               timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))));
    frame.children.append(node(QStringLiteral("Frame Length"), QString("%1 bytes").arg(wireLength)));
    frame.children.append(node(QStringLiteral("Captured Length"), QString("%1 bytes").arg(capturedLength)));
    summary.details.append(frame);

    if (data == nullptr || capturedLength <= 0) {
        return summary;
    }

    int offset = 0;
    quint16 etherType = 0;
    bool linkParsed = false;

    if (linkType == kLinkTypeEthernet && capturedLength >= 14) {
        etherType = readU16(data + 12);
        sss::model::DetailNode ethernet =
            node(QString("Ethernet II, Src: %1, Dst: %2").arg(macText(data + 6), macText(data)));
        ethernet.children.append(node(QStringLiteral("Type"), etherTypeText(etherType)));
        summary.details.append(ethernet);
        offset = 14;
        linkParsed = true;
        summary.protocol = QStringLiteral("ETH");
    } else if (linkType == kLinkTypeNull && capturedLength >= 4) {
        quint32 family = 0;
        std::memcpy(&family, data, sizeof(family));
        if (family == 2) {
            etherType = kEtherTypeIpv4;
        } else if (family == 24 || family == 28 || family == 30) {
            etherType = kEtherTypeIpv6;
        }
        sss::model::DetailNode loopback = node(QStringLiteral("Loopback"));
        loopback.children.append(node(QStringLiteral("Family"), QString::number(family)));
        summary.details.append(loopback);
        offset = 4;
        linkParsed = true;
        summary.protocol = QStringLiteral("LOOP");
    } else if (linkType == kLinkTypeRawIp) {
        const quint8 version = static_cast<quint8>(data[0] >> 4);
        etherType = (version == 4) ? kEtherTypeIpv4 : ((version == 6) ? kEtherTypeIpv6 : 0);
        linkParsed = true;
    }

    if (!linkParsed) {
        summary.info = QString("Unsupported link type %1 (%2 bytes)").arg(linkType).arg(wireLength);
        return summary;
    }

    if (etherType == kEtherTypeArp) {
        summary.protocol = QStringLiteral("ARP");
        summary.info = QStringLiteral("Address Resolution Protocol (dissector pending)");
        return summary;
    }
    if (etherType == kEtherTypeIpv6) {
        summary.protocol = QStringLiteral("IPv6");
        summary.info = QStringLiteral("IPv6 frame (dissector pending)");
        return summary;
    }
    if (etherType != kEtherTypeIpv4) {
        summary.protocol = QStringLiteral("ETH");
        summary.info = QString("EtherType %1").arg(etherTypeText(etherType));
        return summary;
    }
    if (capturedLength < offset + 20) {
        summary.info = QStringLiteral("Truncated IPv4 header");
        return summary;
    }

    const uchar *ip = data + offset;
    const int version = ip[0] >> 4;
    const int headerLength = (ip[0] & 0x0F) * 4;
    if (version != 4 || headerLength < 20 || capturedLength < offset + headerLength) {
        summary.info = QStringLiteral("Malformed IPv4 header");
        return summary;
    }

    const QString source = ipv4Text(ip + 12);
    const QString destination = ipv4Text(ip + 16);
    const quint8 protocol = ip[9];
    const quint8 ttl = ip[8];
    const int totalLength = readU16(ip + 2);

    summary.source = source;
    summary.destination = destination;
    summary.protocol = QStringLiteral("IP");

    sss::model::DetailNode internet =
        node(QString("Internet Protocol Version 4, Src: %1, Dst: %2").arg(source, destination));
    internet.children.append(node(QStringLiteral("Version"), QStringLiteral("4")));
    internet.children.append(node(QStringLiteral("Header Length"), QString("%1 bytes").arg(headerLength)));
    internet.children.append(node(QStringLiteral("Total Length"), QString::number(totalLength)));
    internet.children.append(node(QStringLiteral("Time to Live"), QString::number(ttl)));
    internet.children.append(node(QStringLiteral("Protocol"), ipProtocolText(protocol)));
    summary.details.append(internet);

    const uchar *transport = ip + headerLength;
    const int transportLength = totalLength - headerLength;
    const int available = capturedLength - offset - headerLength;

    if (protocol == 6 && available >= 20) {
        const quint16 sourcePort = readU16(transport);
        const quint16 destinationPort = readU16(transport + 2);
        const quint32 sequence = readU32(transport + 4);
        const quint32 acknowledgment = readU32(transport + 8);
        const quint8 dataOffset = static_cast<quint8>(transport[12] >> 4);
        const quint8 flags = transport[13];
        const quint16 window = readU16(transport + 14);
        const int payloadLength = transportLength - dataOffset * 4;

        summary.protocol = QStringLiteral("TCP");
        summary.info = QString("%1 -> %2 [%3] Seq=%4 Ack=%5 Win=%6 Len=%7")
                           .arg(sourcePort)
                           .arg(destinationPort)
                           .arg(tcpFlagsText(flags))
                           .arg(sequence)
                           .arg(acknowledgment)
                           .arg(window)
                           .arg(payloadLength < 0 ? 0 : payloadLength);

        sss::model::DetailNode tcp =
            node(QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2").arg(sourcePort).arg(destinationPort));
        tcp.children.append(node(QStringLiteral("Source Port"), QString::number(sourcePort)));
        tcp.children.append(node(QStringLiteral("Destination Port"), QString::number(destinationPort)));
        tcp.children.append(node(QStringLiteral("Sequence Number"), QString::number(sequence)));
        tcp.children.append(node(QStringLiteral("Acknowledgment Number"), QString::number(acknowledgment)));
        tcp.children.append(node(QStringLiteral("Flags"), tcpFlagsText(flags)));
        tcp.children.append(node(QStringLiteral("Window"), QString::number(window)));
        tcp.children.append(node(QStringLiteral("Header Length"), QString("%1 bytes").arg(dataOffset * 4)));
        tcp.children.append(node(QStringLiteral("Payload Length"), QString::number(payloadLength < 0 ? 0 : payloadLength)));
        summary.details.append(tcp);
    } else if (protocol == 17 && available >= 8) {
        const quint16 sourcePort = readU16(transport);
        const quint16 destinationPort = readU16(transport + 2);
        const quint16 length = readU16(transport + 4);

        summary.protocol = QStringLiteral("UDP");
        summary.info = QString("%1 -> %2 Len=%3").arg(sourcePort).arg(destinationPort).arg(length);

        sss::model::DetailNode udp =
            node(QString("User Datagram Protocol, Src Port: %1, Dst Port: %2").arg(sourcePort).arg(destinationPort));
        udp.children.append(node(QStringLiteral("Source Port"), QString::number(sourcePort)));
        udp.children.append(node(QStringLiteral("Destination Port"), QString::number(destinationPort)));
        udp.children.append(node(QStringLiteral("Length"), QString::number(length)));
        udp.children.append(node(QStringLiteral("Checksum"), QString("0x%1").arg(readU16(transport + 6), 4, 16, QLatin1Char('0'))));
        summary.details.append(udp);
    } else if (protocol == 1 && available >= 8) {
        const quint8 type = transport[0];
        const quint8 code = transport[1];
        const quint16 identifier = readU16(transport + 4);
        const quint16 sequence = readU16(transport + 6);

        summary.protocol = QStringLiteral("ICMP");
        summary.info = QString("%1 id=0x%2 seq=%3")
                           .arg(icmpTypeText(type, code))
                           .arg(identifier, 4, 16, QLatin1Char('0'))
                           .arg(sequence);

        sss::model::DetailNode icmp = node(QStringLiteral("Internet Control Message Protocol"));
        icmp.children.append(node(QStringLiteral("Type"), QString::number(type)));
        icmp.children.append(node(QStringLiteral("Code"), QString::number(code)));
        icmp.children.append(node(QStringLiteral("Identifier"), QString("0x%1").arg(identifier, 4, 16, QLatin1Char('0'))));
        icmp.children.append(node(QStringLiteral("Sequence Number"), QString::number(sequence)));
        summary.details.append(icmp);
    } else {
        summary.info = QString("%1 -> %2 %3 (%4 bytes)")
                           .arg(source, destination, ipProtocolText(protocol))
                           .arg(totalLength);
    }

    return summary;
}

} // namespace sss::capture
