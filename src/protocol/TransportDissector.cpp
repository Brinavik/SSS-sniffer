#include "protocol/TransportDissector.h"

#include "protocol/ApplicationDissector.h"
#include "protocol/ProtocolHelpers.h"

namespace sss::protocol::detail {
namespace {

using detail::hex16;
using detail::ipProtocolText;
using detail::node;
using detail::readU16;
using detail::readU32;
using detail::tcpFlagsText;

QString icmpTypeText(quint8 type, bool ipv6)
{
    if (ipv6) {
        switch (type) {
        case 128:
            return QStringLiteral("Echo (ping) request");
        case 129:
            return QStringLiteral("Echo (ping) reply");
        case 133:
            return QStringLiteral("Router solicitation");
        case 134:
            return QStringLiteral("Router advertisement");
        case 135:
            return QStringLiteral("Neighbor solicitation");
        case 136:
            return QStringLiteral("Neighbor advertisement");
        default:
            return QString("ICMPv6 type %1").arg(type);
        }
    }

    switch (type) {
    case 0:
        return QStringLiteral("Echo (ping) reply");
    case 3:
        return QStringLiteral("Destination unreachable");
    case 5:
        return QStringLiteral("Redirect");
    case 8:
        return QStringLiteral("Echo (ping) request");
    case 11:
        return QStringLiteral("Time-to-live exceeded");
    default:
        return QString("ICMP type %1").arg(type);
    }
}

bool isEchoType(quint8 type, bool ipv6)
{
    if (ipv6) {
        return type == 128 || type == 129;
    }
    return type == 0 || type == 8;
}

void dissectTcp(const TransportInput &input, Dissection &out)
{
    out.protocol = QStringLiteral("TCP");

    if (input.capturedBytes < 20) {
        out.info = QStringLiteral("Truncated TCP header");
        return;
    }

    const uchar *tcp = input.header;
    const quint16 sourcePort = readU16(tcp);
    const quint16 destinationPort = readU16(tcp + 2);
    const quint32 sequence = readU32(tcp + 4);
    const quint32 acknowledgment = readU32(tcp + 8);
    const int headerLength = (tcp[12] >> 4) * 4;
    const quint8 flags = tcp[13];
    const quint16 window = readU16(tcp + 14);

    out.sourcePort = sourcePort;
    out.destinationPort = destinationPort;
    out.tcpFlags = flags;

    const int safeHeaderLength = qMax(20, headerLength);
    const int declaredPayload = qMax(0, input.declaredBytes - safeHeaderLength);
    const int capturedPayload = qMax(0, qMin(input.capturedBytes, input.declaredBytes) - safeHeaderLength);

    out.info = QString("%1 -> %2 [%3] Seq=%4 Ack=%5 Win=%6 Len=%7")
                   .arg(sourcePort)
                   .arg(destinationPort)
                   .arg(tcpFlagsText(flags))
                   .arg(sequence)
                   .arg(acknowledgment)
                   .arg(window)
                   .arg(declaredPayload);

    sss::model::DetailNode tcpNode =
        node(QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Len: %3")
                 .arg(sourcePort)
                 .arg(destinationPort)
                 .arg(declaredPayload));
    tcpNode.children.append(node(QStringLiteral("Source Port"), QString::number(sourcePort)));
    tcpNode.children.append(node(QStringLiteral("Destination Port"), QString::number(destinationPort)));
    tcpNode.children.append(node(QStringLiteral("Sequence Number"), QString::number(sequence)));
    tcpNode.children.append(node(QStringLiteral("Acknowledgment Number"), QString::number(acknowledgment)));
    tcpNode.children.append(node(QStringLiteral("Header Length"), QString("%1 bytes").arg(headerLength)));
    tcpNode.children.append(node(QStringLiteral("Flags"), tcpFlagsText(flags)));
    tcpNode.children.append(node(QStringLiteral("Window"), QString::number(window)));
    tcpNode.children.append(node(QStringLiteral("Checksum"), hex16(readU16(tcp + 16))));
    tcpNode.children.append(node(QStringLiteral("Urgent Pointer"), QString::number(readU16(tcp + 18))));
    tcpNode.children.append(node(QStringLiteral("Payload Length"), QString::number(declaredPayload)));
    out.details.append(tcpNode);

    if (capturedPayload > 0) {
        dissectApplication(sourcePort, destinationPort, tcp + safeHeaderLength, capturedPayload, out);
    }
}

void dissectUdp(const TransportInput &input, Dissection &out)
{
    out.protocol = QStringLiteral("UDP");

    if (input.capturedBytes < 8) {
        out.info = QStringLiteral("Truncated UDP header");
        return;
    }

    const uchar *udp = input.header;
    const quint16 sourcePort = readU16(udp);
    const quint16 destinationPort = readU16(udp + 2);
    const quint16 length = readU16(udp + 4);
    const quint16 checksum = readU16(udp + 6);

    out.sourcePort = sourcePort;
    out.destinationPort = destinationPort;

    const int declared = qMin<int>(length, input.declaredBytes);
    const int capturedPayload = qMax(0, qMin(input.capturedBytes, declared) - 8);

    out.info = QString("%1 -> %2 Len=%3").arg(sourcePort).arg(destinationPort).arg(length);

    sss::model::DetailNode udpNode =
        node(QString("User Datagram Protocol, Src Port: %1, Dst Port: %2")
                 .arg(sourcePort)
                 .arg(destinationPort));
    udpNode.children.append(node(QStringLiteral("Source Port"), QString::number(sourcePort)));
    udpNode.children.append(node(QStringLiteral("Destination Port"), QString::number(destinationPort)));
    udpNode.children.append(node(QStringLiteral("Length"), QString::number(length)));
    udpNode.children.append(node(QStringLiteral("Checksum"), hex16(checksum)));
    out.details.append(udpNode);

    if (capturedPayload > 0) {
        dissectApplication(sourcePort, destinationPort, udp + 8, capturedPayload, out);
    }
}

void dissectIcmp(const TransportInput &input, Dissection &out)
{
    const bool ipv6 = (input.ipVersion == 6);
    out.protocol = ipv6 ? QStringLiteral("ICMPv6") : QStringLiteral("ICMP");

    if (input.capturedBytes < 8) {
        out.info = QStringLiteral("Truncated ICMP header");
        return;
    }

    const uchar *icmp = input.header;
    const quint8 type = icmp[0];
    const quint8 code = icmp[1];
    const quint16 checksum = readU16(icmp + 2);

    sss::model::DetailNode icmpNode =
        node(QString("Internet Control Message Protocol%1").arg(ipv6 ? QStringLiteral(" v6") : QString()));
    icmpNode.children.append(node(QStringLiteral("Type"),
                                  QString("%1 (%2)").arg(type).arg(icmpTypeText(type, ipv6))));
    icmpNode.children.append(node(QStringLiteral("Code"), QString::number(code)));
    icmpNode.children.append(node(QStringLiteral("Checksum"), hex16(checksum)));

    QString info = icmpTypeText(type, ipv6);
    if (isEchoType(type, ipv6)) {
        const quint16 identifier = readU16(icmp + 4);
        const quint16 sequence = readU16(icmp + 6);
        info += QString(" id=0x%1 seq=%2")
                    .arg(identifier, 4, 16, QLatin1Char('0'))
                    .arg(sequence);
        icmpNode.children.append(node(QStringLiteral("Identifier"), hex16(identifier)));
        icmpNode.children.append(node(QStringLiteral("Sequence Number"), QString::number(sequence)));
    }
    if (code != 0) {
        info += QString(" (code %1)").arg(code);
    }

    out.info = info;
    out.details.append(icmpNode);
}

} // namespace

void dissectTransport(const TransportInput &input, Dissection &out)
{
    switch (input.protocol) {
    case 6:
        dissectTcp(input, out);
        return;
    case 17:
        dissectUdp(input, out);
        return;
    case 1:
    case 58:
        dissectIcmp(input, out);
        return;
    default:
        out.protocol = QString("IP %1").arg(input.protocol);
        out.info = QString("%1 -> %2, %3, %4 bytes")
                       .arg(input.sourceAddress,
                            input.destinationAddress,
                            ipProtocolText(input.protocol))
                       .arg(input.declaredBytes);
        return;
    }
}

} // namespace sss::protocol::detail
