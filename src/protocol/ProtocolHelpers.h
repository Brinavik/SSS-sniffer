#pragma once

#include <QChar>
#include <QString>

#include "model/PacketRecord.h"

// Small, allocation-light helpers shared by the dissectors.
namespace sss::protocol::detail {

inline quint16 readU16(const uchar *data)
{
    return static_cast<quint16>((static_cast<quint16>(data[0]) << 8)
                                | static_cast<quint16>(data[1]));
}

inline quint32 readU32(const uchar *data)
{
    return (static_cast<quint32>(data[0]) << 24)
           | (static_cast<quint32>(data[1]) << 16)
           | (static_cast<quint32>(data[2]) << 8)
           | static_cast<quint32>(data[3]);
}

inline sss::model::DetailNode node(const QString &name, const QString &value = QString())
{
    sss::model::DetailNode item;
    item.name = name;
    item.value = value;
    return item;
}

inline QString macText(const uchar *mac)
{
    QString text;
    text.reserve(17);
    for (int i = 0; i < 6; ++i) {
        if (i != 0) {
            text += QLatin1Char(':');
        }
        text += QString("%1").arg(mac[i], 2, 16, QLatin1Char('0'));
    }
    return text.toUpper();
}

inline QString ipv4Text(const uchar *address)
{
    return QString("%1.%2.%3.%4")
        .arg(address[0])
        .arg(address[1])
        .arg(address[2])
        .arg(address[3]);
}

// RFC 5952 style compression: lowercase hex, no leading zeros, and the longest
// run of zero groups replaced by "::". Keeps IPv6 addresses readable in a column.
inline QString ipv6Text(const uchar *address)
{
    quint16 groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = static_cast<quint16>((static_cast<quint16>(address[i * 2]) << 8)
                                         | static_cast<quint16>(address[i * 2 + 1]));
    }

    int zeroStart = -1;
    int zeroLength = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        int end = i;
        while (end < 8 && groups[end] == 0) {
            ++end;
        }
        if (end - i > zeroLength) {
            zeroStart = i;
            zeroLength = end - i;
        }
        i = end;
    }
    if (zeroLength < 2) {
        zeroStart = -1;
        zeroLength = 0;
    }

    QString text;
    text.reserve(39);
    for (int i = 0; i < 8; ++i) {
        if (i == zeroStart) {
            text += QLatin1String("::");
            i += zeroLength - 1;
            continue;
        }
        if (!text.isEmpty() && !text.endsWith(QLatin1Char(':'))) {
            text += QLatin1Char(':');
        }
        text += QString::number(groups[i], 16);
    }
    return text;
}

inline QString hex16(quint16 value)
{
    return QString("0x%1").arg(value, 4, 16, QLatin1Char('0'));
}

inline QString tcpFlagsText(quint8 flags)
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
        return hex16(flags);
    }
    return names.join(QLatin1Char(','));
}

inline QString ipProtocolText(quint8 protocol)
{
    switch (protocol) {
    case 1:
        return QStringLiteral("ICMP (1)");
    case 6:
        return QStringLiteral("TCP (6)");
    case 17:
        return QStringLiteral("UDP (17)");
    case 41:
        return QStringLiteral("IPv6 (41)");
    case 47:
        return QStringLiteral("GRE (47)");
    case 50:
        return QStringLiteral("ESP (50)");
    case 51:
        return QStringLiteral("AH (51)");
    case 58:
        return QStringLiteral("ICMPv6 (58)");
    default:
        return QString("IP protocol %1").arg(protocol);
    }
}

} // namespace sss::protocol::detail
