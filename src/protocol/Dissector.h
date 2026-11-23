#pragma once

#include <QDateTime>
#include <QString>
#include <QVector>

#include "model/PacketRecord.h"

namespace sss::protocol {

// Everything the UI needs to render one frame: the list columns, the protocol
// tree and the structured fields a display filter will use later.
struct Dissection
{
    QString source;       // IP address, or MAC address for non-IP frames
    QString destination;
    QString protocol;     // highest recognized layer: HTTP, DNS, TCP, ICMP, IPv4 ...
    QString info;         // one line summary, Wireshark style

    QVector<sss::model::DetailNode> details;

    quint8 ipVersion = 0;      // 4 / 6, 0 when the frame carries no IP
    quint8 ipProtocol = 0;     // IANA protocol number of the transport header
    quint16 sourcePort = 0;
    quint16 destinationPort = 0;
    quint8 tcpFlags = 0;       // TCP flag bits, 0 for non-TCP frames
};

// `linkType` uses the libpcap DLT_* numbering (DLT_EN10MB, DLT_NULL, DLT_RAW...).
Dissection dissectFrame(const uchar *data,
                        int capturedLength,
                        int wireLength,
                        int linkType,
                        quint64 index,
                        const QDateTime &timestamp);

} // namespace sss::protocol
