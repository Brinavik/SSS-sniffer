#pragma once

#include <QDateTime>
#include <QString>
#include <QVector>

#include "model/PacketRecord.h"

namespace sss::capture {

// Temporary, deliberately small header peek used to fill the packet list.
// The real dissectors will live in src/protocol; this exists so capture can be
// validated against Wireshark before that module is written.
// Supported: Ethernet and BSD loopback carrying IPv4 with TCP / UDP / ICMP.
struct FrameSummary
{
    QString source;
    QString destination;
    QString protocol;
    QString info;
    QVector<sss::model::DetailNode> details;
};

FrameSummary summarizeFrame(const uchar *data,
                            int capturedLength,
                            int wireLength,
                            int linkType,
                            quint64 index,
                            const QDateTime &timestamp);

} // namespace sss::capture
