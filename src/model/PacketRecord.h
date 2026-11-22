#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace sss::model {

// One node of the protocol detail tree, e.g. "Internet Protocol Version 4".
// The tree is generic on purpose: real dissectors will fill it the same way.
struct DetailNode
{
    QString name;
    QString value;
    QVector<DetailNode> children;
};

// A single captured frame plus the metadata the UI needs.
// `raw` holds the bytes shown in the hex pane; `details` feeds the tree view.
struct PacketRecord
{
    quint64 index = 0;            // 1-based ordinal inside the capture
    QDateTime timestamp;
    QString source;               // IP (or MAC for non-IP frames)
    QString destination;
    QString protocol;             // "TCP", "UDP", "ICMP", "HTTP", "DNS"
    int length = 0;               // frame length in bytes
    QString info;                 // one-line summary, Wireshark style
    QByteArray raw;
    QVector<DetailNode> details;
};

} // namespace sss::model
