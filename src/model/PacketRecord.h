#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace sss::model {

// One node of the protocol detail tree, e.g. "Internet Protocol Version 4".
// The tree is generic on purpose: every dissector fills it the same way.
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

    // Address shown in the list. IP address for IP frames (ARP: the advertised
    // IPv4 addresses); MAC address for everything else; "-" when unknown.
    QString source;
    QString destination;

    QString protocol;             // highest recognized layer, e.g. "HTTP" / "TCP" / "IPv4"
    int length = 0;               // frame length in bytes
    QString info;                 // one-line summary, Wireshark style

    QByteArray raw;
    QVector<DetailNode> details;

    // Structured fields, filled by the dissector, kept for the display filter.
    quint8 ipVersion = 0;         // 4 / 6, 0 when the frame carries no IP header
    quint8 ipProtocol = 0;        // IANA transport protocol number
    quint16 sourcePort = 0;
    quint16 destinationPort = 0;
    quint8 tcpFlags = 0;          // TCP flag bits, 0 for every non-TCP frame
};

} // namespace sss::model
