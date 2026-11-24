#pragma once

#include <QHash>
#include <QString>
#include <QVector>

#include "flow/TcpFlowTracker.h"
#include "flow/TcpTableParser.h"

namespace sss::flow {

// Maps a TCP conversation to the local process that owns it.
//
// The data comes from GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL), which is a
// snapshot: very short connections can disappear between two snapshots, so the
// caller refreshes when a new flow appears rather than only on a timer.
class ProcessResolver
{
public:
    // Re-reads the IPv4 and the IPv6 table. Cheap enough to call a few times a
    // second; the caller throttles it.
    void refresh();

    // Drops the snapshot and the image name cache (new capture, PID reuse).
    void reset();

    bool resolve(const TcpFlowKey &key, quint32 *pid) const;

    // Cached image name (e.g. "chrome.exe"); empty when the process cannot be
    // queried (protected processes, or the process already exited).
    QString processName(quint32 pid);

private:
    QVector<TcpTableRow> m_rows;
    QHash<quint32, QString> m_names;
};

} // namespace sss::flow
