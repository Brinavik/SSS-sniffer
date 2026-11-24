#pragma once

#include <QString>
#include <QVector>

#include "flow/TcpFlowTracker.h"

namespace sss::flow {

// One row of the Windows TCP owner-PID tables, already byte-order corrected.
struct TcpTableRow
{
    QString localAddress;
    quint16 localPort = 0;      // host byte order
    QString remoteAddress;      // empty for a listening socket
    quint16 remotePort = 0;     // 0 for a listening socket
    quint32 state = 0;          // MIB_TCP_STATE_*; 2 is LISTEN
    quint32 pid = 0;
    bool listening = false;
};

// The parsers mirror MIB_TCPROW_OWNER_PID / MIB_TCP6ROW_OWNER_PID field by
// field, so they take a raw buffer and can be tested with synthetic bytes
// without calling the Windows API.
QVector<TcpTableRow> parseTcpTableV4(const void *buffer, quint32 byteCount);
QVector<TcpTableRow> parseTcpTableV6(const void *buffer, quint32 byteCount);

// Finds the PID that owns a conversation: exact 4-tuple first (either
// direction), then a listening socket on one of the two ports. Returns 0 when
// nothing matches, which is normal for traffic that is not from this host.
quint32 resolvePid(const QVector<TcpTableRow> &rows, const TcpFlowKey &key);

} // namespace sss::flow
