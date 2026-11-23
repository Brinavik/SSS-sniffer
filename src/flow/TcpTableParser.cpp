#include "flow/TcpTableParser.h"

#include <cstring>

#include "protocol/ProtocolHelpers.h"

namespace sss::flow {
namespace {

// Mirrors MIB_TCPROW_OWNER_PID.
struct RawTcp4Row
{
    quint32 state;
    quint32 localAddress;
    quint32 localPort;
    quint32 remoteAddress;
    quint32 remotePort;
    quint32 pid;
};

// Mirrors MIB_TCP6ROW_OWNER_PID. The 16 byte addresses keep the following
// 32 bit fields naturally aligned, so no packing attributes are needed.
struct RawTcp6Row
{
    quint8 localAddress[16];
    quint32 localScopeId;
    quint32 localPort;
    quint8 remoteAddress[16];
    quint32 remoteScopeId;
    quint32 remotePort;
    quint32 state;
    quint32 pid;
};

// The tables store the port in network byte order inside the low 16 bits of a
// DWORD. Reading that DWORD on a little-endian machine yields the two port
// bytes swapped, which is why every consumer has to convert. This is the
// ntohs() equivalent, kept platform independent so it can be unit tested.
quint16 hostPort(quint32 value)
{
    const quint16 stored = static_cast<quint16>(value & 0xFFFF);
    return static_cast<quint16>((stored >> 8) | (stored << 8));
}

QString ipv4FromDword(quint32 value)
{
    uchar bytes[4] = {0, 0, 0, 0};
    std::memcpy(bytes, &value, sizeof(bytes));
    return sss::protocol::detail::ipv4Text(bytes);
}

QString ipv6FromBytes(const quint8 *bytes)
{
    return sss::protocol::detail::ipv6Text(bytes);
}

} // namespace

QVector<TcpTableRow> parseTcpTableV4(const void *buffer, quint32 byteCount)
{
    QVector<TcpTableRow> rows;

    const quint32 headerSize = sizeof(quint32);
    if (buffer == nullptr || byteCount < headerSize) {
        return rows;
    }

    const auto *bytes = static_cast<const uchar *>(buffer);
    quint32 count = 0;
    std::memcpy(&count, bytes, sizeof(count));

    const quint32 rowSize = sizeof(RawTcp4Row);
    if (count > (byteCount - headerSize) / rowSize) {
        return rows; // truncated or hostile buffer
    }

    for (quint32 index = 0; index < count; ++index) {
        RawTcp4Row raw {};
        std::memcpy(&raw, bytes + headerSize + index * rowSize, rowSize);

        TcpTableRow row;
        row.localAddress = ipv4FromDword(raw.localAddress);
        row.localPort = hostPort(raw.localPort);
        row.remotePort = hostPort(raw.remotePort);
        row.pid = raw.pid;
        row.listening = (row.remotePort == 0);
        if (!row.listening) {
            row.remoteAddress = ipv4FromDword(raw.remoteAddress);
        }
        rows.append(row);
    }

    return rows;
}

QVector<TcpTableRow> parseTcpTableV6(const void *buffer, quint32 byteCount)
{
    QVector<TcpTableRow> rows;

    const quint32 headerSize = sizeof(quint32);
    if (buffer == nullptr || byteCount < headerSize) {
        return rows;
    }

    const auto *bytes = static_cast<const uchar *>(buffer);
    quint32 count = 0;
    std::memcpy(&count, bytes, sizeof(count));

    const quint32 rowSize = sizeof(RawTcp6Row);
    if (count > (byteCount - headerSize) / rowSize) {
        return rows;
    }

    for (quint32 index = 0; index < count; ++index) {
        RawTcp6Row raw {};
        std::memcpy(&raw, bytes + headerSize + index * rowSize, rowSize);

        TcpTableRow row;
        row.localAddress = ipv6FromBytes(raw.localAddress);
        row.localPort = hostPort(raw.localPort);
        row.remotePort = hostPort(raw.remotePort);
        row.pid = raw.pid;
        row.listening = (row.remotePort == 0);
        if (!row.listening) {
            row.remoteAddress = ipv6FromBytes(raw.remoteAddress);
        }
        rows.append(row);
    }

    return rows;
}

quint32 resolvePid(const QVector<TcpTableRow> &rows, const TcpFlowKey &key)
{
    // 1. Exact 4-tuple, in either orientation.
    for (const TcpTableRow &row : rows) {
        if (row.listening) {
            continue;
        }
        const bool forward = row.localAddress == key.addressA && row.localPort == key.portA
                             && row.remoteAddress == key.addressB && row.remotePort == key.portB;
        const bool reverse = row.localAddress == key.addressB && row.localPort == key.portB
                             && row.remoteAddress == key.addressA && row.remotePort == key.portA;
        if (forward || reverse) {
            return row.pid;
        }
    }

    // 2. Fallback: a listening socket on one of the ports belongs to the
    //    service that accepted the connection.
    for (const TcpTableRow &row : rows) {
        if (!row.listening) {
            continue;
        }
        if (row.localPort == key.portA || row.localPort == key.portB) {
            return row.pid;
        }
    }

    return 0;
}

} // namespace sss::flow
