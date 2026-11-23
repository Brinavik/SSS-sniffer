#pragma once

#include <QDateTime>
#include <QHash>
#include <QString>
#include <QVector>

#include "model/PacketRecord.h"

namespace sss::flow {

// Canonical 4-tuple key for one TCP connection: both endpoints plus their
// ports. Endpoints are sorted so the two directions of a conversation map to
// the same key.
struct TcpFlowKey
{
    QString addressA;
    quint16 portA = 0;
    QString addressB;
    quint16 portB = 0;

    bool isValid() const;
    bool operator==(const TcpFlowKey &other) const;

    static TcpFlowKey fromEndpoints(const QString &source, quint16 sourcePort,
                                    const QString &destination, quint16 destinationPort);

    // Returns false when the record is not a usable TCP record.
    static bool fromRecord(const sss::model::PacketRecord &record, TcpFlowKey *key);

    QString endpointAText() const;
    QString endpointBText() const;
};

inline size_t qHash(const TcpFlowKey &key, size_t seed = 0)
{
    return ::qHash(key.addressA, seed) ^ ::qHash(key.portA, seed)
           ^ ::qHash(key.addressB, seed) ^ ::qHash(key.portB, seed);
}

// Aggregated state for one connection.
struct TcpFlow
{
    TcpFlowKey key;

    QString initiatorAddress;   // who sent the first packet we saw
    quint16 initiatorPort = 0;
    QString responderAddress;
    quint16 responderPort = 0;

    QDateTime firstSeen;
    QDateTime lastSeen;
    quint64 firstPacketIndex = 0;

    quint64 packetsAToB = 0;
    quint64 packetsBToA = 0;
    quint64 bytesAToB = 0;
    quint64 bytesBToA = 0;

    bool sawSyn = false;
    bool sawSynAck = false;
    bool sawFin = false;
    bool sawRst = false;

    // Filled by the process resolver; 0 means "not attributed to a local
    // process" (for example traffic that was not sent by this host).
    quint32 pid = 0;
    QString processName;

    quint64 packetCount() const { return packetsAToB + packetsBToA; }
    quint64 byteCount() const { return bytesAToB + bytesBToA; }
    qint64 durationMs() const { return firstSeen.msecsTo(lastSeen); }
    QString stateText() const;
    QString initiatorText() const;
    QString responderText() const;
};

// Groups TCP packets into flows. Feed it every packet once; it ignores anything
// that is not TCP and keeps insertion order stable for the UI.
class TcpFlowTracker
{
public:
    void reset();

    // Returns true when a new flow was created.
    bool observe(const sss::model::PacketRecord &record);

    int count() const;
    QVector<TcpFlow> flows() const;
    const TcpFlow *flowAt(int index) const;

    // Used to attach the owning process right after a flow is created.
    TcpFlow *flowByKey(const TcpFlowKey &key);
    const TcpFlow *flowByKey(const TcpFlowKey &key) const;

private:
    QHash<TcpFlowKey, int> m_indexByKey; // key -> position in m_flows
    QVector<TcpFlow> m_flows;
};

} // namespace sss::flow
