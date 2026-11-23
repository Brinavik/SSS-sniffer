#include "flow/TcpFlowTracker.h"

namespace sss::flow {
namespace {

// Orders the two endpoints of a conversation so that a packet and its reply
// produce the same key regardless of direction.
bool endpointLess(const QString &firstAddress, quint16 firstPort,
                  const QString &secondAddress, quint16 secondPort)
{
    const int comparison = QString::compare(firstAddress, secondAddress, Qt::CaseInsensitive);
    if (comparison != 0) {
        return comparison < 0;
    }
    return firstPort < secondPort;
}

QString endpointText(const QString &address, quint16 port)
{
    if (address.isEmpty()) {
        return QStringLiteral("-");
    }
    return QString("%1:%2").arg(address).arg(port);
}

} // namespace

bool TcpFlowKey::isValid() const
{
    return !addressA.isEmpty() && !addressB.isEmpty() && portA != 0 && portB != 0;
}

bool TcpFlowKey::operator==(const TcpFlowKey &other) const
{
    return portA == other.portA
           && portB == other.portB
           && addressA == other.addressA
           && addressB == other.addressB;
}

TcpFlowKey TcpFlowKey::fromEndpoints(const QString &source, quint16 sourcePort,
                                     const QString &destination, quint16 destinationPort)
{
    // Addresses are case folded once, here, so that operator== and qHash can
    // stay exact: two spellings of the same IPv6 address must never end up in
    // two different flows.
    const QString first = source.toLower();
    const QString second = destination.toLower();

    TcpFlowKey key;
    if (endpointLess(first, sourcePort, second, destinationPort)) {
        key.addressA = first;
        key.portA = sourcePort;
        key.addressB = second;
        key.portB = destinationPort;
    } else {
        key.addressA = second;
        key.portA = destinationPort;
        key.addressB = first;
        key.portB = sourcePort;
    }
    return key;
}

bool TcpFlowKey::fromRecord(const sss::model::PacketRecord &record, TcpFlowKey *key)
{
    // Ports are only meaningful for TCP; a UDP datagram on the same pair of
    // ports must not be folded into a connection.
    if (record.ipProtocol != 6) {
        return false;
    }
    if (record.source.isEmpty() || record.destination.isEmpty()) {
        return false;
    }
    if (record.sourcePort == 0 || record.destinationPort == 0) {
        return false;
    }

    if (key != nullptr) {
        *key = fromEndpoints(record.source, record.sourcePort,
                             record.destination, record.destinationPort);
        // Ports and addresses must both be usable; a truncated TCP header has
        // no ports and must not create a flow.
        return key->isValid();
    }
    return true;
}

QString TcpFlowKey::endpointAText() const
{
    return endpointText(addressA, portA);
}

QString TcpFlowKey::endpointBText() const
{
    return endpointText(addressB, portB);
}

QString TcpFlow::stateText() const
{
    if (sawRst) {
        return QStringLiteral("RESET");
    }
    if (sawFin) {
        return QStringLiteral("CLOSED");
    }
    if (sawSynAck) {
        return QStringLiteral("ESTABLISHED");
    }
    if (sawSyn) {
        return QStringLiteral("SYN SENT");
    }
    return QStringLiteral("ACTIVE");
}

QString TcpFlow::initiatorText() const
{
    return endpointText(initiatorAddress, initiatorPort);
}

QString TcpFlow::responderText() const
{
    return endpointText(responderAddress, responderPort);
}

void TcpFlowTracker::reset()
{
    m_indexByKey.clear();
    m_flows.clear();
}

bool TcpFlowTracker::observe(const sss::model::PacketRecord &record)
{
    TcpFlowKey key;
    if (!TcpFlowKey::fromRecord(record, &key)) {
        return false;
    }

    const bool fromA = (record.source == key.addressA && record.sourcePort == key.portA);

    bool created = false;
    auto it = m_indexByKey.constFind(key);
    if (it == m_indexByKey.constEnd()) {
        TcpFlow flow;
        flow.key = key;
        flow.firstSeen = record.timestamp;
        flow.lastSeen = record.timestamp;
        flow.firstPacketIndex = record.index;
        if (fromA) {
            flow.initiatorAddress = record.source;
            flow.initiatorPort = record.sourcePort;
            flow.responderAddress = record.destination;
            flow.responderPort = record.destinationPort;
        } else {
            flow.initiatorAddress = record.destination;
            flow.initiatorPort = record.destinationPort;
            flow.responderAddress = record.source;
            flow.responderPort = record.sourcePort;
        }

        m_indexByKey.insert(key, static_cast<int>(m_flows.size()));
        m_flows.append(flow);
        it = m_indexByKey.constFind(key);
        created = true;
    }

    TcpFlow &flow = m_flows[it.value()];
    flow.lastSeen = record.timestamp;

    if (fromA) {
        ++flow.packetsAToB;
        flow.bytesAToB += static_cast<quint64>(record.length);
    } else {
        ++flow.packetsBToA;
        flow.bytesBToA += static_cast<quint64>(record.length);
    }

    const quint8 flags = record.tcpFlags;
    const bool syn = (flags & 0x02) != 0;
    const bool ack = (flags & 0x10) != 0;

    if (syn) {
        if (ack) {
            flow.sawSynAck = true;
        } else {
            // A SYN without ACK starts a new connection. The same 4-tuple can
            // be reused after TIME_WAIT, so drop the previous session's state;
            // otherwise the new conversation would be born "CLOSED".
            flow.sawFin = false;
            flow.sawRst = false;
            flow.sawSynAck = false;
            flow.sawSyn = true;
            // The SYN names the client even when we started capturing mid-flow.
            flow.initiatorAddress = record.source;
            flow.initiatorPort = record.sourcePort;
            flow.responderAddress = record.destination;
            flow.responderPort = record.destinationPort;
        }
    }
    if ((flags & 0x01) != 0) {
        flow.sawFin = true;
    }
    if ((flags & 0x04) != 0) {
        flow.sawRst = true;
    }

    return created;
}

int TcpFlowTracker::count() const
{
    return static_cast<int>(m_flows.size());
}

QVector<TcpFlow> TcpFlowTracker::flows() const
{
    return m_flows;
}

const TcpFlow *TcpFlowTracker::flowAt(int index) const
{
    if (index < 0 || index >= m_flows.size()) {
        return nullptr;
    }
    return &m_flows.at(index);
}

} // namespace sss::flow
