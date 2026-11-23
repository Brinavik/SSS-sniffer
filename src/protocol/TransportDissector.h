#pragma once

#include "protocol/Dissector.h"

namespace sss::protocol::detail {

// Input for the transport layer: where the L4 header starts, how many bytes are
// actually captured, and how long the IP payload claims to be.
struct TransportInput
{
    QString sourceAddress;
    QString destinationAddress;
    quint8 protocol = 0;
    quint8 ipVersion = 0;
    const uchar *header = nullptr;
    int capturedBytes = 0;
    int declaredBytes = 0;
};

// Dispatches TCP / UDP / ICMP / ICMPv6 and updates protocol, info, ports and
// details of `out`. Falls back to a generic description for unknown protocols.
void dissectTransport(const TransportInput &input, Dissection &out);

} // namespace sss::protocol::detail
