#pragma once

#include "protocol/Dissector.h"

namespace sss::protocol::detail {

// Tries to recognize an application protocol inside an L4 payload.
// On success it appends a node to `out.details` and overwrites protocol/info
// with the more specific description (e.g. "HTTP" and the request line).
// Returns true when something was recognized.
bool dissectApplication(quint16 sourcePort,
                        quint16 destinationPort,
                        const uchar *payload,
                        int capturedBytes,
                        Dissection &out);

} // namespace sss::protocol::detail
