#pragma once

#include <QVector>

#include "model/PacketRecord.h"

namespace sss::model {

// Builds a deterministic batch of demo frames for the UI skeleton.
// No socket, driver or network access is involved: every frame is synthesized
// in memory so the interface can be developed and reviewed before the capture
// module exists.
QVector<PacketRecord> makeSamplePackets(int count = 240);

} // namespace sss::model
