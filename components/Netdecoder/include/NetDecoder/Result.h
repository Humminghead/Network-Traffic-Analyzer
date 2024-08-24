#pragma once

#include <tuple>

namespace Nta::Network {
struct Packet;
using Result = std::tuple<bool, Packet>;
} // namespace Nta::Network
