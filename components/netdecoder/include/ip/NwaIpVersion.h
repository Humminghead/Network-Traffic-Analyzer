#pragma once

#include <stdint.h>

namespace Nta::Network {

enum class IpVersion : uint8_t { Ip4 = 4, Ip6 = 6, Unknown };
}
