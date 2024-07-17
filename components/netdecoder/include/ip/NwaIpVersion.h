#pragma once

#include <stdint.h>

namespace Nwa::Network {

enum class IpVersion : uint8_t { Ip4 = 4, Ip6 = 6, Unknown };
}
