#pragma once

#include <stdint.h>
#include <strings.h>

namespace Nwa::Network {
struct IpParseResult;
bool HandleIp4(const uint8_t *data, size_t len, IpParseResult &res);
} // namespace Nwa::Network
