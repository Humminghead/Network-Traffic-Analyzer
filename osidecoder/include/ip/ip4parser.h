#pragma once

#include <string.h>
#include <stdint.h>

namespace protocols
{
struct IpParseResult;
}

namespace protocols
{
bool parseIp4(const uint8_t *data, size_t len, IpParseResult& res);
}  // namespace protocols
