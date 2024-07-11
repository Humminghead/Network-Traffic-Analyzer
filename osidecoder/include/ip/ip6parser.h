#pragma once

#include <string.h>
#include <stdint.h>

namespace protocols
{
struct PacketBase;
struct IpParseResult;
}

namespace protocols
{
bool parseIp6(const uint8_t *data, size_t len, IpParseResult& res);
bool parseIp6(const uint8_t*& data, size_t &len, protocols::PacketBase &p);
}  // namespace protocols
