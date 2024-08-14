#pragma once

#include <string.h>
#include <stdint.h>

namespace Nta::Network
{
struct PacketBase;
struct IpParseResult;

bool parseIp6(const uint8_t *data, size_t len, IpParseResult& res);
bool parseIp6(const uint8_t*& data, size_t &len, PacketBase &p);
}  // namespace protocols
