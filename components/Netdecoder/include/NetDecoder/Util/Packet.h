#pragma once

#include <cstddef>
#include <cstdint>

namespace Nta::Network {
struct GtpHeader;
struct PacketBase;
} // namespace Nta::Network

namespace Nta::Network::Util {

uint16_t GetIpProtocol(const PacketBase &p);
int8_t GetIpVersion(const PacketBase &p);
int8_t GetGtpVersion(const PacketBase &p);
static int8_t GetGtpVersion(const GtpHeader *gtph);
size_t GetTotalSize(const PacketBase &p);
bool IsGtpv1HdrExt(const PacketBase &p);
bool IsIp4Fragment(const PacketBase &p);
bool IsIp6Fragment(const PacketBase &p);
bool IsIpFragment(const PacketBase &p);

} // namespace Nta::Network::Util
