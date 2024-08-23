#pragma once

#include <cstddef>
#include <cstdint>

namespace Nta::Network {
struct GtpHeader;
struct Packet;
} // namespace Nta::Network

namespace Nta::Network::Util {

uint16_t GetIpProtocol(const Packet &p);
int8_t GetIpVersion(const Packet &p);
int8_t GetGtpVersion(const Packet &p);
static int8_t GetGtpVersion(const GtpHeader *gtph);
bool IsGtpv1HdrExt(const Packet &p);
bool IsIp4Fragment(const Packet &p);
bool IsIp6Fragment(const Packet &p);
bool IsIpFragment(const Packet &p);

} // namespace Nta::Network::Util
