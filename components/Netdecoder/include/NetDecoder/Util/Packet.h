#pragma once

#include <cstdint>

struct iphdr;
struct ip6_frag;

namespace Nta::Network {
struct GtpHeader;
struct Packet;
enum class LinkLayer : unsigned short;
} // namespace Nta::Network

namespace Nta::Network::Util {
LinkLayer GetL2Type(const Packet &p);
uint16_t GetL3Type(const Packet &p);
uint16_t GetL4Type(const Packet &p);
uint16_t GetIpProtocol(const Packet &p);
int8_t GetIpVersion(const Packet &p);
bool IsGtpv1HdrExt(const GtpHeader *p);
static int8_t GetGtpVersion(const GtpHeader *gtph);
bool IsGtpv1HdrExt(const Packet &p);
bool IsIp4FragmentFlagSet(const iphdr *ip4Header);
bool IsIp4Fragment(const Packet &p);
bool IsIp6Fragment(const ip6_frag *p);
bool IsIp6Icmp(const Packet &p);
LinkLayer GetLinkLayerFromNetProtoType(const uint16_t linkLayer);

} // namespace Nta::Network::Util
