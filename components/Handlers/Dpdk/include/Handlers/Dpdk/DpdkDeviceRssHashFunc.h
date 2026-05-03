#pragma once

namespace Nta::Network::Device {
/*!
 * \brief An enum describing all RSS (Receive Side Scaling) hash functions supported in DPDK. Notice not all  PMDs
 * support all types of hash functions
 */
enum DpdkRssHashFunction {
    /// No RSS
    RSS_NONE = 0,
    /// IPv4 based flow
    RSS_IPV4 = 0x1,
    /// Fragmented IPv4 based flow
    RSS_FRAG_IPV4 = 0x2,
    /// Non-fragmented IPv4 + TCP flow
    RSS_NONFRAG_IPV4_TCP = 0x4,
    /// Non-fragmented IPv4 + UDP flow
    RSS_NONFRAG_IPV4_UDP = 0x8,
    /// Non-fragmented IPv4 + SCTP flow
    RSS_NONFRAG_IPV4_SCTP = 0x10,
    /// Non-fragmented IPv4 + non TCP/UDP/SCTP flow
    RSS_NONFRAG_IPV4_OTHER = 0x20,
    /// IPv6 based flow
    RSS_IPV6 = 0x40,
    /// Fragmented IPv6 based flow
    RSS_FRAG_IPV6 = 0x80,
    /// Non-fragmented IPv6 + TCP flow
    RSS_NONFRAG_IPV6_TCP = 0x100,
    /// Non-fragmented IPv6 + UDP flow
    RSS_NONFRAG_IPV6_UDP = 0x200,
    /// Non-fragmented IPv6 + SCTP flow
    RSS_NONFRAG_IPV6_SCTP = 0x400,
    /// Non-fragmented IPv6 + non TCP/UDP/SCTP flow
    RSS_NONFRAG_IPV6_OTHER = 0x800,
    /// L2 payload based flow
    RSS_L2_PAYLOAD = 0x1000,
    /// IPv6 Ex based flow
    RSS_IPV6_EX = 0x2000,
    /// IPv6 + TCP Ex based flow
    RSS_IPV6_TCP_EX = 0x4000,
    /// IPv6 + UDP Ex based flow
    RSS_IPV6_UDP_EX = 0x8000,
    /// Consider device port number as a flow differentiator
    RSS_PORT = 0x10000,
    /// VXLAN protocol based flow
    RSS_VXLAN = 0x20000,
    /// GENEVE protocol based flow
    RSS_GENEVE = 0x40000,
    /// NVGRE protocol based flow
    RSS_NVGRE = 0x80000,
    /// All RSS functions supported by the device
    RSS_ALL_SUPPORTED = -1,
    /// A default set of RSS functions supported by the device
    RSS_DEFAULT = RSS_NONE
};

} // namespace Device
