#pragma once

#include <memory>

//Linux includes
struct ether_header;
struct vlan_tag;
struct iphdr;
struct ip6_hdr;
struct ip6_frag;
struct udphdr;
struct tcphdr;

namespace Nta::Network {

struct SctpHdr;
struct Gtp1Hdr;
struct Gtp2Hdr;
struct gtp_v2_opt;
struct PacketBase;
struct EthStat;
struct VlanStat;
struct IpStat;
struct UdpStat;
struct TcpStat;

class NetDecoderBase {
  public:
    NetDecoderBase();
    virtual ~NetDecoderBase() = default;

    bool DecodeEth(const uint8_t *&data, size_t &size, const struct ether_header *&eth);
    bool DecodeVlan(const uint8_t *&data, size_t &size, const struct vlan_tag *&vlan);
    bool DecodeIpv4(const uint8_t *&data, size_t &size, const struct iphdr *&iph);
    bool DecodeIpv6(const uint8_t *&data, size_t &size, const struct ip6_hdr *&ip6h, const struct ip6_frag *&ip6frag);
    bool DecodeUdp(const uint8_t *&data, size_t &size, const struct udphdr *&udph);
    bool DecodeTcp(const uint8_t *&data, size_t &size, const struct tcphdr *&tcph);
    bool DecodeSctp(const uint8_t *&data, size_t &size, const struct SctpHdr *&sctph);

    EthStat &GetEthStat() const;
    VlanStat &GetVlanStat() const;
    IpStat &GetIpStat() const;
    UdpStat &GetUdpStat() const;
    TcpStat &GetTcpStat() const;

    void ResetStat();

  private:
    struct Impl;
    struct ptr_impl : std::unique_ptr<Impl> {
        ~ptr_impl();
    } d;
};
} // namespace Nta::Network
