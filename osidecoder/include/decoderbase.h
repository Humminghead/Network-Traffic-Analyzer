#pragma once

#include <memory>

struct ether_header;
struct vlan_tag;
struct iphdr;
struct ip6_hdr;
struct ip6_frag;
struct udphdr;
struct tcphdr;
struct sctphdr;
struct Gtp1Hdr;
struct Gtp2Hdr;
struct gtp_v2_opt;

namespace protocols {

struct PacketBase;
struct EthStat;
struct VlanStat;
struct IpStat;
struct UdpStat;
struct TcpStat;

class DecoderBase
{
public:
    DecoderBase();
    virtual ~DecoderBase() = default;    

    bool decodeEth(const uint8_t *&data, size_t& size, const ether_header *&eth);
    bool decodeVlan(const uint8_t *&data, size_t& size, const vlan_tag *&vlan);
    bool decodeIpv4(uint32_t tm_sec, const uint8_t *&data, size_t& size, const struct iphdr*& iph);
    bool decodeIpv6(uint32_t tm_sec, const uint8_t *&data, size_t& size, const struct ip6_hdr*& ip6h, const struct ip6_frag*& ip6frag);
    bool decodeUdp(const uint8_t*& data, size_t& size, const udphdr *&udph);
    bool decodeTcp(const uint8_t *&data, size_t& size, const struct tcphdr*& tcph);
    bool decodeSctp(const uint8_t *&data, size_t& size, const struct sctphdr*& sctph);

    EthStat& getEthStat() const;
    VlanStat& getVlanStat() const;
    IpStat& getIpStat() const;
    UdpStat& getUdpStat() const;
    TcpStat& getTcpStat() const;

    void resetStat();
private:
    struct Impl;
    struct ptr_impl : std::unique_ptr<Impl> {
        ~ptr_impl();
    } d;
};
}
