#pragma once

#include <cstdint>

namespace Nta::Network
{
struct EthStat {
    virtual ~EthStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;
    uint64_t invalid_ethertype = 0;

    void reset() {
        pkt_count = 0;
        no_space = 0;
        invalid_ethertype = 0;
    };
};

struct VlanStat {
    virtual ~VlanStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;
    uint64_t invalid_ethertype = 0;

    void reset() {
        pkt_count = 0;
        no_space = 0;
        invalid_ethertype = 0;
    };
};

struct PppoeStat {
    virtual ~PppoeStat() = default;

    uint64_t pkt_count = 0;
    uint64_t ppptype_ip = 0;
    uint64_t ppptype_ip6 = 0;
    uint64_t ppptype_other = 0;

    void reset() {
        pkt_count = 0;
        ppptype_ip = 0;
        ppptype_ip6 = 0;
        ppptype_other = 0;
    };
};

struct IpStat {
    virtual ~IpStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;
    uint64_t ipv4 = 0;
    uint64_t ipv6 = 0;
    uint64_t ipv4_udp = 0;
    uint64_t ipv4_tcp = 0;
    uint64_t ipv4_icmp = 0;
    uint64_t ipv6_udp = 0;
    uint64_t ipv6_tcp = 0;
    uint64_t ipv6_icmpv6 = 0;
    uint64_t ipv6_ext_hdrs = 0;
    uint64_t invalid_version = 0;
    uint64_t invalid_tot_len = 0;
    uint64_t invalid_protocol = 0;
    uint64_t unsupported_ip_proto = 0;   

    void reset() { *this = {}; };
};

struct UdpStat {
    virtual ~UdpStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;

    void reset() {*this = {};};
};

struct TcpStat {
    virtual ~TcpStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;

    void reset() {*this = {};};
};

struct SctpStat {
    virtual ~SctpStat() = default;

    uint64_t pkt_count = 0;
    uint64_t no_space = 0;

    void reset() { *this = {}; };
};

struct GtpStat {
    uint64_t pkt_count = 0;
    uint64_t user_ipv4 = 0;
    uint64_t user_ipv6 = 0;
    uint64_t no_space_pco = 0;
    uint64_t no_space = 0;
    uint64_t invalid_version = 0;
    uint64_t invalid_tpdu_len = 0;
    uint64_t no_space_ext = 0;
    uint64_t invalid_ext_len = 0;
    uint64_t invalid_ie = 0;

    void reset() {*this = {};};
};
}
