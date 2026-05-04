#pragma once

#include <cstddef>
#include <cstdint>
#include <rte_mbuf_core.h>
// #include <rte_ip4.h>
#include <rte_ip.h>
#include <rte_ether.h>

namespace Nta::Network {

struct EthHeader {
    constexpr static auto offset = sizeof(struct rte_ether_hdr);
};

struct IpV4HeaderPtoto {
    constexpr static auto offset = offsetof(struct rte_ipv4_hdr, next_proto_id);
};

template <typename... T> auto GetRtePktMbufMtodOffset(const rte_mbuf *mbuf, const size_t offset = 0) {
    if (uint8_t * p{nullptr}; !mbuf)
        return p;

    return reinterpret_cast<uint8_t *>(mbuf->buf_addr) + mbuf->data_off + offset + (T::offset + ...);
}
}
