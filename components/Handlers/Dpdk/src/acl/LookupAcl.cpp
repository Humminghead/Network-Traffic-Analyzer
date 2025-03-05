#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>

struct EthHeader {
    constexpr static auto offset = sizeof(struct rte_ether_hdr);
};

struct IpV4HeaderPtoto {
    constexpr static auto offset = offsetof(struct rte_ipv4_hdr, next_proto_id);
};

template <typename... T> auto GetRtePktMbufMtodOffset(const rte_mbuf *mbuf) {
    if (uint8_t * p{nullptr}; !mbuf)
        return p;

    return reinterpret_cast<uint8_t *>(mbuf->buf_addr) + mbuf->data_off + (T::offset + ...);
}

void Nta::Network::RteAclContext::Create(const rte_acl_param &prm) {
    if (m_Context = ContextPtr(rte_acl_create(&prm), m_ContextDeleter); m_Context == nullptr) {
        throw std::runtime_error("Can't create ACL context!");
    }
}

auto Nta::Network::RteAclContext::SetClassify(enum rte_acl_classify_alg alg) -> bool {
    if (rte_acl_set_ctx_classify(RawPointer(), alg) != 0)
        return false;
    return true;
}

auto Nta::Network::RteAclContext::Build() -> void {
    auto ret = rte_acl_build(RawPointer(), &m_Cfg);
    if (ret != 0) {
        throw std::runtime_error("Error at build runtime structures for ACL context!");
    }
}

Nta::Network::RteLookupAcl::Result Nta::Network::RteLookupAcl::Classify(
    const RteAclContext &ctx,
    std::vector<const uint8_t *> &packets,
    const uint32_t categories) {
    std::vector<uint32_t> searchResult;
    searchResult.resize(packets.size());
    return {
        0 == rte_acl_classify(ctx.RawPointer(), packets.data(), searchResult.data(), packets.size(), categories),
        searchResult};
}

Nta::Network::RteLookupAcl::Result Nta::Network::RteLookupAcl::Classify(
    const RteAclContext &ctx,
    const uint8_t **data,
    const uint32_t nbRx,
    uint32_t *results,
    uint32_t num,
    const uint32_t categories) {
    std::vector<uint32_t> searchResult;
    searchResult.resize(nbRx);
    return {0 == rte_acl_classify(ctx.RawPointer(), data, results, num, categories), searchResult};
}

auto Nta::Network::PrefetchCpuCache(const std::vector<rte_mbuf *> &rxPkts, const size_t prefetchCount) -> void {
    for (auto i = 0; i < prefetchCount && i < rxPkts.size(); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(rxPkts[i], void *));
    }
}

Nta::Network::RteLookupAcl::Result Nta::Network::RteLookupAcl::Classify(
    const RteAclContext &ctx,
    const std::vector<rte_mbuf *> &rxPkts,
    const uint32_t categories) {
    std::vector<const uint8_t *> packetPointers;
    packetPointers.reserve(rxPkts.size());

    for (auto *mbuf : rxPkts) {
        if (!mbuf)
            break;
        packetPointers.push_back(GetRtePktMbufMtodOffset<EthHeader, IpV4HeaderPtoto>(mbuf));
    }

    return Classify(ctx, packetPointers, categories);
}
