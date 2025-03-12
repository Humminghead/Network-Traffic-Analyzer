#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>

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
    PacketPointers &packets,
    const uint32_t categories) {
    std::vector<uint32_t> searchResult;
    searchResult.resize(packets.size());
    return {
        0 == rte_acl_classify(ctx.RawPointer(), packets.data(), searchResult.data(), packets.size(), categories),
        searchResult};
}

auto Nta::Network::PrefetchCpuCache(const std::vector<rte_mbuf *> &rxPkts, const size_t prefetchCount) -> void {
    for (auto i = 0; i < prefetchCount && i < rxPkts.size(); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(rxPkts[i], void *));
    }
}
