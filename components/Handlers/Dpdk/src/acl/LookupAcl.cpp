#include "Handlers/Dpdk/Acl/LookupAcl.h"

void Nta::Network::RteAclContext::Create(const rte_acl_param &prm) {
    if (m_Context = ContextPtr(rte_acl_create(&prm), m_ContextDeleter); m_Context == nullptr) {
        throw std::runtime_error("Can't create ACL context!");
    }
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
        rte_acl_classify(ctx.RawPointer(), packets.data(), searchResult.data(), packets.size(), categories),
        searchResult};
}
