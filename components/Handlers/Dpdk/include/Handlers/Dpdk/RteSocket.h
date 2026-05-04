#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <map>

namespace Nta::Network {
class RteCpuSocket {
  public:
    auto AddTupleFiveIp4Context(const int coreId, std::shared_ptr<RteAclContext> context) {
        m_TupleFiveIp4Context.emplace(coreId, std::move(context));
    }

    auto AddTupleFiveIp6Context(const int coreId, std::shared_ptr<RteAclContext> context) {
        m_TupleFiveIp6Context.emplace(coreId, std::move(context));
    }

    auto GetTupleFiveIp4Context(const int coreId) const {
        auto it = m_TupleFiveIp4Context.find(coreId);
        return it == std::end(m_TupleFiveIp4Context) ? nullptr : it->second;
    }

    auto GetTupleFiveIp6Context(const int coreId) const {
        auto it = m_TupleFiveIp6Context.find(coreId);
        return it == std::end(m_TupleFiveIp6Context) ? nullptr : it->second;
    }

    auto& GetTupleFiveIp4Contexts() const {
        return m_TupleFiveIp4Context;
    }

    auto& GetTupleFiveIp6Contexts() const {
        return m_TupleFiveIp6Context;
    }

  private:    
    std::map<int, std::shared_ptr<RteAclContext>> m_TupleFiveIp4Context{};
    std::map<int, std::shared_ptr<RteAclContext>> m_TupleFiveIp6Context{};
};
} // namespace Nta::Network
