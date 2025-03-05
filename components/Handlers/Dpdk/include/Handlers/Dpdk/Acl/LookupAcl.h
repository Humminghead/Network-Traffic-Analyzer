#pragma once

#include <array>
#include <functional>
#include <memory>
#include <rte_acl.h>
#include <stdexcept>

struct rte_mbuf;

namespace Nta::Network {

template <size_t N> struct RteAclLookupRule {
    struct rte_acl_rule_data data;
    std::array<rte_acl_field, N> fields;
};

/*!
 * \brief Creates for a given set of rules internal structure for further run-time traversal.
 * https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html#overview
 * 7.1.2. RT memory size limit
 */
class RteAclContext {
  public:
    /*!
     * \brief Sets maximum memory limit for internal RT structures for given AC context.Setting it to zero makes
     * rte_acl_build() to use the default behavior: try to minimize size of the RT structures, but doesn’t expose any
     * hard limit on it.
     *
     * Example:
     * try to build AC context, with RT structures less then 8MB:
     * cfg.max_size = 0x800000;
     *
     * \param size
     */
    RteAclContext(const size_t maxSize = 0) : m_Cfg{.max_size = maxSize} {}

    /*!
     * \brief Creates context with parameters of the dpdk ACL context.
     * \param Name of the ACL context
     * \param Size of each rule
     * \param Maximum number of rules
     * \param Socket ID to allocate memory for
     */
    RteAclContext(
        const std::string_view name,
        const uint32_t numFields,
        const uint32_t maxRuleNum,
        const int socketId = SOCKET_ID_ANY)
        : m_Cfg{.num_fields = numFields}, m_Prm{
                                              .name = name.data(),
                                              .socket_id = socketId,
                                              .rule_size = static_cast<uint32_t>(RTE_ACL_RULE_SZ(numFields)),
                                              .max_rule_num = maxRuleNum} {
        Create(m_Prm);
    }

    /*!
     * \brief Creates an empty AC context with the inner parameters
     */
    void Create() { Create(m_Prm); }

    /*!
     * \brief Creates an empty AC context
     * \param AC context creation parameters
     */
    void Create(const rte_acl_param &param);

    /*!
     * \brief Returns rte_acl_ctx raw pointer
     */
    auto RawPointer() const { return m_Context.get(); }

    /*!
     * \brief Set number of categories to build with
     * \param number of categories
     */
    auto SetNumCategories(const uint32_t num) { m_Cfg.num_categories = num; }

    /*!
     * \brief Set number of field definitions
     * \param number of fields
     */
    auto SetNumFields(const uint32_t numFields) { m_Cfg.num_fields = numFields; }

    /*!
     * \brief Set maximal possibe rule count in context
     * \param rule count
     */
    auto SetMaxRuleCount(const size_t maxRuleCount) { m_Prm.max_rule_num = maxRuleCount; }

    /*!
     * \brief Set name of the context
     * \param name
     */
    auto SetName(const std::string_view name) { m_Prm.name = name.data(); }

    /*!
     * \brief Set socket ID to allocate memory for
     * \param id
     */
    auto SetSocketId(const int id) { m_Prm.socket_id = id; }

    /*!
     * \brief Set size of each rule
     * \param num of fields
     */
    auto SetRuleSize(const uint32_t numFields) { m_Prm.rule_size = static_cast<uint32_t>(RTE_ACL_RULE_SZ(numFields)); }

    /*!
     * \brief Sets size of each rule and number of fields defenitions
     * \param num of fields
     */
    auto SetNumFieldsAndRuleSize(const uint32_t numFields) {
        m_Cfg.num_fields = numFields;
        m_Prm.rule_size = static_cast<uint32_t>(RTE_ACL_RULE_SZ(numFields));
    }

    /*!
     * \brief Sets array of field definitions that can be used
     * \param d
     */
    template <size_t N> auto SetCfgDefs(const std::array<rte_acl_field_def, N> &d) {
        memcpy(m_Cfg.defs, d.data(), sizeof(d));
    }

    /*!
     * \brief Build runtime structures for ACL context
     */
    auto Build() -> void;

    /*!
     * \brief Add rules to the context
     * \param context
     * \param rules
     */
    template <size_t N> void AddRules(const std::vector<RteAclLookupRule<N>> &rules) {
        if (auto ret = rte_acl_add_rules(RawPointer(), (const rte_acl_rule *)rules.data(), rules.size()); ret != 0) {
            throw std::runtime_error("Handle error at adding ACL rules!");
        }
    }

  private:
    using ContextPtr = std::unique_ptr<rte_acl_ctx, std::function<void(rte_acl_ctx *)>>;

    static void m_ContextDeleter(rte_acl_ctx *p) { rte_free(p); };

    ContextPtr m_Context{nullptr, m_ContextDeleter};
    rte_acl_config m_Cfg;
    rte_acl_param m_Prm{.name = "ACL context", .socket_id = SOCKET_ID_ANY};
};

class RteLookupAcl {
  public:
    using Result = std::pair<int, std::vector<uint32_t>>;
    /*!
     * \brief Classify
     * \param ctx
     * \param data
     * \param categories
     * \return
     */
    Result Classify(const RteAclContext &ctx, std::vector<const uint8_t *> &packets, const uint32_t categories = 1);

    /*!
     * \brief Classify
     * \param ctx
     * \param data
     * \param results
     * \param num
     * \param categories
     * \return
     */
    Result Classify(const RteAclContext &ctx, const uint8_t **data,const uint32_t nbRx, uint32_t *results, uint32_t num, const uint32_t categories = 1);

    Result Classify(const RteAclContext &ctx, const std::vector<rte_mbuf *>& rxPkts, const uint32_t categories = 1);
};

auto PrefetchCpuCache(const std::vector<rte_mbuf *>& rxPkts, const size_t prefetchCount)  -> void;

} // namespace Nta::Network
