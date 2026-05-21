#pragma once

#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <regex>
#include <rte_ip.h>

namespace Nta::Network {

template <typename AclArray> class RteRuleMaker {
  public:
    [[nodiscard("Rule was generated, but not used")]] auto Make(
        const std::string &rule,
        const uint32_t categoryMask = (uint32_t)-1,
        const int32_t priority = RTE_ACL_MAX_PRIORITY,
        const uint32_t userData = 1) {
        using EmptyRule = RteAclLookupRule<AclArray::field_count>;

        static_assert(AclArray::field_count > 0, "Rule array should be greater than 0!");

        if (rule.empty())
            return EmptyRule{};

        if ('R' != rule[0])
            return EmptyRule{};

        std::regex regex{"[0-9x]{1,5}", std::regex::extended};
        const size_t matchValuesCount = 17;
        std::smatch matches;

        if (std::regex_search(rule, matches, regex)) {
            using RuleIter = std::remove_reference_t<decltype(rule)>::const_iterator;

            std::vector<uint16_t> values;
            values.reserve(matchValuesCount);

            for (std::regex_iterator<RuleIter> it(std::begin(rule), std::end(rule), regex);
                 it != std::regex_iterator<RuleIter>();
                 ++it) {

                if (auto pos = it->str().find('x'); pos != std::string::npos && pos > 0) {
                    values.push_back(std::stoi(it->str(), &++pos, 16));
                } else {
                    values.push_back(std::stoi(it->str()));
                }
            }

            if (matchValuesCount != values.size())
                throw std::runtime_error("Wrong rule string format!");

            // clang-format off
             return RteAclLookupRule<AclArray::field_count>{
                .data =
                    {
                        .category_mask = categoryMask,//0x01, // Number of categories (num_categories)
                        .priority = priority,
                        .userdata = userData,
                    },
                .fields{
                        AclArray::GetFields(values)
                    }};
            // clang-format on
        }
        return EmptyRule{};
    }
};
} // namespace Nta::Network
