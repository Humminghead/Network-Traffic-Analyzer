#pragma once

#include "Handlers/Dpdk/Acl/Classification/Tuple5.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"
#include <concepts>
#include <regex>
#include <rte_ip.h>

namespace Nta::Network {

struct FiveTupleIp4;

template <typename T>
concept IsFiveTupleIp4 = std::is_same<T, FiveTupleIp4>::value;

template <typename Rule> class RteRuleMaker;

template <IsFiveTupleIp4 Rule> class RteRuleMaker<Rule> {
  public:
    [[nodiscard("Rule was generated, but not used")]] auto Make(const std::string &rule, const uint32_t categoryMask = (uint32_t)-1, const int32_t  priority = RTE_ACL_MAX_PRIORITY, const uint32_t userData = 1) {
        using EmptyRule = RteAclLookupRule<FiveTupleIp4Defs.size()>;
        if (rule.empty())
            return EmptyRule{};

        if ('R' != rule[0])
            return EmptyRule{};      

        std::regex regex{"[0-9x]{1,4}", std::regex::extended};
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
            return RteAclLookupRule<FiveTupleIp4Defs.size()>{
                .data =
                    {
                        .category_mask = categoryMask,//0x01, // Number of categories (num_categories)
                        .priority = priority,
                        .userdata = userData,
                    },
                .fields{{
                    {.value{.u8 = static_cast<uint8_t>(values[14])}, .mask_range{.u32 = values[15]}},//PROTO
                    {.value{.u32 = RTE_IPV4(values[0], values[1], values[2], values[3])}, .mask_range{.u32 = values[4]}},//IP_SRC
                    {.value{.u32 = RTE_IPV4(values[5], values[6], values[7], values[8])}, .mask_range{.u32 = values[9]}},//IP_DST
                    {.value{.u16 = values[10]}, .mask_range{.u16 = values[11]}},//PORT_SRC
                    {.value{.u16 = values[12]}, .mask_range{.u16 = values[13]}},//PORT_DST
                }}};
            // clang-format on
        }
        return EmptyRule{};
    }
};
} // namespace Nta::Network
