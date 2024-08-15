#pragma once

#include "Handlers/Common/JsonObjectHandler.h"
#include "Util/Json.h"
#include <nlohmann/json.hpp>
#include <string>

namespace Nta::Json::Objects {
struct JsonObjectPcap : JsonObjectHandler {
    std::string m_BpfFilter{};
    bool m_PromiscuousMode{false};

    [[maybe_unused]] static auto ToJson(const JsonObjectPcap &p) -> nlohmann::json {
        // clang-format off
        return {
             {"filter", p.m_BpfFilter},
             {"promiscuous", p.m_PromiscuousMode}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, JsonObjectPcap &p) {
        ///\warning execeptions if field name is mising
        Util::Json::GetTo(j, "filter", p.m_BpfFilter);
        Util::Json::GetTo(j, "promiscuous", p.m_PromiscuousMode);
    }
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const JsonObjectPcap &p) {
    ///\warning may corrupt app memory (uncheked)
    // clang-format off
    std::apply(
        [&j](auto&&... jIn) {
            (j.merge_patch(jIn), ...);
        },
        std::make_tuple(JsonObjectHandler::ToJson(p), JsonObjectPcap::ToJson(p)));
    // clang-format on
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, JsonObjectPcap &p) {
    JsonObjectHandler::FromJson(j, p);
    JsonObjectPcap::FromJson(j, p);
}

} // namespace Nta::Json::Objects
