#pragma once

#include "Util/Json.h"
#include <nlohmann/json.hpp>
#include <string>

namespace Nta::Json::Objects {
struct HandlerObject {
    std::string m_Type{};
    std::string m_Device{};

    [[maybe_unused]] static auto ToJson(const HandlerObject &p) -> nlohmann::json{
        // clang-format off
        return
        {
             {"device", p.m_Device},
             {"type", p.m_Type}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, HandlerObject &p) {
        ///\warning execeptions if field name is mising
        Util::Json::GetTo(j, "type", p.m_Type);
        Util::Json::GetTo(j, "device", p.m_Device);
    }
};

[[maybe_unused]] static void to_json(nlohmann::json &j, const HandlerObject &p) {
    j = HandlerObject::ToJson(p);
}

[[maybe_unused]] static void from_json(const nlohmann::json &j, HandlerObject &p) {
    HandlerObject::FromJson(j, p);
}
} // namespace Nta::Json::Objects
