#pragma once

#include "Json.h"
#include <nlohmann/json.hpp>
#include <string>

namespace Nta::Json::Objects {
struct JsonObjectHandler {
    std::string m_Type{};
    std::string m_Device{};

    [[maybe_unused]] static auto ToJson(const JsonObjectHandler &p) -> nlohmann::json{
        // clang-format off
        return
        {
             {"device", p.m_Device},
             {"type", p.m_Type}
        };
        // clang-format on
    }

    [[maybe_unused]] static void FromJson(const nlohmann::json &j, JsonObjectHandler &p) {
        ///\warning execeptions if field name is mising
        Util::Json::GetTo(j, "type", p.m_Type);
        Util::Json::GetTo(j, "device", p.m_Device);
    }
};
} // namespace Nta::Json::Objects
