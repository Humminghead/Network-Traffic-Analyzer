#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace Nta::Utility::Json {
template <typename ValueType>
static inline void tryGetValue(const nlohmann::json &j, const std::string &name, ValueType &value) noexcept {
    value = j.contains(name) ? j.at(name).get_to(value) : value;
}
} // namespace Nta::Utility::Json

namespace Nta::Json::Objects {
struct JsonObjectPcap {
    std::string m_Device{};
    std::string m_BpfFilter{};
    bool m_PromiscuousMode{false};///\todo false
};

/**
 * @brief to_json
 * @param j
 * @param p
 */
[[maybe_unused]] static void to_json(nlohmann::json &j, const JsonObjectPcap &p) {
    // clang-format off
    j = nlohmann::json{                
        {"device", p.m_Device},
        {"filter", p.m_BpfFilter},
        {"promiscuous", p.m_PromiscuousMode}
    };

    // clang-format on
}
/**
 * @brief from_json
 * @param j
 * @param p
 */
[[maybe_unused]] static void from_json(const nlohmann::json &j, JsonObjectPcap &p) {
    ///\warning execeptions if field name is mising
    Utility::Json::tryGetValue(j, "device", p.m_Device);
    Utility::Json::tryGetValue(j, "filter", p.m_BpfFilter);
    Utility::Json::tryGetValue(j, "promiscuous", p.m_PromiscuousMode);
}
} // namespace Nta::Json::Objects
