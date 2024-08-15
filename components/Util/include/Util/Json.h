#pragma once

#include <nlohmann/json.hpp>

namespace Nta::Util::Json {
template <typename ValueType> auto GetTo(const std::string &name, const nlohmann::json &j) noexcept -> ValueType {
    ValueType v{};
    return j.contains(name) ? j.at(name).get_to(v) : v;
}

template <typename ValueType>
static inline void GetTo(const nlohmann::json &j, const std::string &name, ValueType &value) noexcept {
    value = j.contains(name) ? j.at(name).get_to(value) : value;
}
} // namespace Nta::Util::Json
