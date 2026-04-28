#pragma once

#include <nlohmann/json.hpp>

namespace Nta::Util::Json {
template <typename ValueType> auto GetTo(const std::string &name, const nlohmann::json &j) noexcept -> ValueType {
    ValueType v{};
    return j.contains(name) ? j.at(name).get_to(v) : v;
}

template <typename ValueType> auto GetTo(const std::string &name, const nlohmann::json &j, ValueType &&defaultValue) noexcept -> ValueType {
    ValueType v{};
    return j.contains(name) ? j.at(name).get_to(v) : std::move(defaultValue);
}
///\todo swap j and name
template <typename ValueType>
static inline void GetTo(const nlohmann::json &j, const std::string &name, ValueType &value) noexcept {
    value = j.contains(name) ? j.at(name).get_to(value) : value;
}

template <typename ValueType, typename Predicate>
static inline void GetTo(const nlohmann::json &j, const std::string &name, ValueType &value, Predicate pred) noexcept {
    value = j.contains(name) ? pred(j, name, value) : value;
}
} // namespace Nta::Util::Json
