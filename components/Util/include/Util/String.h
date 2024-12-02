#pragma once

#include <charconv>
#include <optional>
#include <string_view>
#include <system_error>

namespace Nta::Util::String {

/*!
 * \brief Analyzes the character sequence and return int value
 * \param string with int value
 * \return int if conversion successful. Otherwise return std::nullopt
 */
#if __cplusplus >= 202100L
constexpr
#endif
auto ToInt(std::string_view s) -> std::optional<int>
{
    int value{};
#if __cpp_lib_to_chars >= 202306L
    if (std::from_chars(s.data(), s.data() + s.size(), value))
#else
    if (std::from_chars(s.data(), s.data() + s.size(), value).ec == std::errc{})
#endif
        return value;
    else
        return std::nullopt;
};

} // namespace Nta::Util::String
