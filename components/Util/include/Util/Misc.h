#pragma once

#include <stdexcept>

namespace Poco::Util {
class Application;
}

namespace Nta::Util {
namespace Misc {
template <class Application> auto ApplicationCast(Poco::Util::Application *app) -> Application * {
    auto AppPtr = dynamic_cast<Application *>(app);
    if (!AppPtr)
        throw std::runtime_error("The application has not been derrived from Util::Application! Cast failed!");
    return AppPtr;
}

} // namespace Misc
namespace Thread {
/*!
 * \brief Stick the current thread to the core with specified id
 * \param Core id
 */
void Stick2Core(const int id);
} // namespace Thread

namespace Std {
template <typename T, size_t... Is, typename... Args>
std::array<T, sizeof...(Is)> MakeArrayHelper(std::index_sequence<Is...>, Args &&...args) {
    return {(static_cast<void>(Is), T{std::forward<Args>(args)...})...};
}

template <typename T, size_t N, typename... Args> std::array<T, N> MakeArray(Args &&...args) {
    return MakeArrayHelper<T>(std::make_index_sequence<N>{}, std::forward<Args>(args)...);
}

template <typename> struct ArraySize;

template <typename T, size_t N> struct ArraySize<std::array<T, N>> {
    constexpr static auto size = N;
};

} // namespace Std

} // namespace Nta::Util
