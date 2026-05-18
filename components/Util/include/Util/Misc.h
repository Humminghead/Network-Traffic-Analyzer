#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

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

namespace PosixSignal {

// -----------------------------------------------------------------------------
// Storage – holds the registered callbacks and provides safe access
// -----------------------------------------------------------------------------
class Storage {
  public:
    using func_t = std::function<int(int)>;

    /*!
     * \brief * Add for one or more callables (function pointers, lambdas, etc.)
     * \param callable object
     */
    template <typename... F, std::enable_if_t<(std::is_invocable_r_v<int, F, int> && ...), int> = 0>
    void Add(F &&...f) {
        std::lock_guard<std::mutex> lock(m_mutex);
        (m_funcs.push_back(func_t(std::forward<F>(f))), ...);
    }

    /*!
     * \brief Call all stored callbacks (not signal‑safe – only called from Process)
     * \param signal
     */
    void CallAll(int signal) {
        if (auto lock = std::unique_lock<decltype(m_mutex)>(m_mutex, std::try_to_lock); !lock) {
            return;
        } else {
            for (auto &f : m_funcs) {
                if (f)
                    f(signal); // return value ignored
            }
        }
    }

  private:
    std::vector<func_t> m_funcs;
    std::mutex m_mutex;
};

// -----------------------------------------------------------------------------
// Global state (process‑wide) – an atomic flag and a pointer to the storage
// -----------------------------------------------------------------------------
namespace Detail {
inline std::atomic<int> g_PendingSignal{0};
inline std::atomic<int> g_TerminateFlag{0};
inline std::unique_ptr<Storage> g_Storage; // process‑wide, not thread‑local
inline std::mutex g_StorageMutex;          // protects creation of g_storage
} // namespace Detail

// Add one or more callbacks to the global storage.
// Safe to call from multiple threads before or after setting up the signal handler.
template <typename... F> void AddHandler(F &&...f) {
    // Lazy initialisation of the global storage – mutex‑protected.
    std::lock_guard<std::mutex> lock(Detail::g_StorageMutex);

    if (!Detail::g_Storage) {
        Detail::g_Storage = std::make_unique<Storage>();
    }

    Detail::g_Storage->Add(std::forward<F>(f)...);
}

// Signal handler – async‑signal‑safe because it only writes to an atomic.
// Install it with std::signal() or sigaction().
inline void AsyncHandler(int signal) {
    Detail::g_PendingSignal.store(signal, std::memory_order_relaxed);
}

// Call this from your main loop (normal context) to process any pending signals.
// Returns true if a signal was processed, false otherwise.
inline bool AsyncProcess() {
    int sig = Detail::g_PendingSignal.exchange(0, std::memory_order_relaxed);

    if (sig == 0)
        return false;

    if (Detail::g_Storage) {
        Detail::g_Storage->CallAll(sig);
    }
    return true;
}

// Wait for the moment when the signal will be caught
inline auto AsyncWait() {
    while (!Detail::g_TerminateFlag && !AsyncProcess()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Process any signal that arrived before termination
    while (AsyncProcess()) {
    }
}

inline auto Terminate(){
    Detail::g_TerminateFlag.store(1);
}

} // namespace PosixSignal

} // namespace Nta::Util
