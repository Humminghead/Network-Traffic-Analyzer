#include "Util/Misc.h"
#include <array>
#include <cstring> //strerror_r
#include <string>
#include <thread>

void Nta::Util::Thread::Stick2Core(const int id) {
    std::array<char, 128> errorBuffer;

    if (auto cores = std::thread::hardware_concurrency(); cores == 0)
        throw std::runtime_error("Can't get the number of concurrent threads supported by the implementation!");
    else if (id >= cores)
        throw std::runtime_error("Core with id " + std::to_string(id) + " is out of bounds");

    ///\todo OS selection
    /// https://www.baeldung.com/linux/cmake-cross-platform-compilation
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(id, &cpuset);
    auto current_thread = pthread_self();
    if (auto error = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset); error)
        throw std::runtime_error(
            "Error: " + std::string{strerror_r(error, errorBuffer.data(), errorBuffer.size())} +
            "Can't limit specified thread TH to run only on core  " + std::to_string(id));
}
