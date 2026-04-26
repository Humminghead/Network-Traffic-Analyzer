#pragma once

#include <memory>
#include <mutex>
#include <vector>

namespace Nta::Network {

namespace Device {

class DpdkEal {
    auto EalInit(const std::vector<const char *> &params) -> bool;

    static std::shared_ptr<DpdkEal> m_instance;
    bool m_isInited{false};

  protected:
    DpdkEal(const std::vector<const char *> &params) { m_isInited = EalInit(params); }

  public:
    DpdkEal() = delete;

    DpdkEal(DpdkEal &) = delete;
    DpdkEal &operator=(DpdkEal &) = delete;

    DpdkEal(const DpdkEal &) = delete;
    DpdkEal &operator=(const DpdkEal &) = delete;

    DpdkEal(DpdkEal &&) = delete;
    DpdkEal &operator=(DpdkEal &&) = delete;

    static auto GetInstance(const std::vector<const char *> &params) {
        static std::once_flag flag;
        std::call_once(flag, [&params] {
            if (!m_instance) {
                m_instance = std::shared_ptr<DpdkEal>(new DpdkEal(params));
            }
        });
        return m_instance;
    }

    auto isInited() const { return m_isInited; }
};

} // namespace Device
} // namespace Nta::Network
