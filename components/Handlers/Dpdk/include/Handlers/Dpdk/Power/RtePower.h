#pragma once

#include <cstdint>
#include <stdexcept>

namespace Nta::Network::Power {

struct PowerManagment {

protected:
    virtual void Enable_virt(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) = 0;
    virtual void Disable_virt(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) = 0;
    virtual bool Idle_virt(const size_t nbPkts) = 0;

  public:
    virtual ~PowerManagment() = default;

    void Enable(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) {
        return Enable_virt(portId, queueId, lcore);
    }
    void Disable(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) {
        return Disable_virt(portId, queueId, lcore);
    };
    bool Idle(const size_t nbPkts) { return Idle_virt(nbPkts); };
};

struct PowerManagmentDefaults : public PowerManagment {
  public:
    void Enable(const uint16_t, const uint16_t, const unsigned int) {
        throw std::runtime_error("this power managment policy does not supported.");
    }

    void Disable(const uint16_t, const uint16_t, const unsigned int) { throw std::runtime_error("this power managment policy does not supported."); }

    bool Idle(const size_t) { throw std::runtime_error("this power managment policy does not supported."); }
};

template <class Mode> struct PowerManagmentVirt : public PowerManagmentDefaults {
  public:
    void Enable_virt(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) override {
        return static_cast<Mode *>(this)->Enable(portId, queueId, lcore);
    }

    void Disable_virt(const uint16_t portId, const uint16_t queueId, const unsigned int lcore) override {
        return static_cast<Mode *>(this)->Disable(portId, queueId, lcore);
    }

    bool Idle_virt(const size_t nbPkts) override { return static_cast<Mode *>(this)->Idle(nbPkts); }
};

} // namespace Nta::Network::Power
