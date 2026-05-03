#pragma once

#include <cstdint>
#include <vector>

///\todo Move it in separate header
struct rte_mbuf;
namespace Nta::Network {
using MbufArray = std::vector<rte_mbuf *>;
}

namespace Nta::Network::Device {
class AbstractDevice {
  protected:
    AbstractDevice() = default;

  public:
    virtual ~AbstractDevice() = default;

    AbstractDevice &operator=(AbstractDevice &&) = default;
    AbstractDevice(AbstractDevice &&) = default;

    AbstractDevice &operator=(const AbstractDevice &) = delete;
    AbstractDevice(const AbstractDevice &) = delete;

    virtual void SetupRxQueue(const uint16_t queueId) = 0;
    virtual void SetupTxQueue(const uint16_t queueId) = 0;
    virtual void Open() = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;
    virtual uint16_t SendPackets(const uint16_t queueId, MbufArray &bufArray, const uint16_t nbPkts) = 0;
    virtual uint16_t RecivePackets(const uint16_t queueId, MbufArray &m_BufArray) = 0;
};

template <typename... Product> class AbstractDeviceFactory : public Product... {
  public:
    virtual ~AbstractDeviceFactory() = default;
};

}; // namespace Nta::Network::Device
