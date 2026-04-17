#pragma once

namespace Nta::Network::Device {
class AbstractDevice {
  protected:
    AbstractDevice() = default;

  public:
    virtual ~AbstractDevice() = default;

    virtual void Open() = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const = 0;
};

template <typename... Product> class AbstractDeviceFactory : public Product... {
  public:
    virtual ~AbstractDeviceFactory() = default;
};

}; // namespace Nta::Network::Device
