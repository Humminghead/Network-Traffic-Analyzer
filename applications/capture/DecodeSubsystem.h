#pragma once

#include <NetDecoder/LinkLayer.h>
#include <Poco/Util/Subsystem.h>
#include <memory>

namespace Nta::Network {
struct HandlerAbstract;
class CaptureSubsystem;
class ConfigureSubsystem;
} // namespace Nta::Network

namespace Nta::Network {
class DecodeSubsystem : public Poco::Util::Subsystem {
  public:
    using HandlerPtr = std::shared_ptr<HandlerAbstract>;

    DecodeSubsystem(const ConfigureSubsystem *cSubSys);

    bool Decode(const struct timeval time, const uint8_t *d, const size_t s);
    void SetLinkedSubSystem(CaptureSubsystem *);
    void SetLinkLayer(const LinkLayer &layer);

    const char *name() const override;

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    class Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Pimpl;
};
} // namespace Nta::Network
