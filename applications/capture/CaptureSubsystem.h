#pragma once

#include <Poco/Util/Subsystem.h>
#include <memory>

namespace Nta::Network {
struct HandlerAbstract;
class ConfigureSubsystem;
} // namespace Nta::Network

namespace Nta::Network {
class CaptureSubsystem : public Poco::Util::Subsystem {
  public:
    using HandlerPtr = std::shared_ptr<Nta::Network::HandlerAbstract>;

    CaptureSubsystem(const ConfigureSubsystem *cSubSys);

    auto name() const -> const char * override;
    auto GetHandler() const -> HandlerPtr;
    auto SetHandler(HandlerPtr p) -> void;

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    class Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Pimpl;
};
} // namespace Nta::Network
