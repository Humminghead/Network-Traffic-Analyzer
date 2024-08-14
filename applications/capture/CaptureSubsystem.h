#pragma once

#include <Poco/Util/Subsystem.h>
#include <memory>

namespace Nta::Network {
struct HandlerAbstract;
}

namespace Nta::Network {
class CaptureSubsystem : public Poco::Util::Subsystem {
  public:
    using HandlerPtr = std::shared_ptr<Nta::Network::HandlerAbstract>;

    CaptureSubsystem();    

    const char *name() const override;
    HandlerPtr GetHandler();

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    class Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Pimpl;
};
} // namespace Nta::Network
