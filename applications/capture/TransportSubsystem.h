#pragma once

#include <Poco/Util/Subsystem.h>
#include <memory>
#include <NetDecoder/Result.h>

namespace Nta::Network {
class ConfigureSubsystem;
} // namespace Nta::Network

namespace Nta::Network {
class TransportSubsystem : public Poco::Util::Subsystem {
  public:
    TransportSubsystem(const ConfigureSubsystem *cSubSys);

    const char *name() const override;

    bool Send(Result&&result);

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    class Impl;
    class ImplPointer : public std::unique_ptr<Impl> {
      public:
        ~ImplPointer();
    } m_Pimpl;
};
} // namespace Nta::Network
