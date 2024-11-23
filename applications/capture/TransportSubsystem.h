#pragma once

#include <NetDecoder/Result.h>
#include <Poco/Util/Subsystem.h>
#include <memory>

namespace apache::thrift {
class TConfiguration;
}

namespace Nta::Json::Objects {
struct JsonObjectTransport;
}

namespace Nta::Network {
class ConfigureSubsystem;
} // namespace Nta::Network

namespace Nta::Network {

struct TransportSubsystemBase : public Poco::Util::Subsystem {
    virtual bool Send(Result &&result) = 0;
};

class TransportSubsystem : public TransportSubsystemBase {
  public:
    TransportSubsystem(const ConfigureSubsystem *cSubSys);
    ~TransportSubsystem();

    TransportSubsystem(const TransportSubsystem&) = delete;
    TransportSubsystem &operator=(const TransportSubsystem &) = delete;

    const char *name() const override;

    bool Send(Result &&result) override;

  protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

  private:
    void InitializeTransport(const Json::Objects::JsonObjectTransport &, std::shared_ptr<apache::thrift::TConfiguration>);
    void InitializeBuffer(const Json::Objects::JsonObjectTransport &, std::shared_ptr<apache::thrift::TConfiguration>);
    void InitializeProtocol(const Json::Objects::JsonObjectTransport &, std::shared_ptr<apache::thrift::TConfiguration>);

  private:
    class Impl;
    class ImplPointer : public std::unique_ptr<Impl> {
      public:
        ~ImplPointer();
    } m_Pimpl;
};
} // namespace Nta::Network
