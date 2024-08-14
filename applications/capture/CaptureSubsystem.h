#pragma once

#include <Poco/Util/Subsystem.h>
#include <memory>
// #include <vector>

namespace Nta::Network {
struct HandlerAbstract;
}

class CaptureSubsystem : public Poco::Util::Subsystem {
public:
    using HandlerPtr = std::shared_ptr<Nta::Network::HandlerAbstract>;

    const char *name() const override;

    CaptureSubsystem();

protected:
    void initialize(Poco::Util::Application &app) override;
    void uninitialize() override;

private:
    class Impl;
    std::unique_ptr<Impl, void (*)(Impl *)> m_Pimpl;
};
