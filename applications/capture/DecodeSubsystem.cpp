#include "DecodeSubsystem.h"

#include "CaptureSubsystem.h"
#include "Misc.h"
#include "Common/HandlerIface.h"
#include "packetbase.h"
#include <Poco/Util/Application.h>
#include <cctype>
#include <decoder.h>

namespace Nta::Network {
const char *DecodeSubsystem::name() const {
    return "capture";
}

struct DecodeSubsystem::Impl {
    std::unique_ptr<Nta::Network::NetDecoder> m_Decoder{nullptr};
};

DecodeSubsystem::DecodeSubsystem()
    : m_Pimpl{std::unique_ptr<Impl, void (*)(Impl *)>(new DecodeSubsystem::Impl, [](auto p) { delete p; })} {}

void DecodeSubsystem::initialize(Poco::Util::Application &app) {
    m_Pimpl->m_Decoder = std::make_unique<Nta::Network::NetDecoder>();
    auto& subsystem = app.getSubsystem<CaptureSubsystem>();
    subsystem.GetHandler()->SetCallback([&](const struct timeval, const uint8_t *d, const size_t s){
        size_t tSz{s};
        auto [ok,packet] = m_Pimpl->m_Decoder->FullProcessing(0,d,tSz);

        return false;
    });
}

void DecodeSubsystem::uninitialize() {
    m_Pimpl->m_Decoder.reset(nullptr);
}
} // namespace Nta::Network
