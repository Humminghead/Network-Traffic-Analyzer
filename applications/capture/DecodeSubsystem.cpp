#include "DecodeSubsystem.h"

#include "CaptureSubsystem.h"
#include "Handlers/Common/HandlerIface.h"
#include "Util/Misc.h"
#include "NetDecoder/packetbase.h"
#include <Poco/Util/Application.h>
#include <cctype>
#include <NetDecoder/decoder.h>

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
    auto &capture = app.getSubsystem<CaptureSubsystem>();
    capture.GetHandler()->SetCallback([&](const struct timeval, const uint8_t *d, const size_t s) {
        size_t tSz{s};
        auto [ok, packet] = m_Pimpl->m_Decoder->FullProcessing(LinkLayer::Eth, d, tSz);

        return false;
    });
}

void DecodeSubsystem::uninitialize() {
    m_Pimpl->m_Decoder.reset(nullptr);
}
} // namespace Nta::Network
