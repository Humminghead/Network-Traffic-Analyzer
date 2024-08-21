#include "DecodeSubsystem.h"

#include "CaptureSubsystem.h"
#include "Handlers/Common/HandlerIface.h"
#include "NetDecoder/PacketBase.h"
#include "Util/Misc.h"
#include <NetDecoder/Decoder.h>
#include <Poco/Util/Application.h>
#include <cctype>

namespace Nta::Network {

struct DecodeSubsystem::Impl {
    std::string m_SubSystemName{"decode"};
    std::unique_ptr<Nta::Network::NetDecoder> m_Decoder{nullptr};
    LinkLayer m_LinkLayer{LinkLayer::Eth};
    const ConfigureSubsystem *m_ConfigureSubsystem{nullptr};
    CaptureSubsystem *m_LinkedSubsystem{nullptr};
};

const char *DecodeSubsystem::name() const {
    return m_Pimpl->m_SubSystemName.c_str();
}

DecodeSubsystem::DecodeSubsystem(const ConfigureSubsystem *cSubSys)
    : m_Pimpl{std::unique_ptr<Impl, void (*)(Impl *)>(new DecodeSubsystem::Impl, [](auto p) { delete p; })} {
    m_Pimpl->m_ConfigureSubsystem = cSubSys;
}

void DecodeSubsystem::initialize(Poco::Util::Application &app) {
    if (!m_Pimpl->m_ConfigureSubsystem)
        throw std::runtime_error("ConfigureSubsystem wasn't set in " + m_Pimpl->m_SubSystemName + " subsustem!");

    if (!m_Pimpl->m_LinkedSubsystem)
        throw std::runtime_error("DecodeSubsystem wasn't linked with " + m_Pimpl->m_SubSystemName + " subsustem!");

    m_Pimpl->m_Decoder = std::make_unique<Nta::Network::NetDecoder>();
    m_Pimpl->m_LinkedSubsystem->GetHandler()->SetCallback(
        std::bind(&DecodeSubsystem::Decode, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
}

void DecodeSubsystem::uninitialize() {
    m_Pimpl->m_Decoder.reset(nullptr);
}

bool DecodeSubsystem::Decode(const struct timeval, const uint8_t *d, const size_t s) {
    size_t tSz{s};
    auto [ok, packet] = m_Pimpl->m_Decoder->FullProcessing(m_Pimpl->m_LinkLayer, d, tSz);
    return ok;
}

void DecodeSubsystem::SetLinkedSubSystem(CaptureSubsystem *s) {
    m_Pimpl->m_LinkedSubsystem = s;
}

void DecodeSubsystem::SetLinkLayer(const LinkLayer &layer) {
    m_Pimpl->m_LinkLayer = static_cast<LinkLayer>(layer);
}

} // namespace Nta::Network
