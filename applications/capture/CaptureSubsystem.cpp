#include "CaptureSubsystem.h"
#include "ConfigureSubsystem.h"
#include "Handlers/Common/HandlerIface.h"
#include "Handlers/Pcap/HandlerPcap.h"
#include "Handlers/Pcap/JsonObjectPcap.h"
#include "Util/Misc.h"
#include <algorithm>
#include <cctype>

namespace Nta::Network {

struct CaptureSubsystem::Impl {
    std::string m_SubSystemName{"capture"};
    HandlerPtr m_Handler{nullptr};
    const ConfigureSubsystem *m_ConfigureSubsystem{nullptr};
};

const char *CaptureSubsystem::name() const {
    return "capture";
}

CaptureSubsystem::HandlerPtr CaptureSubsystem::GetHandler() const {
    return m_Pimpl->m_Handler;
}

void CaptureSubsystem::SetHandler(HandlerPtr p) {
    m_Pimpl->m_Handler = std::move(p);
}

CaptureSubsystem::CaptureSubsystem(const ConfigureSubsystem *cSubSys)
    : m_Pimpl{std::unique_ptr<Impl, void (*)(Impl *)>(new CaptureSubsystem::Impl, [](auto p) { delete p; })} {
    m_Pimpl->m_ConfigureSubsystem = cSubSys;
}

void CaptureSubsystem::initialize(Poco::Util::Application &app) {
    if (!m_Pimpl->m_ConfigureSubsystem)
        throw std::runtime_error("ConfigureSubsystem wasn't set in " + m_Pimpl->m_SubSystemName + " subsustem!");

    auto config = Nta::Util::Json::GetTo<Nta::Json::Objects::JsonObjectPcap>(
        "handler", m_Pimpl->m_ConfigureSubsystem->GetRawJsonConfig());

    std::string tempType{};
    std::transform(std::begin(config.m_Type), std::end(config.m_Type), std::back_inserter(tempType), [](const auto &c) {
        return std::tolower(c);
    });

    if (tempType == "pcap") {
        m_Pimpl->m_Handler = std::make_shared<Nta::Network::HandlerPcap>(config);
    } else if (tempType.empty()) {
        throw std::runtime_error("Empty device type string in config!");
    } else {
        throw std::runtime_error("Unsupported device type \"" + tempType + "\"!");
    }
}

void CaptureSubsystem::uninitialize() {
    m_Pimpl->m_Handler.reset();
}
} // namespace Nta::Network
