#include "CaptureSubsystem.h"
#include "CaptureApp.h"
#include "ConfigureSubsystem.h"
#include "Handlers/Common/HandlerIface.h"
#include "Handlers/Pcap/HandlerPcap.h"
#include "Handlers/Pcap/JsonObjectPcap.h"
#include "Util/Misc.h"
#include <algorithm>
#include <cctype>
#include <decoder.h>

namespace Nta::Network {

struct CaptureSubsystem::Impl {
    std::shared_ptr<Nta::Network::HandlerAbstract> m_Handler{nullptr};
};

const char *CaptureSubsystem::name() const {
    return "capture";
}

CaptureSubsystem::HandlerPtr CaptureSubsystem::GetHandler() {
    return m_Pimpl->m_Handler;
}

CaptureSubsystem::CaptureSubsystem()
    : m_Pimpl{std::unique_ptr<Impl, void (*)(Impl *)>(new CaptureSubsystem::Impl, [](auto p) { delete p; })} {}

void CaptureSubsystem::initialize(Poco::Util::Application &app) {
    auto &subsustem = Nta::Util::Misc::ApplicationCast<CaptureApp>(&app)->getSubsystem<ConfigureSubsystem>();

    auto config = Nta::Util::Json::GetTo<Nta::Json::Objects::JsonObjectPcap>("handler", subsustem.GetRawJsonConfig());

    {
        std::string type{};
        std::transform(std::begin(config.m_Type), std::end(config.m_Type), std::back_inserter(type), [](const auto &c) {
            return std::tolower(c);
        });

        if (type == "pcap") {
            m_Pimpl->m_Handler = std::make_unique<Nta::Network::HandlerPcap>(config);
        } else {
            throw std::runtime_error("Unsupported device type \"" + type + "\"!");
        }
    }
}

void CaptureSubsystem::uninitialize() {
    m_Pimpl->m_Handler.reset();
}
} // namespace Nta::Network
