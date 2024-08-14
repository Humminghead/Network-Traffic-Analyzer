#include "CaptureSubsystem.h"
#include "CaptureApp.h"
#include "Common/HandlerIface.h"
#include "Common/JsonObjectHandler.h"
#include "ConfigureSubsystem.h"
#include "Misc.h"
#include "Pcap/HandlerPcap.h"
#include "Pcap/JsonObjectPcap.h"

const char *CaptureSubsystem::name() const {
    return "capture";
}

struct CaptureSubsystem::Impl {
    std::unique_ptr<Nta::Network::HandlerAbstract> m_Handler{nullptr};
};

CaptureSubsystem::CaptureSubsystem()
    : m_Pimpl{std::unique_ptr<Impl, void (*)(Impl *)>(new CaptureSubsystem::Impl, [](auto p) { delete p; })} {}

void CaptureSubsystem::initialize(Poco::Util::Application &app) {
    auto &subsustem = Nta::Util::Misc::ApplicationCast<CaptureApp>(&app)->getSubsystem<ConfigureSubsystem>();

    auto config = Nta::Util::Json::GetTo<Nta::Json::Objects::JsonObjectPcap>("handler", subsustem.GetRawJsonConfig());

    if(config.m_Type == "pcap")

    printf("c_Init\n");
}

void CaptureSubsystem::uninitialize() {
    printf("c_UnInit\n");
}
