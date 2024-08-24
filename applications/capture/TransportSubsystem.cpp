#include "TransportSubsystem.h"
#include "ConfigureSubsystem.h"
// #include <

namespace Nta::Network {

class TransportSubsystem::Impl {};

TransportSubsystem::ImplPointer::~ImplPointer() {}

TransportSubsystem::TransportSubsystem(const ConfigureSubsystem *cSubSys) : m_Pimpl{std::make_unique<Impl>()} {}

const char *TransportSubsystem::name() const {
    return "";
}

bool TransportSubsystem::Send(Result && result){
    return false;
}

void TransportSubsystem::initialize(Poco::Util::Application &app) {}

void TransportSubsystem::uninitialize() {}
} // namespace Nta::Network
