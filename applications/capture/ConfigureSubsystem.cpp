#include "ConfigureSubsystem.h"
#include "CaptureApp.h"
#include "Util/Filesystem.h"
#include "Util/Misc.h"
#include "Util/Json.h"

namespace Nta::Network {
const char *ConfigureSubsystem::name() const {
    return "configure";
}

void ConfigureSubsystem::initialize(Poco::Util::Application &app) {
    auto p = Nta::Util::Misc::ApplicationCast<CaptureApp>(&app);

    m_JsonCfg = nlohmann::json{}.parse(Nta::Util::Filesystem::ReadBinaryFile(p->GetConfigPath()), nullptr, true, true);
}

void ConfigureSubsystem::uninitialize() {
    m_JsonCfg.clear();
}

template<>
auto ConfigureSubsystem::GetAppCore<int>(int&& defaultValue) const -> int {
        return Util::Json::GetTo<int>("app_core", this->GetRawJsonConfig(), std::move(defaultValue));
}

} // namespace Nta::Network
