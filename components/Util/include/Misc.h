#pragma once

#include <stdexcept>

namespace Poco::Util {
class Application;
}

namespace Nta::Util::Misc {

template <class Application> auto ApplicationCast(Poco::Util::Application *app) -> Application * {
    auto AppPtr = dynamic_cast<Application *>(app);
    if (!AppPtr)
        throw std::runtime_error("The application has not been derrived from Util::Application! Cast failed!");
    return AppPtr;
}

} // namespace Nta::Util::Misc
