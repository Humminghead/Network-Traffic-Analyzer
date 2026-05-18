#pragma once

#include <string_view>

namespace Nta::Network {
std::string_view GetDpdkErrorMessage(const int err);
}
