#pragma once

#include <filesystem>
#include <vector>

namespace Nta::Util::Filesystem {
[[maybe_unused]] auto ReadBinaryFile(const std::filesystem::path &path) noexcept -> std::vector<char>;
} // namespace Nta::Util::Filesystem
