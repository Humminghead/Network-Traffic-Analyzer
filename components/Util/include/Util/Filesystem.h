#pragma once

#include <filesystem>
#include <vector>

namespace Nta::Util::Filesystem {
[[maybe_unused]] auto ReadBinaryFile(const std::filesystem::path &path) noexcept -> std::vector<char>;
[[maybe_unused]] auto IsValidJsonPath(const std::filesystem::path &p) -> std::filesystem::path;
} // namespace Nta::Util::Filesystem
