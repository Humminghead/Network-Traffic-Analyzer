#include "Filesystem.h"

#include <fstream>

std::vector<char> Nta::Util::Filesystem::ReadBinaryFile(const std::filesystem::path &path) noexcept {
    std::ifstream stream(path.c_str(), std::ios::binary);

    return std::vector<char>((std::istreambuf_iterator<char>(stream)),
                             std::istreambuf_iterator<char>());
}

auto Nta::Util::Filesystem::IsValidJsonPath(const std::filesystem::path &p) -> std::filesystem::path {
    if (p.empty())
        throw std::runtime_error("Empty config path!");

    if (p.extension() != ".json")
        throw std::runtime_error(std::string{"Unknown config extension: "} + std::string{p.extension()});

    if (!std::filesystem::exists(p))
        throw std::runtime_error(std::string{"The path doesn't exist: "} + p.string());

    return p;
}
