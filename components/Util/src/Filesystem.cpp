#include "Filesystem.h"

#include <fstream>

std::vector<char> Nta::Util::Filesystem::ReadBinaryFile(const std::filesystem::path &path) noexcept {
    std::ifstream stream(path.c_str(), std::ios::binary);

    // std::vector<char> vec;

    // if (stream.is_open()) {
    //     stream.seekg(0, std::ios::end);
    //     auto size = stream.tellg();
    //     stream.seekg(0, std::ios::beg);

    //     vec.resize(size);
    //     stream.read((char *)vec.data(), size);

    //     return vec;
    // }

    // return vec;

    return std::vector<char>((std::istreambuf_iterator<char>(stream)),
                             std::istreambuf_iterator<char>());
}
