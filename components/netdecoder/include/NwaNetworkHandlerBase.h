#pragma once

#include <memory>

namespace Nwa::Network {

template <class Tp> using Result = std::pair<bool, std::unique_ptr<Tp>>;

template <class Tp> class HandlerBase {
  public:
    virtual ~HandlerBase() = default;

    virtual Result<Tp> Handle(const uint8_t *, size_t) const = 0;
};
} // namespace Nwa::Network
