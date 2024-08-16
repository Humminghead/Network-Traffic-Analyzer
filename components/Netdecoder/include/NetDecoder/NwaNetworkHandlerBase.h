#pragma once

#include <memory>

namespace Nta::Network {

template <class Tp> using Result = std::pair<bool, std::unique_ptr<Tp>>;

template <class Tp> class HandlerBase {
  public:
    virtual ~HandlerBase() = default;

    virtual Result<Tp> Handle(const uint8_t *,const size_t&) const = 0;
};
} // namespace Nta::Network
