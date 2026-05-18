#pragma once

#include <cstdint>

namespace protocols
{
struct IpAssemblerStat {
    virtual ~IpAssemblerStat() = default;

    uint64_t assembled_messages = 0;
    uint64_t assembled_fragments = 0;
    uint64_t assembling_failed = 0;

    uint64_t cache_empty = 0;
    uint64_t cache_allocated = 0;
    uint64_t failure_buffer_oversize = 0;
    uint64_t failure_fragments_overlaps = 0;
    uint64_t failure_unexpected_end = 0;
    uint64_t failure_holes_oversize = 0;

    uint64_t drop_messages = 0;
    uint64_t drop_fragments = 0;

    void reset() { *this = {}; };
};

}  // namespace protocols
