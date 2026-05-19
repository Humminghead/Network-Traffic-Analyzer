#pragma once

#include "Handlers/Dpdk/Acl/Classification/Tuple5.h"
#include "Handlers/Dpdk/Acl/LookupAcl.h"

namespace Nta::Network::Rules {

template<typename Tuple, typename Defs>
struct UnifiedTuple
{
    using tuple_type = Tuple;
    using tuple_defs_type = Defs;


    constexpr inline auto DefsSize() const {
        return sizeof(Defs);
    }
};

using Tuple5 = UnifiedTuple<FiveTupleIp4, decltype(FiveTupleIp4Defs)>;
}