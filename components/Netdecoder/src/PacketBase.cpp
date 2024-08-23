#include "NetDecoder/PacketBase.h"

#include <algorithm>
#include <netinet/ip.h>
#include <netinet/ip6.h>

namespace Nta::Network {

void Packet::Reset() {    
    ethHeader = nullptr;
    pppoeHeader = nullptr;
    std::for_each(std::begin(vlansTags), std::end(vlansTags), [](auto *&p) { p = nullptr; });
    std::for_each(std::begin(mplsLabels), std::end(mplsLabels), [](auto *&p) { p = nullptr; });
    ip4Header = nullptr;
    ip6Header = nullptr;
    ip6Fragment = nullptr;
    udpHeader = nullptr;
    icmpHeader = nullptr;
    gtpHeader = nullptr;
    sctpHeader = nullptr;
}

void Packet::ResetLowerLevels() {
    tcpHeader = nullptr;
    sctpHeader = nullptr;
    gtpHeader = nullptr;
}

} // namespace Nta::Network
