#pragma once

#include <NetDecoder/NwaNetworkHandlerBase.h>
#include <NetDecoder/Ip/NwaIpHandlerResult.h>
#include <NetDecoder/Ip/NwaIpVersion.h>

namespace Nta::Network {

struct Ip4 {};
struct Ip6 {};

template <typename Ip> class IpHandler;
} // namespace Nta::Network

#include <NetDecoder/Ip/NwaIp4Handler.h>
#include <NetDecoder/Ip/NwaIp6Handler.h>
