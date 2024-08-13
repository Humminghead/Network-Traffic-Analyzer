#pragma once

#include <NwaNetworkHandlerBase.h>
#include <ip/NwaIpVersion.h>
#include <ip/NwaIpHandlerResult.h>

namespace Nta::Network {

struct Ip4 {};
struct Ip6 {};

template <typename Ip> class IpHandler;
} // namespace Nta::Network

#include <ip/NwaIp4Handler.h>
#include <ip/NwaIp6Handler.h>
