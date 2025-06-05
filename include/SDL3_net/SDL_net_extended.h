#pragma once

#include "SDL3_net/SDL_net.h"

typedef enum NETEx_ResolveAddressFlags
{
    NETEx_Any,
    NETEx_IPv4,
    NETEx_IPv6,
} NETEx_ResolveAddressFlags;

extern SDL_DECLSPEC NET_Address *NETEx_ResolveHostname(const char *host, NETEx_ResolveAddressFlags flags);
