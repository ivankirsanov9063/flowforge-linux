#pragma once

// Network.hpp — Linux implementation aligned with Windows interface.
// Provides Network::ConfigureNetwork(ifname, server_ip, IpVersion)
// and keeps a thin legacy wrapper ConfigureNetwork(tun, server_ip).

#include <string>
#include <stdexcept>

namespace Network
{
    enum class IpVersion
    {
        V4,
        V6
    };

    struct Params
    {
        std::string local4 = "10.200.0.2";
        std::string peer4  = "10.200.0.1";
        std::string local6 = "fd00:dead:beef::2";
        std::string peer6  = "fd00:dead:beef::1";
        int mtu = 1400;
    };

    static Params g_params{};

    // Установить параметры (должно быть вызвано до ConfigureNetwork)
    void SetParams(const Params& p);

    /**
     * @brief Configure per-family routing on Linux for a TUN device.
     *
     * Steps (per family):
     *  - Bring interface UP and set a safe MTU (if not already).
     *  - (Optional) assign point-to-point address on the TUN (private range).
     *  - Detect current default gateway (wan ifindex + gw address).
     *  - Pin a /32 (/128) host route to the VPN server via the WAN gateway.
     *  - Add split-default via the TUN device (two /1 routes for v4; ::/1 and 8000::/1 for v6)
     *    with a priority that wins over the existing default.
     *
     * Throws std::runtime_error on failures.
     */
    void ConfigureNetwork(const std::string &ifname,
                          const std::string &server_ip,
                          IpVersion family);
}

// --- Legacy wrapper kept for backward compatibility (will throw on failure) ---
int ConfigureNetwork(const std::string &tun, const std::string &server_ip);
