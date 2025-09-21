#pragma once
#include <string>
#include <cstdint>

class FirewallRules
{
public:
    struct Params
    {
        std::string table_name   = "flowforge_client";
        std::string chain_name   = "egress";
        std::string tun_ifname;              // "cvpn0"
        std::string server_ip;               // IPv4 или [IPv6]
        std::uint16_t server_port = 0;
        bool allow_udp = true;
        bool allow_tcp = true;
        int  hook_priority = 0;

        // Bootstrap исключения
        bool allow_dhcp          = true;     // oif "<wan>" udp 68->67
        bool allow_icmp          = true;     // icmp/icmpv6
    };

public:
    explicit FirewallRules(const Params &params);
    ~FirewallRules();

    FirewallRules(const FirewallRules&)            = delete;
    FirewallRules& operator=(const FirewallRules&) = delete;
    FirewallRules(FirewallRules&& other) noexcept;
    FirewallRules& operator=(FirewallRules&& other) noexcept;

    void Apply();
    void Revert();

private:
    void CreateCtx_();
    void DestroyCtx_();
    bool RunCmd_(const std::string &cmd, bool ignore_error = false);
    static std::string NormalizeIp_(std::string ip);
    static bool IsIPv6Literal_(const std::string &s);
    static std::string DetectWanIfname_();

private:
    struct nft_ctx* ctx_ = nullptr;
    Params          p_;
    bool            applied_ = false;
};
