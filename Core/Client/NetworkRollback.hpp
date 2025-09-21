#pragma once

// NetworkRollback — Linux
// RAII-откат сетевых правок, внесённых Network::ConfigureNetwork.
// Можно создавать ДО появления TUN: если интерфейса нет — это не ошибка.
// Откат делает:
//  - удаляет host-route до server_ip (/32 или /128) — не зависит от TUN;
//  - удаляет split-default 0.0.0.0/1 и 128.0.0.0/1 (или ::/1 и 8000::/1) через TUN — если TUN существует;
//  - по желанию удаляет адреса на TUN — если TUN существует.
//
// Зависимости: libnl-3, libnl-route-3. Никаких внешних утилит.

#include <string>

class NetworkRollback
{
public:
    struct Params
    {
        std::string tun_ifname;     // напр., "cvpn0" (может отсутствовать на момент Arm)
        std::string server_ip;      // IPv4 или IPv6 (можно в [..])
        bool revert_v4   = true;
        bool revert_v6   = true;
        bool flush_addrs = true;
    };

    NetworkRollback() = default;
    explicit NetworkRollback(const Params& p);

    ~NetworkRollback();

    NetworkRollback(const NetworkRollback&)            = delete;
    NetworkRollback& operator=(const NetworkRollback&) = delete;

    void Arm(const Params& p);   // можно вызывать до появления TUN
    void Revert();               // идемпотентно
    void Disarm();               // отключить откат

private:
    // утилиты
    static bool        IsIPv6Literal_(const std::string& s);
    static std::string StripBrackets_(const std::string& s);

    void RevertFamily_(int family);
    void DelSplitDefaultsViaTun_(int family, int curr_ifindex);
    void DelHostRouteToServer_(int family);
    void FlushAddrsOnTun_(int family, int curr_ifindex);

    int  IfIndex_() const;  // if_nametoindex(p_.tun_ifname); может вернуть 0 — интерфейса ещё нет

private:
    Params p_{};
    bool   armed_{false};
};
