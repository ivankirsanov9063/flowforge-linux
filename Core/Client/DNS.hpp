#pragma once
// DNS.hpp — Linux: RAII-настройка DNS.
// 1) systemd-resolved через sd-bus (если доступен);
// 2) крайний фолбэк — прямая запись /etc/resolv.conf с жёсткими проверками.
// Внешних утилит не вызываем.

#include <string>
#include <vector>

class DNS
{
public:
    struct Params
    {
        std::string ifname;                 // интерфейс (например, "cvpn0")
        std::vector<std::string> servers;   // IPv4/IPv6, можно c [..] для IPv6

        bool use_systemd           = true;  // пробовать org.freedesktop.resolve1
        bool make_default_route    = true;  // SetLinkDefaultRoute(true) + "~." domains
        bool resolv_conf_fallback  = true;  // разрешить fallback на /etc/resolv.conf (с предохранителями)
        std::string resolv_conf_path = "/etc/resolv.conf";
    };

public:
    explicit DNS(const Params &p);
    ~DNS();

    DNS(const DNS&)            = delete;
    DNS& operator=(const DNS&) = delete;
    DNS(DNS&&)                 = delete;
    DNS& operator=(DNS&&)      = delete;

    void Apply();   // идемпотентно/многоразово
    void Revert();  // откат

private:
    // ---- systemd-resolved ----
    bool Systemd_Available() const;
    bool Systemd_Apply();
    void Systemd_Revert();

    // ---- /etc/resolv.conf fallback ----
    bool Resolv_IsSafeToEdit() const; // не symlink на systemd/NM/openresolv + доступен для записи
    bool Resolv_Apply();
    void Resolv_Revert();

    static bool IsIPv6(const std::string &ip);
    static std::string StripBrackets(const std::string &s);
    static int  IfIndex(const std::string &ifname);

private:
    Params p_;
    int    ifindex_ = 0;

    // backup для resolv.conf
    bool        backup_done_ = false;
    std::string backup_path_;

    bool applied_          = false;
    bool applied_systemd_  = false;
    bool applied_resolv_   = false;
};
