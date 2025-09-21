#include "NetworkRollback.hpp"
#include "Core/Logger.hpp"

#include <arpa/inet.h>
#include <net/if.h>

#include <string>
#include <cstring>
#include <stdexcept>
#include <functional>

#include <netlink/netlink.h>
#include <netlink/errno.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

namespace
{
    constexpr int FAM_V4 = AF_INET;
    constexpr int FAM_V6 = AF_INET6;

    struct SplitPiece { const char* cidr; int prefix; };
    const SplitPiece SPLIT_V4[2] = { { "0.0.0.0", 1 }, { "128.0.0.0", 1 } };
    const SplitPiece SPLIT_V6[2] = { { "::", 1 },       { "8000::",   1 } };

    // Локальный RAII для libnl-сокета
    struct NlSock
    {
        nl_sock* sk{nullptr};
        NlSock()
        {
            sk = nl_socket_alloc();
            if (!sk) throw std::runtime_error("nl_socket_alloc failed");
            const int rc = nl_connect(sk, NETLINK_ROUTE);
            if (rc < 0)
            {
                std::string msg = std::string("nl_connect: ") + nl_geterror(rc);
                nl_socket_free(sk); sk = nullptr;
                throw std::runtime_error(msg);
            }
        }
        ~NlSock() { if (sk) nl_socket_free(sk); }
        NlSock(const NlSock&) = delete;
        NlSock& operator=(const NlSock&) = delete;
    };

    // Обход таблицы маршрутов (MAIN) с фильтром по семейству
    void ForEachRoute_(int family, const std::function<bool(struct rtnl_route*)>& fn)
    {
        NlSock nl;
        nl_cache* rcache = nullptr;
        const int rc = rtnl_route_alloc_cache(nl.sk, family, 0, &rcache);
        if (rc < 0)
            throw std::runtime_error(std::string("rtnl_route_alloc_cache: ") + nl_geterror(rc));

        for (rtnl_route* r = (rtnl_route*)nl_cache_get_first(rcache);
             r;
             r = (rtnl_route*)nl_cache_get_next((nl_object*)r))
        {
            if (fn(r)) break;
        }

        nl_cache_free(rcache);
    }

    // Обход адресов
    void ForEachAddr_(int family, const std::function<bool(struct rtnl_addr*)>& fn)
    {
        NlSock nl;
        nl_cache* acache = nullptr;
        const int rc = rtnl_addr_alloc_cache(nl.sk, &acache);
        if (rc < 0)
            throw std::runtime_error(std::string("rtnl_addr_alloc_cache: ") + nl_geterror(rc));

        for (rtnl_addr* a = (rtnl_addr*)nl_cache_get_first(acache);
             a;
             a = (rtnl_addr*)nl_cache_get_next((nl_object*)a))
        {
            if (rtnl_addr_get_family(a) != family) continue;
            if (fn(a)) break;
        }

        nl_cache_free(acache);
    }
} // namespace

// -------- util --------

bool NetworkRollback::IsIPv6Literal_(const std::string& s)
{
    return s.find(':') != std::string::npos;
}

std::string NetworkRollback::StripBrackets_(const std::string& s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        return s.substr(1, s.size()-2);
    return s;
}

int NetworkRollback::IfIndex_() const
{
    if (p_.tun_ifname.empty()) return 0;
    unsigned idx = if_nametoindex(p_.tun_ifname.c_str());
    return static_cast<int>(idx); // 0 — интерфейса нет (это ок)
}

// -------- public --------

NetworkRollback::NetworkRollback(const Params& p)
{
    Arm(p);
}

NetworkRollback::~NetworkRollback()
{
    try { Revert(); } catch (...) {}
}

void NetworkRollback::Arm(const Params& p)
{
    p_ = p;
    if (p_.tun_ifname.empty())
        LOGD("network") << "Rollback armed: tun_ifname is empty (skip TUN-specific cleanup)";
    else
        LOGD("network") << "Rollback armed for if=" << p_.tun_ifname;

    armed_ = true;
}

void NetworkRollback::Disarm()
{
    armed_ = false;
    LOGD("network") << "Rollback disarmed";
}

void NetworkRollback::Revert()
{
    if (!armed_) return;

    try { if (p_.revert_v4) RevertFamily_(FAM_V4); }
    catch (const std::exception& e) { LOGW("network") << "Rollback IPv4 failed: " << e.what(); }

    try { if (p_.revert_v6) RevertFamily_(FAM_V6); }
    catch (const std::exception& e) { LOGW("network") << "Rollback IPv6 failed: " << e.what(); }

    armed_ = false;
    LOGI("network") << "Network rollback done";
}

// -------- core --------

void NetworkRollback::RevertFamily_(int family)
{
    const int curr_ifindex = IfIndex_();

    // 1) удалить split-default /1 через TUN (только если TUN существует)
    if (curr_ifindex > 0)
        DelSplitDefaultsViaTun_(family, curr_ifindex);

    // 2) удалить host-route до server_ip (не зависит от TUN)
    DelHostRouteToServer_(family);

    // 3) удалить адреса на TUN (если просили и TUN существует)
    if (p_.flush_addrs && curr_ifindex > 0)
        FlushAddrsOnTun_(family, curr_ifindex);
}

void NetworkRollback::DelSplitDefaultsViaTun_(int family, int curr_ifindex)
{
    const SplitPiece* pieces = (family == FAM_V4) ? SPLIT_V4 : SPLIT_V6;

    ForEachRoute_(family, [&](rtnl_route* r) -> bool
    {
        nl_addr* dst = rtnl_route_get_dst(r);
        if (!dst) return false;
        if (static_cast<int>(nl_addr_get_prefixlen(dst)) != pieces[0].prefix) return false;

        char buf[INET6_ADDRSTRLEN] = {};
        nl_addr2str(dst, buf, sizeof(buf));

        const bool is_split = (std::strcmp(buf, pieces[0].cidr) == 0) ||
                              (std::strcmp(buf, pieces[1].cidr) == 0);
        if (!is_split) return false;

        rtnl_nexthop* nh = rtnl_route_nexthop_n(r, 0);
        if (!nh) return false;
        if (rtnl_route_nh_get_ifindex(nh) != curr_ifindex) return false;

        NlSock nl;
        const int rc = rtnl_route_delete(nl.sk, r, 0);
        if (rc < 0)
            LOGD("network") << "Del split /1 failed: " << nl_geterror(rc) << " dst=" << buf;
        else
            LOGI("network") << "Del split /1: " << buf << "/" << pieces[0].prefix << " via " << p_.tun_ifname;

        return false;
    });
}

void NetworkRollback::DelHostRouteToServer_(int family)
{
    const std::string ip = StripBrackets_(p_.server_ip);
    if (ip.empty()) return;
    if ((family == FAM_V4 && IsIPv6Literal_(ip)) ||
        (family == FAM_V6 && !IsIPv6Literal_(ip)))
        return;

    ForEachRoute_(family, [&](rtnl_route* r) -> bool
    {
        nl_addr* dst = rtnl_route_get_dst(r);
        if (!dst) return false;

        const int need_pl = (family == FAM_V4) ? 32 : 128;
        if (static_cast<int>(nl_addr_get_prefixlen(dst)) != need_pl) return false;

        char buf[INET6_ADDRSTRLEN] = {};
        nl_addr2str(dst, buf, sizeof(buf));
        if (ip != buf) return false;

        NlSock nl;
        const int rc = rtnl_route_delete(nl.sk, r, 0);
        if (rc < 0)
            LOGD("network") << "Del host route failed: " << nl_geterror(rc) << " dst=" << buf;
        else
            LOGI("network") << "Del host route to server: " << buf;

        return false;
    });
}

void NetworkRollback::FlushAddrsOnTun_(int family, int curr_ifindex)
{
    ForEachAddr_(family, [&](rtnl_addr* a) -> bool
    {
        if (rtnl_addr_get_ifindex(a) != curr_ifindex) return false;

        NlSock nl;
        const int rc = rtnl_addr_delete(nl.sk, a, 0);
        if (rc < 0)
        {
            LOGD("network") << "Addr delete failed: " << nl_geterror(rc);
        }
        else
        {
            char buf[INET6_ADDRSTRLEN] = {};
            if (auto* local = rtnl_addr_get_local(a))
                nl_addr2str(local, buf, sizeof(buf));
            LOGI("network") << "Addr deleted on " << p_.tun_ifname << ": " << buf;
        }
        return false;
    });
}
