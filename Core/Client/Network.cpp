#include "Network.hpp"
#include "Core/Logger.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/errno.h>      // NLE_* codes
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

#include <cstring>
#include <string>
#include <optional>
#include <stdexcept>
#include <algorithm>

namespace
{
    // -------- Helpers: ioctl --------
    int IfSetUp(const std::string &ifname)
    {
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0)
        {
            return -errno;
        }

        ifreq ifr{};
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());

        if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
        {
            int e = -errno;
            ::close(s);
            return e;
        }

        ifr.ifr_flags |= IFF_UP;

        if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
        {
            int e = -errno;
            ::close(s);
            return e;
        }

        ::close(s);
        return 0;
    }

    int IfSetMtu(const std::string &ifname, int mtu)
    {
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0)
        {
            return -errno;
        }

        ifreq ifr{};
        std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());
        ifr.ifr_mtu = mtu;

        if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
        {
            int e = -errno;
            ::close(s);
            return e;
        }

        ::close(s);
        return 0;
    }

    // -------- RAII for libnl socket --------
    struct NlSock
    {
        nl_sock *sk {nullptr};

        NlSock()
        {
            sk = nl_socket_alloc();
            if (!sk)
            {
                throw std::runtime_error("nl_socket_alloc failed");
            }
            int err = nl_connect(sk, NETLINK_ROUTE);
            if (err < 0)
            {
                std::string msg = std::string("nl_connect: ") + nl_geterror(err);
                nl_socket_free(sk);
                sk = nullptr;
                throw std::runtime_error(msg);
            }
        }

        ~NlSock()
        {
            if (sk) nl_socket_free(sk);
        }

        NlSock(const NlSock&) = delete;
        NlSock& operator=(const NlSock&) = delete;
    };

    // -------- addr helpers --------
    void FlushAddrs(nl_sock *sk, int ifindex, int family)
    {
        nl_cache *ac = nullptr;
        int err = rtnl_addr_alloc_cache(sk, &ac);
        if (err < 0)
        {
            throw std::runtime_error(std::string("rtnl_addr_alloc_cache: ") + nl_geterror(err));
        }

        for (rtnl_addr *a = (rtnl_addr *)nl_cache_get_first(ac);
             a;
             a = (rtnl_addr *)nl_cache_get_next((nl_object *)a))
        {
            if (rtnl_addr_get_ifindex(a) != ifindex) continue;
            if (rtnl_addr_get_family(a)  != family)  continue;

            int del_err = rtnl_addr_delete(sk, a, 0);
            if (del_err < 0)
            {
                LOGW("network") << "rtnl_addr_delete: " << nl_geterror(del_err);
            }
        }

        nl_cache_free(ac);
    }

    void AddAddrP2P(nl_sock *sk, int ifindex, int family,
                    const std::string &local_str, int prefix,
                    const std::string &peer_str)
    {
        nl_addr *local = nullptr;
        nl_addr *peer  = nullptr;

        int err = nl_addr_parse(local_str.c_str(), family, &local);
        if (err < 0)
        {
            throw std::runtime_error(std::string("nl_addr_parse(local): ") + nl_geterror(err));
        }
        nl_addr_set_prefixlen(local, prefix);

        err = nl_addr_parse(peer_str.c_str(), family, &peer);
        if (err < 0)
        {
            nl_addr_put(local);
            throw std::runtime_error(std::string("nl_addr_parse(peer): ") + nl_geterror(err));
        }

        rtnl_addr *a = rtnl_addr_alloc();
        rtnl_addr_set_ifindex(a, ifindex);
        rtnl_addr_set_family(a, family);
        rtnl_addr_set_local(a, local);
        rtnl_addr_set_peer(a,  peer);
        if (family == AF_INET6)
        {
            rtnl_addr_set_flags(a, IFA_F_NODAD | IFA_F_NOPREFIXROUTE);
        }

        err = rtnl_addr_add(sk, a, 0);
        if (err < 0 && err != -NLE_EXIST)
        {
            rtnl_addr_put(a);
            nl_addr_put(local);
            nl_addr_put(peer);
            throw std::runtime_error(std::string("rtnl_addr_add: ") + nl_geterror(err));
        }

        rtnl_addr_put(a);
        nl_addr_put(local);
        nl_addr_put(peer);

        if (err == -NLE_EXIST)
        {
            LOGD("network") << "Address already present (idempotent)";
        }
    }

    // -------- route helpers --------
    struct GwInfo
    {
        int ifindex {};
        std::string gw_text;
    };

    std::optional<int> GetDefaultMetric(nl_sock *sk, int family)
    {
        nl_cache *rcache = nullptr;
        int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
        if (err < 0)
        {
            throw std::runtime_error(std::string("rtnl_route_alloc_cache: ") + nl_geterror(err));
        }

        int metric = 0x7fffffff;
        bool found = false;

        for (rtnl_route *r = (rtnl_route *)nl_cache_get_first(rcache);
             r;
             r = (rtnl_route *)nl_cache_get_next((nl_object *)r))
        {
            nl_addr *dst = rtnl_route_get_dst(r);
            if (!dst) continue;
            if (nl_addr_get_family(dst) != family) continue;
            if (nl_addr_get_prefixlen(dst) != 0)   continue;

            found = true;
            int prio = rtnl_route_get_priority(r);
            if (prio < metric) metric = prio;
        }

        nl_cache_free(rcache);
        if (!found) return std::nullopt;
        return metric;
    }

    std::optional<GwInfo> FindDefaultGw(nl_sock *sk, int family)
    {
        nl_cache *rcache = nullptr;
        int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
        if (err < 0)
        {
            throw std::runtime_error(std::string("rtnl_route_alloc_cache: ") + nl_geterror(err));
        }

        std::optional<GwInfo> res;

        for (rtnl_route *r = (rtnl_route *)nl_cache_get_first(rcache);
             r;
             r = (rtnl_route *)nl_cache_get_next((nl_object *)r))
        {
            nl_addr *dst = rtnl_route_get_dst(r);
            if (!dst) continue;
            if (nl_addr_get_family(dst) != family) continue;
            if (nl_addr_get_prefixlen(dst) != 0)   continue;

            rtnl_nexthop *nh = rtnl_route_nexthop_n(r, 0);
            if (!nh) continue;
            nl_addr *gw = rtnl_route_nh_get_gateway(nh);
            if (!gw) continue;

            char buf[INET6_ADDRSTRLEN] = {};
            nl_addr2str(gw, buf, sizeof(buf));
            res = GwInfo{ rtnl_route_nh_get_ifindex(nh), std::string(buf) };
            break;
        }

        nl_cache_free(rcache);
        return res;
    }

    void AddHostRouteViaGw(nl_sock *sk, int family,
                           const std::string &host_ip,
                           const GwInfo &gw)
    {
        nl_addr *dst = nullptr;
        int err = nl_addr_parse(host_ip.c_str(), family, &dst);
        if (err < 0)
        {
            throw std::runtime_error(std::string("nl_addr_parse(dst): ") + nl_geterror(err));
        }
        nl_addr_set_prefixlen(dst, (family == AF_INET) ? 32 : 128);

        nl_addr *gwaddr = nullptr;
        err = nl_addr_parse(gw.gw_text.c_str(), family, &gwaddr);
        if (err < 0)
        {
            nl_addr_put(dst);
            throw std::runtime_error(std::string("nl_addr_parse(gw): ") + nl_geterror(err));
        }

        rtnl_route *route = rtnl_route_alloc();
        rtnl_route_set_family(route, family);
        rtnl_route_set_table(route, RT_TABLE_MAIN);
        rtnl_route_set_dst(route, dst);
        rtnl_route_set_type(route, RTN_UNICAST);
        rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
        rtnl_route_set_protocol(route, RTPROT_STATIC);

        rtnl_nexthop *nh = rtnl_route_nh_alloc();
        rtnl_route_nh_set_ifindex(nh, gw.ifindex);
        rtnl_route_nh_set_gateway(nh, gwaddr);
        rtnl_route_add_nexthop(route, nh);

        int prio = 5;
        if (auto cur = GetDefaultMetric(sk, family))
        {
            prio = std::max(0, *cur - 10);
        }
        rtnl_route_set_priority(route, prio);

        int err2 = rtnl_route_add(sk, route, 0);
        if (err2 < 0 && err2 != -NLE_EXIST)
        {
            std::string msg = std::string("rtnl_route_add(host via gw): ") + nl_geterror(err2);
            rtnl_route_put(route);
            nl_addr_put(dst);
            nl_addr_put(gwaddr);
            throw std::runtime_error(msg);
        }

        if (err2 == -NLE_EXIST)
        {
            LOGD("network") << "Host route already exists (idempotent)";
        }
        else
        {
            LOGI("network") << "Pinned /" << ((family == AF_INET) ? 32 : 128)
                            << " to server via gw";
        }

        rtnl_route_put(route);
        nl_addr_put(dst);
        nl_addr_put(gwaddr);
    }

    void AddSplitDefaultViaDev(nl_sock *sk, int family, int oif)
    {
        struct Piece { const char *cidr; int prefix; };

        Piece pieces_v4[2] = { { "0.0.0.0", 1 }, { "128.0.0.0", 1 } };
        Piece pieces_v6[2] = { { "::", 1 },        { "8000::",   1 } };

        const Piece *pieces = (family == AF_INET) ? pieces_v4 : pieces_v6;

        int prio = 5;
        if (auto cur = GetDefaultMetric(sk, family))
        {
            prio = std::max(0, *cur - 10);
        }

        for (int i = 0; i < 2; ++i)
        {
            nl_addr *dst = nullptr;
            int err = nl_addr_parse(pieces[i].cidr, family, &dst);
            if (err < 0)
            {
                throw std::runtime_error(std::string("nl_addr_parse(/1): ") + nl_geterror(err));
            }
            nl_addr_set_prefixlen(dst, pieces[i].prefix);

            rtnl_route *route = rtnl_route_alloc();
            rtnl_route_set_family(route, family);
            rtnl_route_set_table(route, RT_TABLE_MAIN);
            rtnl_route_set_dst(route, dst);
            rtnl_route_set_type(route, RTN_UNICAST);
            rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
            rtnl_route_set_protocol(route, RTPROT_STATIC);
            rtnl_route_set_priority(route, prio);

            rtnl_nexthop *nh = rtnl_route_nh_alloc();
            rtnl_route_nh_set_ifindex(nh, oif);
            rtnl_route_add_nexthop(route, nh);

            int err2 = rtnl_route_add(sk, route, 0);
            if (err2 < 0 && err2 != -NLE_EXIST)
            {
                std::string msg = std::string("rtnl_route_add(/1 via dev): ") + nl_geterror(err2);
                rtnl_route_put(route);
                nl_addr_put(dst);
                throw std::runtime_error(msg);
            }

            if (err2 == -NLE_EXIST)
            {
                LOGD("network") << "Split piece already exists: " << pieces[i].cidr << "/" << pieces[i].prefix;
            }
            else
            {
                LOGI("network") << "Added split piece: " << pieces[i].cidr << "/" << pieces[i].prefix;
            }

            rtnl_route_put(route);
            nl_addr_put(dst);
        }
    }

    void WriteProcIfSysctl(const std::string &ifname,
                           const char *key,
                           const char *value)
    {
        char path[256];
        std::snprintf(path, sizeof(path),
                      "/proc/sys/net/ipv6/conf/%s/%s",
                      ifname.c_str(), key);
        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return;
        (void) ::write(fd, value, std::strlen(value));
        ::close(fd);
    }

    bool IsIPv6Literal(const std::string &s)
    {
        return s.find(':') != std::string::npos;
    }
} // anonymous namespace

namespace Network
{
    void SetParams(const Params& p)
    {
        g_params = p;
        LOGD("network") << "Params set: mtu=" << g_params.mtu
                        << " local4=" << g_params.local4 << " peer4=" << g_params.peer4
                        << " local6=" << g_params.local6 << " peer6=" << g_params.peer6;
    }


void ConfigureNetwork(const std::string &ifname,
                          const std::string &server_ip,
                          IpVersion family)
    {
        LOGD("network") << "ConfigureNetwork(if=" << ifname
                        << ", server=" << server_ip
                        << ", family=" << (family == IpVersion::V4 ? "IPv4" : "IPv6") << ")";

        if (int rc = IfSetUp(ifname); rc != 0)
        {
            throw std::runtime_error("IfSetUp(" + ifname + "): " + std::string(std::strerror(-rc)));
        }
        int desired_mtu = g_params.mtu > 0 ? g_params.mtu : 1400;
        if (int rc = IfSetMtu(ifname, desired_mtu); rc != 0)
        {
            LOGW("network") << "IfSetMtu(" << ifname << "," << desired_mtu
                            << "): " << std::strerror(-rc) << " (ignored)";

        }

        if (family == IpVersion::V6)
        {
            WriteProcIfSysctl(ifname, "accept_ra",    "0\n");
            WriteProcIfSysctl(ifname, "autoconf",     "0\n");
            WriteProcIfSysctl(ifname, "disable_ipv6", "0\n");
        }

        NlSock nl;
        int ifindex = if_nametoindex(ifname.c_str());
        if (!ifindex)
        {
            throw std::runtime_error("if_nametoindex(" + ifname + ") failed");
        }

        if (family == IpVersion::V4)
        {
            FlushAddrs(nl.sk, ifindex, AF_INET);
            try
            {
                AddAddrP2P(nl.sk, ifindex, AF_INET, g_params.local4, 32, g_params.peer4);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(std::string("IPv4 address apply failed: ") + e.what());
            }
        }
        else
        {
            FlushAddrs(nl.sk, ifindex, AF_INET6);
            try
            {
                AddAddrP2P(nl.sk, ifindex, AF_INET6, g_params.local6, 128, g_params.peer6);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(std::string("IPv6 address apply failed: ") + e.what());
            }
        }

        const int fam = (family == IpVersion::V4) ? AF_INET : AF_INET6;

        auto gw = FindDefaultGw(nl.sk, fam);
        if (!gw)
        {
            // Для IPv6 это частая ситуация на v4-only сетях — понизим уровень до warning
            if (family == IpVersion::V6)
            {
                LOGW("network") << "Default gateway not found for IPv6 — skipping v6 pin/split";
                return;
            }
            throw std::runtime_error("default gateway not found for family");
        }
        LOGD("network") << "Default gw: ifindex=" << gw->ifindex << " gw=" << gw->gw_text;

        if ((family == IpVersion::V6) != IsIPv6Literal(server_ip))
        {
            LOGW("network") << "Server IP family mismatch; skipping pin route";
        }
        else
        {
            // Идемпотентно: EXIST -> ок, продолжаем
            AddHostRouteViaGw(nl.sk, fam, server_ip, *gw);
        }

        // Идемпотентно добавляем split-default
        AddSplitDefaultViaDev(nl.sk, fam, ifindex);
        LOGI("network") << "Split-default installed via " << ifname;
    }
} // namespace Network

// Legacy wrapper (configure both families best-effort).
int ConfigureNetwork(const std::string &tun, const std::string &server_ip)
{
    try
    {
        Network::ConfigureNetwork(tun, server_ip, Network::IpVersion::V4);
    }
    catch (const std::exception &e)
    {
        LOGE("network") << "IPv4 configure failed: " << e.what();
    }

    try
    {
        Network::ConfigureNetwork(tun, server_ip, Network::IpVersion::V6);
    }
    catch (const std::exception &e)
    {
        LOGW("network") << "IPv6 configure failed: " << e.what();
    }

    return 0;
}
