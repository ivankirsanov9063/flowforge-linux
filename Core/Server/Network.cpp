#include "Network.hpp"
#include "Core/Logger.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstdio>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include <nftables/libnftables.h>

namespace NetConfig
{
    bool write_sysctl(const char *path,
                      const char *val)
    {
        LOGT("network") << "write_sysctl: path=" << path << " val=" << val;
        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
        {
            LOGE("network") << "write_sysctl: open failed path=" << path << " errno=" << errno;
            return false;
        }

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);

        const bool ok = (n == need);
        if (!ok)
        {
            LOGW("network") << "write_sysctl: short write path=" << path << " need=" << need << " wrote=" << n;
        }
        else
        {
            LOGD("network") << "write_sysctl: ok path=" << path;
        }
        return ok;
    }

    bool write_if_sysctl(const std::string &ifname,
                         const char        *key,
                         const char        *val)
    {
        char path[256];
        std::snprintf(path,
                      sizeof(path),
                      "/proc/sys/net/ipv6/conf/%s/%s",
                      ifname.c_str(),
                      key);

        LOGT("network") << "write_if_sysctl(v6): if=" << ifname << " key=" << key << " val=" << val;

        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
        {
            LOGE("network") << "write_if_sysctl(v6): open failed path=" << path << " errno=" << errno;
            return false;
        }

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);

        const bool ok = (n == need);
        if (!ok)
        {
            LOGW("network") << "write_if_sysctl(v6): short write path=" << path << " need=" << need << " wrote=" << n;
        }
        else
        {
            LOGD("network") << "write_if_sysctl(v6): ok path=" << path;
        }

        return ok;
    }

    // --- IPv4 per-interface sysctl: /proc/sys/net/ipv4/conf/<if>/<key>
    static bool write_if_sysctl_v4(const std::string &ifname,
                                   const char        *key,
                                   const char        *val)
    {
        char path[256];
        std::snprintf(path,
                      sizeof(path),
                      "/proc/sys/net/ipv4/conf/%s/%s",
                      ifname.c_str(),
                      key);

        LOGT("network") << "write_if_sysctl(v4): if=" << ifname << " key=" << key << " val=" << val;

        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
        {
            LOGE("network") << "write_if_sysctl(v4): open failed path=" << path << " errno=" << errno;
            return false;
        }

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);
        const bool ok = (n == need);
        if (!ok)
        {
            LOGW("network") << "write_if_sysctl(v4): short write path=" << path << " need=" << need << " wrote=" << n;
        }
        else
        {
            LOGD("network") << "write_if_sysctl(v4): ok path=" << path;
        }
        return ok;
    }

    nl_sock *nl_connect_route()
    {
        LOGD("network") << "nl_connect_route: creating NETLINK_ROUTE socket";
        nl_sock *sk = nl_socket_alloc();
        if (!sk)
        {
            LOGE("network") << "nl_connect_route: nl_socket_alloc failed";
            return nullptr;
        }

        if (nl_connect(sk, NETLINK_ROUTE) < 0)
        {
            LOGE("network") << "nl_connect_route: nl_connect failed";
            nl_socket_free(sk);
            return nullptr;
        }
        LOGD("network") << "nl_connect_route: connected";
        return sk;
    }

    bool link_set_up_and_mtu(nl_sock *sk,
                             int      ifindex,
                             int      mtu)
    {
        LOGD("network") << "link_set_up_and_mtu: ifindex=" << ifindex << " mtu=" << mtu;
        rtnl_link *link = rtnl_link_alloc();
        if (!link)
        {
            LOGE("network") << "link_set_up_and_mtu: rtnl_link_alloc failed";
            return false;
        }

        rtnl_link_set_ifindex(link, ifindex);
        rtnl_link_set_mtu(link, static_cast<unsigned int>(mtu));
        rtnl_link_set_flags(link, IFF_UP);

        const int rc = rtnl_link_change(sk, link, link, 0);
        rtnl_link_put(link);
        const bool ok = (rc == 0);
        if (!ok)
        {
            LOGE("network") << "link_set_up_and_mtu: rtnl_link_change rc=" << rc;
        }
        else
        {
            LOGI("network") << "link_set_up_and_mtu: interface up with MTU set";
        }
        return ok;
    }

    bool addr_add_v4_local(nl_sock     *sk,
                           int          ifindex,
                           std::uint32_t local_be,
                           std::uint8_t  prefix)
    {
        LOGD("network") << "addr_add_v4_local: ifindex=" << ifindex << " prefix=" << static_cast<int>(prefix);
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a)
        {
            LOGE("network") << "addr_add_v4_local: rtnl_addr_alloc failed";
            return false;
        }
        rtnl_addr_set_ifindex(a, ifindex);
        rtnl_addr_set_family(a, AF_INET);

        nl_addr *l = nl_addr_build(AF_INET, &local_be, sizeof(local_be));
        if (!l)
        {
            LOGE("network") << "addr_add_v4_local: nl_addr_build(local) failed";
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_prefixlen(a, prefix);

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        rtnl_addr_put(a);
        const bool ok = (rc == 0 || rc == -NLE_EXIST);
        if (!ok)
        {
            LOGE("network") << "addr_add_v4_local: rtnl_addr_add rc=" << rc;
        }
        else
        {
            LOGI("network") << "addr_add_v4_local: ok (rc=" << rc << ")";
        }
        return ok;
    }

    bool addr_flush_all(nl_sock *sk,
                        int      ifindex)
    {
        LOGD("network") << "addr_flush_all: ifindex=" << ifindex;
        nl_cache *cache = nullptr;
        if (rtnl_addr_alloc_cache(sk, &cache) < 0)
        {
            LOGE("network") << "addr_flush_all: rtnl_addr_alloc_cache failed";
            return false;
        }

        std::vector<rtnl_addr *> to_del;

        for (nl_object *it = nl_cache_get_first(cache);
             it;
             it = nl_cache_get_next(it))
        {
            auto *a = reinterpret_cast<rtnl_addr *>(it);
            if (rtnl_addr_get_ifindex(a) == ifindex)
            {
                nl_object_get(it);
                to_del.push_back(a);
            }
        }

        bool ok = true;
        size_t removed = 0;
        for (auto *a : to_del)
        {
            if (rtnl_addr_delete(sk, a, 0) < 0)
            {
                ok = false;
            }
            else
            {
                ++removed;
            }
            rtnl_addr_put(a);
        }

        nl_cache_free(cache);
        if (!ok)
        {
            LOGW("network") << "addr_flush_all: completed with errors, removed=" << removed;
        }
        else
        {
            LOGI("network") << "addr_flush_all: removed=" << removed;
        }
        return ok;
    }

    bool addr_add_v4_p2p(nl_sock     *sk,
                         int          ifindex,
                         std::uint32_t local_be,
                         std::uint32_t peer_be,
                         std::uint8_t  prefix)
    {
        LOGD("network") << "addr_add_v4_p2p: ifindex=" << ifindex << " prefix=" << static_cast<int>(prefix);
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a)
        {
            LOGE("network") << "addr_add_v4_p2p: rtnl_addr_alloc failed";
            return false;
        }
        rtnl_addr_set_ifindex(a, ifindex);

        nl_addr *l = nl_addr_build(AF_INET, &local_be, sizeof(local_be));
        nl_addr *p = nl_addr_build(AF_INET, &peer_be,  sizeof(peer_be));

        if (!l || !p)
        {
            if (!l) { LOGE("network") << "addr_add_v4_p2p: nl_addr_build(local) failed"; }
            if (!p) { LOGE("network") << "addr_add_v4_p2p: nl_addr_build(peer) failed"; }
            if (l) { nl_addr_put(l); }
            if (p) { nl_addr_put(p); }
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_peer(a,  p);
        rtnl_addr_set_prefixlen(a, prefix);

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        nl_addr_put(p);
        rtnl_addr_put(a);
        const bool ok = (rc == 0 || rc == -NLE_EXIST);
        if (!ok)
        {
            LOGE("network") << "addr_add_v4_p2p: rtnl_addr_add rc=" << rc;
        }
        else
        {
            LOGI("network") << "addr_add_v4_p2p: ok (rc=" << rc << ")";
        }
        return ok;
    }

    bool addr_add_v6_local(nl_sock                               *sk,
                           int                                    ifindex,
                           const std::array<std::uint8_t, 16>    &local,
                           std::uint8_t                          prefix)
    {
        LOGD("network") << "addr_add_v6_local: ifindex=" << ifindex << " prefix=" << static_cast<int>(prefix);
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a)
        {
            LOGE("network") << "addr_add_v6_local: rtnl_addr_alloc failed";
            return false;
        }
        rtnl_addr_set_ifindex(a, ifindex);

        nl_addr *l = nl_addr_build(AF_INET6, local.data(), 16);
        if (!l)
        {
            LOGE("network") << "addr_add_v6_local: nl_addr_build(local) failed";
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_prefixlen(a, prefix);
        rtnl_addr_set_flags(a, IFA_F_NODAD | IFA_F_NOPREFIXROUTE);

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        rtnl_addr_put(a);
        const bool ok = (rc == 0 || rc == -NLE_EXIST);
        if (!ok)
        {
            LOGE("network") << "addr_add_v6_local: rtnl_addr_add rc=" << rc;
        }
        else
        {
            LOGI("network") << "addr_add_v6_local: ok (rc=" << rc << ")";
        }
        return ok;
    }

    bool route_add_onlink_host_v6(nl_sock                              *sk,
                                  int                                   ifindex,
                                  const std::array<std::uint8_t, 16>   &dst128)
    {
        LOGD("network") << "route_add_onlink_host_v6: ifindex=" << ifindex;
        rtnl_route *r = rtnl_route_alloc();
        if (!r)
        {
            LOGE("network") << "route_add_onlink_host_v6: rtnl_route_alloc failed";
            return false;
        }

        rtnl_route_set_family(r, AF_INET6);
        rtnl_route_set_scope(r, RT_SCOPE_LINK);

        nl_addr *d = nl_addr_build(AF_INET6, dst128.data(), 16);
        if (!d)
        {
            LOGE("network") << "route_add_onlink_host_v6: nl_addr_build(dst) failed";
            rtnl_route_put(r);
            return false;
        }
        nl_addr_set_prefixlen(d, 128);
        rtnl_route_set_dst(r, d);

        rtnl_nexthop *nh = rtnl_route_nh_alloc();
        if (!nh)
        {
            LOGE("network") << "route_add_onlink_host_v6: rtnl_route_nh_alloc failed";
            nl_addr_put(d);
            rtnl_route_put(r);
            return false;
        }
        rtnl_route_nh_set_ifindex(nh, ifindex);
        rtnl_route_add_nexthop(r, nh);

        const int rc = rtnl_route_add(sk, r, 0);

        nl_addr_put(d);
        rtnl_route_put(r);
        const bool ok = (rc == 0 || rc == -NLE_EXIST);
        if (!ok)
        {
            LOGE("network") << "route_add_onlink_host_v6: rtnl_route_add rc=" << rc;
        }
        else
        {
            LOGI("network") << "route_add_onlink_host_v6: ok (rc=" << rc << ")";
        }
        return ok;
    }

    std::optional<std::string> find_default_oifname(nl_sock *sk,
                                                    int      family)
    {
        LOGT("network") << "find_default_oifname: family=" << family;
        nl_cache *rcache = nullptr;
        nl_cache *lcache = nullptr;

        if (rtnl_route_alloc_cache(sk, family, 0, &rcache) < 0)
        {
            LOGE("network") << "find_default_oifname: rtnl_route_alloc_cache failed";
            return std::nullopt;
        }
        if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &lcache) < 0)
        {
            LOGE("network") << "find_default_oifname: rtnl_link_alloc_cache failed";
            nl_cache_free(rcache);
            return std::nullopt;
        }

        int oif = 0;
        for (nl_object *it = nl_cache_get_first(rcache);
             it;
             it = nl_cache_get_next(it))
        {
            auto *r = reinterpret_cast<rtnl_route *>(it);
            nl_addr *dst = rtnl_route_get_dst(r);
            const bool is_default = (dst == nullptr) || (nl_addr_get_prefixlen(dst) == 0);
            if (!is_default)
            {
                continue;
            }
            if (rtnl_route_get_table(r) != RT_TABLE_MAIN)
            {
                continue;
            }

            const int nn = rtnl_route_get_nnexthops(r);
            if (nn > 0)
            {
                rtnl_nexthop *nh = rtnl_route_nexthop_n(r, 0);
                if (nh)
                {
                    oif = rtnl_route_nh_get_ifindex(nh);
                    if (oif > 0)
                    {
                        break;
                    }
                }
            }
        }

        std::string name;
        if (oif > 0)
        {
            rtnl_link *link = rtnl_link_get(lcache, oif);
            if (link)
            {
                name = rtnl_link_get_name(link);
                rtnl_link_put(link);
            }
        }

        nl_cache_free(rcache);
        nl_cache_free(lcache);
        if (name.empty())
        {
            LOGW("network") << "find_default_oifname: not found";
            return std::nullopt;
        }
        LOGD("network") << "find_default_oifname: oifname=" << name;
        return name;
    }

    bool nft_feature_probe()
    {
        LOGT("network") << "nft_feature_probe: probing nftables";
        nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
        if (!ctx)
        {
            LOGE("network") << "nft_feature_probe: nft_ctx_new failed";
            return false;
        }
        nft_ctx_buffer_output(ctx);
        nft_ctx_buffer_error(ctx);

        int rc = nft_run_cmd_from_buffer(ctx, "list tables");
        if (rc != 0)
        {
            (void) nft_run_cmd_from_buffer(ctx, "add table inet flowforge_probe");
            rc = nft_run_cmd_from_buffer(ctx, "delete table inet flowforge_probe");
        }

        nft_ctx_free(ctx);
        const bool ok = (rc == 0);
        if (!ok)
        {
            LOGW("network") << "nft_feature_probe: nftables not available";
        }
        else
        {
            LOGD("network") << "nft_feature_probe: nftables OK";
        }
        return ok;
    }

    bool nft_apply(const std::string &commands)
    {
        LOGT("network") << "nft_apply: begin (" << commands.size() << " bytes)";
        nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
        if (!ctx)
        {
            LOGE("network") << "nft_apply: nft_ctx_new failed";
            return false;
        }

        nft_ctx_buffer_output(ctx);
        nft_ctx_buffer_error(ctx);

        const int rc = nft_run_cmd_from_buffer(ctx, commands.c_str());
        if (rc != 0)
        {
            const char *err = nft_ctx_get_error_buffer(ctx);
            bool benign     = false;

            if (err)
            {
                std::string e = err;
                std::transform(e.begin(),
                               e.end(),
                               e.begin(),
                               [](unsigned char c)
                               {
                                   return static_cast<char>(std::tolower(c));
                               });

                if (e.find("exist") != std::string::npos ||
                    e.find("already") != std::string::npos)
                {
                    benign = true;
                }

                if (!benign && e.find("no such file or directory") != std::string::npos)
                {
                    std::string cmd_lower = commands;
                    std::transform(cmd_lower.begin(),
                                   cmd_lower.end(),
                                   cmd_lower.begin(),
                                   [](unsigned char c)
                                   {
                                       return static_cast<char>(std::tolower(c));
                                   });

                    if (cmd_lower.find("delete ") != std::string::npos ||
                        cmd_lower.find("flush chain") != std::string::npos)
                    {
                        benign = true;
                    }
                }
            }

            if (!benign)
            {
                LOGE("network") << "nft_apply: error rc=" << rc << " (see stderr dump)";
                LOGE("network") << "nft_apply: stderr: " << (err ? err : "(no error text)");
                LOGE("network") << "nft_apply: commands:\n" << commands;
            }
            else
            {
                LOGD("network") << "nft_apply: benign error rc=" << rc;
            }

            nft_ctx_free(ctx);
            return benign;
        }

        nft_ctx_free(ctx);
        LOGD("network") << "nft_apply: ok";
        return true;
    }

    bool ensure_nat44(const std::string &oifname,
                      const std::string &src_cidr)
    {
        LOGI("network") << "ensure_nat44: oif=" << oifname << " src=" << src_cidr;
        std::string cmd;
        cmd  = "add table ip flowforge_nat\n";
        cmd += "add chain ip flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd += "flush chain ip flowforge_nat postrouting\n";
        cmd += "add rule ip flowforge_nat postrouting "
               "ip saddr " + src_cidr + " "
               "oifname \"" + oifname + "\" "
               "counter masquerade "
               "comment \"flowforge:auto\"\n";
        const bool ok = nft_apply(cmd);
        if (!ok) { LOGE("network") << "ensure_nat44: nft_apply failed"; }
        return ok;
    }

    bool ensure_nat66(const std::string &oifname,
                      const std::string &src_cidr)
    {
        LOGI("network") << "ensure_nat66: oif=" << oifname << " src=" << src_cidr;
        std::string cmd;
        cmd  = "add table ip6 flowforge_nat\n";
        cmd += "add chain ip6 flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd += "flush chain ip6 flowforge_nat postrouting\n";
        cmd += "add rule ip6 flowforge_nat postrouting "
               "ip6 saddr " + src_cidr + " "
               "oifname \"" + oifname + "\" "
               "counter masquerade "
               "comment \"flowforge:auto\"\n";

        const bool ok = nft_apply(cmd);
        if (!ok) { LOGE("network") << "ensure_nat66: nft_apply failed"; }
        return ok;
    }

    // --- MSS clamp в postrouting (идемпотентно): inet/flowforge_post
    static bool ensure_mss_clamp(const std::optional<std::string> &wan4,
                                 const std::optional<std::string> &wan6,
                                 const Params                      &p)
    {
        LOGD("network") << "ensure_mss_clamp: begin wan4=" << (wan4 ? *wan4 : std::string("<none>"))
                        << " wan6=" << (wan6 ? *wan6 : std::string("<none>"));

        auto run = [](const std::string &cmd) -> bool
        {
            if (!nft_apply(cmd))
            {
                LOGW("network") << "ensure_mss_clamp: command failed";
                LOGW("network") << "ensure_mss_clamp: failed cmd: " << cmd;
                return false;
            }
            return true;
        };

        if (!run("add table inet flowforge_post\n"))
        {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n"))
            {
                LOGE("network") << "ensure_mss_clamp: table create failed";
                return false;
            }
        }
        if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n"))
        {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n"))
            {
                LOGE("network") << "ensure_mss_clamp: recreate table failed";
                return false;
            }
            if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n"))
            {
                LOGE("network") << "ensure_mss_clamp: create chain failed";
                return false;
            }
        }

        if (!run("flush chain inet flowforge_post postrouting\n"))
        {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n"))
            {
                LOGE("network") << "ensure_mss_clamp: flush/recreate table failed";
                return false;
            }
            if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n"))
            {
                LOGE("network") << "ensure_mss_clamp: flush/recreate chain failed";
                return false;
            }
        }

        std::string rules;
        if (wan4 && !p.nat44_src.empty())
        {
            rules += "add rule inet flowforge_post postrouting "
                     "ip saddr " + p.nat44_src + " "
                     "oifname \"" + *wan4 + "\" "
                     "tcp flags syn tcp option maxseg size set rt mtu "
                     "comment \"flowforge:mss\"\n";
        }
        if (wan6 && !p.nat66_src.empty())
        {
            rules += "add rule inet flowforge_post postrouting "
                     "ip6 saddr " + p.nat66_src + " "
                     "oifname \"" + *wan6 + "\" "
                     "tcp flags syn tcp option maxseg size set rt mtu "
                     "comment \"flowforge:mss6\"\n";
        }

        const bool ok = rules.empty() ? true : nft_apply(rules);
        if (!ok)
        {
            LOGW("network") << "ensure_mss_clamp: rules apply failed";
        }
        else
        {
            LOGD("network") << "ensure_mss_clamp: rules applied";
        }
        return ok;
    }

    // ---- Политики файрвола для TUN ----------------------------------------------------------
    bool ensure_fw_tun(const std::string &ifname,
                       const Params      &p)
    {
        LOGI("network") << "ensure_fw_tun: if=" << ifname;

        auto run = [](const std::string &cmd) -> bool
        {
            if (!nft_apply(cmd))
            {
                LOGW("network") << "ensure_fw_tun: command failed";
                LOGW("network") << "ensure_fw_tun: failed cmd: " << cmd;
                return false;
            }
            return true;
        };

        if (!run("add table inet flowforge_fw\n"))
        {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n"))
            {
                LOGE("network") << "ensure_fw_tun: create table failed";
                return false;
            }
        }
        if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n"))
        {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n"))
            {
                LOGE("network") << "ensure_fw_tun: recreate table failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: create input chain failed";
                return false;
            }
        }
        if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n"))
        {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n"))
            {
                LOGE("network") << "ensure_fw_tun: recreate table 2 failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: recreate input chain failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: create forward chain failed";
                return false;
            }
        }
        (void) nft_apply("add chain inet flowforge_fw tun_in\n");
        (void) nft_apply("add chain inet flowforge_fw tun_fwd\n");
        (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
        (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");

        if (!run("flush chain inet flowforge_fw tun_in\n"))
        {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate table failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate input failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate forward failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw tun_in\n"))
            {
                LOGE("network") << "ensure_fw_tun: create tun_in failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw tun_fwd\n"))
            {
                LOGE("network") << "ensure_fw_tun: create tun_fwd failed";
                return false;
            }
            (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
            (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");
        }
        if (!run("flush chain inet flowforge_fw tun_fwd\n"))
        {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate table 2 failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate input 2 failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n"))
            {
                LOGE("network") << "ensure_fw_tun: flush/recreate forward 2 failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw tun_in\n"))
            {
                LOGE("network") << "ensure_fw_tun: recreate tun_in failed";
                return false;
            }
            if (!run("add chain inet flowforge_fw tun_fwd\n"))
            {
                LOGE("network") << "ensure_fw_tun: recreate tun_fwd failed";
                return false;
            }
            (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
            (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");
        }

        const std::string net4 = to_network_cidr(p.v4_local);
        const std::string net6 = to_network_cidr(p.v6_local);

        if (!run("add rule inet flowforge_fw tun_in ct state invalid drop\n"))
        {
            LOGE("network") << "ensure_fw_tun: invalid drop rule failed";
            return false;
        }
        if (!run("add rule inet flowforge_fw tun_in ct state established,related accept\n"))
        {
            LOGE("network") << "ensure_fw_tun: established rule failed";
            return false;
        }
        if (p.v4_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_in ip saddr != " + net4 + " drop\n";
            if (!run(r))
            {
                LOGE("network") << "ensure_fw_tun: v4 saddr filter failed";
                return false;
            }
        }
        if (p.v6_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_in ip6 saddr != " + net6 + " drop\n";
            if (!run(r))
            {
                LOGE("network") << "ensure_fw_tun: v6 saddr filter failed";
                return false;
            }
        }
        (void) nft_apply(
            "add rule inet flowforge_fw tun_in meta l4proto icmp "
            "icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } "
            "limit rate 10/second accept\n");
        (void) nft_apply(
            "add rule inet flowforge_fw tun_in meta l4proto icmpv6 "
            "icmpv6 type { echo-request, packet-too-big, time-exceeded, parameter-problem, destination-unreachable } "
            "limit rate 10/second accept\n");
        if (!run("add rule inet flowforge_fw tun_in counter drop\n"))
        {
            LOGE("network") << "ensure_fw_tun: default drop failed";
            return false;
        }

        if (!run("add rule inet flowforge_fw tun_fwd ct state invalid drop\n"))
        {
            LOGE("network") << "ensure_fw_tun: fwd invalid drop failed";
            return false;
        }
        if (p.v4_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_fwd ip saddr != " + net4 + " drop\n";
            if (!run(r))
            {
                LOGE("network") << "ensure_fw_tun: fwd v4 saddr filter failed";
                return false;
            }
        }
        if (p.v6_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_fwd ip6 saddr != " + net6 + " drop\n";
            if (!run(r))
            {
                LOGE("network") << "ensure_fw_tun: fwd v6 saddr filter failed";
                return false;
            }
        }
        if (!run("add rule inet flowforge_fw tun_fwd ct state established,related accept\n"))
        {
            LOGE("network") << "ensure_fw_tun: fwd established rule failed";
            return false;
        }
        if (!run("add rule inet flowforge_fw tun_fwd accept\n"))
        {
            LOGE("network") << "ensure_fw_tun: fwd accept rule failed";
            return false;
        }

        LOGI("network") << "ensure_fw_tun: complete";
        return true;
    }

    // ---- CIDR parsing & normalization ---------------------------------------------------------
    bool parse_cidr4(const std::string &s,
                     CidrV4            &out)
    {
        LOGT("network") << "parse_cidr4: s=" << s;
        auto pos = s.find('/');
        std::string ip   = (pos == std::string::npos) ? s : s.substr(0, pos);
        int         pref = (pos == std::string::npos) ? 32 : std::stoi(s.substr(pos + 1));
        if (pref < 0 || pref > 32)
        {
            LOGE("network") << "parse_cidr4: prefix out of range pref=" << pref;
            return false;
        }

        in_addr ia{};
        if (inet_pton(AF_INET, ip.c_str(), &ia) != 1)
        {
            LOGE("network") << "parse_cidr4: inet_pton failed ip=" << ip;
            return false;
        }
        std::memcpy(&out.addr_be, &ia.s_addr, sizeof(out.addr_be));
        out.prefix = static_cast<std::uint8_t>(pref);
        LOGD("network") << "parse_cidr4: ok";
        return true;
    }

    bool parse_cidr6(const std::string &s,
                     CidrV6            &out)
    {
        LOGT("network") << "parse_cidr6: s=" << s;
        auto pos = s.find('/');
        std::string ip   = (pos == std::string::npos) ? s : s.substr(0, pos);
        int         pref = (pos == std::string::npos) ? 128 : std::stoi(s.substr(pos + 1));
        if (pref < 0 || pref > 128)
        {
            LOGE("network") << "parse_cidr6: prefix out of range pref=" << pref;
            return false;
        }

        in6_addr ia6{};
        if (inet_pton(AF_INET6, ip.c_str(), &ia6) != 1)
        {
            LOGE("network") << "parse_cidr6: inet_pton failed ip=" << ip;
            return false;
        }
        std::memcpy(out.addr.data(), &ia6, 16);
        out.prefix = static_cast<std::uint8_t>(pref);
        LOGD("network") << "parse_cidr6: ok";
        return true;
    }

    static void mask_ipv6(std::array<std::uint8_t, 16> &a,
                          int                           prefix)
    {
        if (prefix <= 0)
        {
            a.fill(0);
            return;
        }
        if (prefix >= 128)
        {
            return;
        }

        int full = prefix / 8;
        int part = prefix % 8;

        for (int i = full + 1; i < 16; ++i)
        {
            a[i] = 0;
        }

        if (part != 0)
        {
            std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8 - part));
            a[full] &= mask;
            for (int i = full + 1; i < 16; ++i)
            {
                a[i] = 0;
            }
        }
    }

    std::string to_network_cidr(const CidrV4 &c)
    {
        std::uint32_t be   = c.addr_be;
        std::uint32_t host = (c.prefix == 0) ? 0xFFFFFFFFu : (0xFFFFFFFFu >> c.prefix);
        std::uint32_t net_be = be & ~htonl(host);

        in_addr ia{};
        std::memcpy(&ia.s_addr, &net_be, sizeof(net_be));

        char buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &ia, buf, sizeof(buf));

        std::ostringstream oss;
        oss << buf << "/" << static_cast<int>(c.prefix);
        return oss.str();
    }

    std::string to_network_cidr(const CidrV6 &c)
    {
        auto bytes = c.addr;
        mask_ipv6(bytes, c.prefix);

        in6_addr ia6{};
        std::memcpy(&ia6, bytes.data(), 16);

        char buf[INET6_ADDRSTRLEN]{};
        inet_ntop(AF_INET6, &ia6, buf, sizeof(buf));

        std::ostringstream oss;
        oss << buf << "/" << static_cast<int>(c.prefix);
        return oss.str();
    }

    void ApplyServerSide(const std::string &ifname,
                         const Params      &p,
                         bool               with_nat_fw)
    {
        LOGI("network") << "ApplyServerSide: begin if=" << ifname
                        << " mtu=" << p.mtu
                        << " nat44_src=" << p.nat44_src
                        << " nat66_src=" << p.nat66_src
                        << " with_nat_fw=" << with_nat_fw;

        const int ifindex = static_cast<int>(if_nametoindex(ifname.c_str()));
        if (ifindex == 0)
        {
            LOGE("network") << "ApplyServerSide: if_nametoindex failed for " << ifname;
            throw std::runtime_error("if_nametoindex failed for " + ifname);
        }

        nl_sock *sk = nl_connect_route();
        if (!sk)
        {
            LOGE("network") << "ApplyServerSide: nl_connect NETLINK_ROUTE failed";
            throw std::runtime_error("nl_connect NETLINK_ROUTE failed");
        }

        if (!link_set_up_and_mtu(sk, ifindex, p.mtu))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: link_set_up_and_mtu failed";
            throw std::runtime_error("link_set_up_and_mtu failed for " + ifname);
        }

        if (!write_if_sysctl(ifname, "accept_ra", "0"))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: sysctl accept_ra=0 failed";
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".accept_ra=0 failed");
        }
        if (!write_if_sysctl(ifname, "autoconf", "0"))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: sysctl autoconf=0 failed";
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".autoconf=0 failed");
        }
        if (!write_if_sysctl(ifname, "disable_ipv6", "0"))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: sysctl disable_ipv6=0 failed";
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".disable_ipv6=0 failed");
        }

        if (!addr_flush_all(sk, ifindex))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: addr_flush_all failed";
            throw std::runtime_error("addr_flush_all failed for " + ifname);
        }
        if (!addr_add_v4_local(sk, ifindex, p.v4_local.addr_be, p.v4_local.prefix))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: addr_add_v4_local failed";
            throw std::runtime_error("addr_add_v4_local failed for " + ifname);
        }

        if (!addr_add_v6_local(sk, ifindex, p.v6_local.addr, p.v6_local.prefix))
        {
            nl_socket_free(sk);
            LOGE("network") << "ApplyServerSide: addr_add_v6_local failed";
            throw std::runtime_error("addr_add_v6_local failed for " + ifname);
        }

        nl_socket_free(sk);
        LOGD("network") << "ApplyServerSide: link and addresses configured";

        if (with_nat_fw)
        {
            if (!nft_feature_probe())
            {
                LOGE("network") << "ApplyServerSide: nftables not available";
                throw std::runtime_error(
                    "nftables is not available (kernel/userland). "
                    "Install nftables or run with --no-nat");
            }

            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/accept_ra", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl all.accept_ra=0 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv6/conf/default/accept_ra", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl default.accept_ra=0 failed";
            }

            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl v4 all.accept_redirects=0 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/accept_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl v4 default.accept_redirects=0 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl all.send_redirects=0 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/send_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl default.send_redirects=0 failed";
            }

            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/accept_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl v6 all.accept_redirects=0 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv6/conf/default/accept_redirects", "0"))
            {
                LOGW("network") << "ApplyServerSide: sysctl v6 default.accept_redirects=0 failed";
            }

            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/accept_local", "1"))
            {
                LOGW("network") << "ApplyServerSide: sysctl all.accept_local=1 failed";
            }
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/accept_local", "1"))
            {
                LOGW("network") << "ApplyServerSide: sysctl default.accept_local=1 failed";
            }

            if (!write_sysctl("/proc/sys/net/ipv4/ip_forward", "1"))
            {
                LOGE("network") << "ApplyServerSide: enable ip_forward failed";
                throw std::runtime_error("sysctl net.ipv4.ip_forward=1 failed");
            }
            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"))
            {
                LOGE("network") << "ApplyServerSide: enable v6 forwarding failed";
                throw std::runtime_error("sysctl net.ipv6.conf.all.forwarding=1 failed");
            }
        }
        else
        {
            if (nft_feature_probe())
            {
                if (!ensure_fw_tun(ifname, p))
                {
                    LOGW("network") << "ApplyServerSide: ensure_fw_tun failed (skipped)";
                }
            }
            else
            {
                LOGW("network") << "ApplyServerSide: nftables unavailable — skipping TUN firewall";
            }
        }

        nl_sock *sk2 = nl_connect_route();
        if (!sk2)
        {
            LOGE("network") << "ApplyServerSide: nl_connect NETLINK_ROUTE failed (2)";
            throw std::runtime_error("nl_connect NETLINK_ROUTE failed (2)");
        }

        auto wan4 = find_default_oifname(sk2, AF_INET);
        auto wan6 = find_default_oifname(sk2, AF_INET6);
        nl_socket_free(sk2);
        LOGD("network") << "ApplyServerSide: wan4=" << (wan4 ? *wan4 : std::string("<none>"))
                        << " wan6=" << (wan6 ? *wan6 : std::string("<none>"));

        if (with_nat_fw)
        {
            if (wan4)
            {
                (void) write_if_sysctl_v4(*wan4, "rp_filter", "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects",     "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/default/accept_redirects", "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects",       "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/default/send_redirects",   "0");
                LOGT("network") << "ApplyServerSide: tuned rp_filter/redirects on WAN4";
            }

            if (wan4 && !ensure_nat44(*wan4, p.nat44_src))
            {
                LOGE("network") << "ApplyServerSide: ensure_nat44 failed";
                throw std::runtime_error("ensure_nat44 failed (oif=" + *wan4 + ", src=" + p.nat44_src + ")");
            }
            if (wan6 && !ensure_nat66(*wan6, p.nat66_src))
            {
                LOGE("network") << "ApplyServerSide: ensure_nat66 failed";
                throw std::runtime_error("ensure_nat66 failed (oif=" + *wan6 + ", src=" + p.nat66_src + ")");
            }

            if (!ensure_mss_clamp(wan4, wan6, p))
            {
                LOGW("network") << "ApplyServerSide: ensure_mss_clamp failed (skipped)";
            }

            if (!ensure_fw_tun(ifname, p))
            {
                LOGE("network") << "ApplyServerSide: ensure_fw_tun failed (mandatory with NAT)";
                throw std::runtime_error("ensure_fw_tun failed");
            }
        }

        LOGI("network") << "ApplyServerSide: complete";
    }
} // namespace NetConfig
