// NetWatcher.cpp — наблюдение за изменениями default route и пересборка NAT/MSS

#include "NetWatcher.hpp"
#include "Network.hpp"
#include "Core/Logger.hpp"

#include <chrono>
#include <thread>
#include <mutex>
#include <optional>
#include <string>
#include <stdexcept>
#include <algorithm>

#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>
#include <netlink/errno.h>

namespace
{
    // Коллбек libnl: любое валидное сообщение маршрутизации — триггер на пересборку.
    int on_nl_valid(struct nl_msg *,
                    void *arg)
    {
        auto *self = static_cast<NetWatcher *>(arg);
        (void) self; // тяжёлую работу не делаем в коллбеке
        LOGT("netwatcher") << "RTNL: valid message received";
        return NL_OK;
    }
}

NetWatcher::NetWatcher(const NetConfig::Params &params)
    : params_(params)
{
    LOGI("netwatcher") << "Init: starting (probing nftables)";

    // Требуем доступность nftables: на старых ядрах/дистрибутивах может не работать.
    if (!NetConfig::nft_feature_probe())
    {
        LOGE("netwatcher") << "Init: nftables not available on this platform";
        throw std::runtime_error("NetWatcher: nftables is not available on this platform");
    }

    sk_ = nl_socket_alloc();
    if (!sk_)
    {
        LOGE("netwatcher") << "Init: nl_socket_alloc failed";
        throw std::runtime_error("NetWatcher: nl_socket_alloc failed");
    }
    if (nl_connect(sk_, NETLINK_ROUTE) != 0)
    {
        LOGE("netwatcher") << "Init: nl_connect NETLINK_ROUTE failed";
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_connect NETLINK_ROUTE failed");
    }
    LOGD("netwatcher") << "Init: connected to NETLINK_ROUTE";

    // Подписываемся на события изменения маршрутов IPv4/IPv6
    if (nl_socket_add_membership(sk_, RTNLGRP_IPV4_ROUTE) != 0)
    {
        LOGE("netwatcher") << "Init: add_membership RTNLGRP_IPV4_ROUTE failed";
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_add_membership RTNLGRP_IPV4_ROUTE failed");
    }
    LOGD("netwatcher") << "Init: subscribed RTNLGRP_IPV4_ROUTE";

    if (nl_socket_add_membership(sk_, RTNLGRP_IPV6_ROUTE) != 0)
    {
        LOGE("netwatcher") << "Init: add_membership RTNLGRP_IPV6_ROUTE failed";
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_add_membership RTNLGRP_IPV6_ROUTE failed");
    }
    LOGD("netwatcher") << "Init: subscribed RTNLGRP_IPV6_ROUTE";

    // Неблокирующий режим + периодический опрос
    if (nl_socket_set_nonblocking(sk_) != 0)
    {
        LOGE("netwatcher") << "Init: nl_socket_set_nonblocking failed";
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_set_nonblocking failed");
    }
    LOGD("netwatcher") << "Init: netlink socket is non-blocking";

    // Коллбек на валидные сообщения (содержание неважно — после события пересчитаем WAN)
    if (nl_socket_modify_cb(sk_, NL_CB_VALID, NL_CB_CUSTOM, &on_nl_valid, this) != 0)
    {
        LOGE("netwatcher") << "Init: nl_socket_modify_cb(NL_CB_VALID) failed";
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_modify_cb(NL_CB_VALID) failed");
    }
    LOGD("netwatcher") << "Init: NL_CB_VALID callback installed";

    // Запускаем рабочий поток
    LOGI("netwatcher") << "Init: starting worker thread";
    th_ = std::thread([this]
    {
        ThreadMain_();
    });
}

NetWatcher::~NetWatcher()
{
    LOGI("netwatcher") << "Shutdown: stopping worker thread";
    stop_.store(true, std::memory_order_relaxed);

    if (th_.joinable())
    {
        th_.join();
        LOGD("netwatcher") << "Shutdown: worker thread joined";
    }
    if (sk_)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        LOGD("netwatcher") << "Shutdown: netlink socket freed";
    }
    LOGI("netwatcher") << "Shutdown: complete";
}

std::optional<std::string> NetWatcher::Wan4() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return last_wan4_;
}

std::optional<std::string> NetWatcher::Wan6() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return last_wan6_;
}

void NetWatcher::ThreadMain_()
{
    LOGI("netwatcher") << "ThreadMain: enter";

    // Первичное применение: на текущий дефолт
    try
    {
        LOGD("netwatcher") << "ThreadMain: initial recompute/apply";
        RecomputeAndApply_();
        LOGD("netwatcher") << "ThreadMain: initial apply done";
    }
    catch (const std::exception &)
    {
        LOGE("netwatcher") << "ThreadMain: initial recompute/apply failed, stopping";
        stop_.store(true, std::memory_order_relaxed);
        return;
    }

    using namespace std::chrono_literals;

    while (!stop_.load(std::memory_order_relaxed))
    {
        int rc = nl_recvmsgs_default(sk_);
        if (rc < 0 && rc != -NLE_AGAIN)
        {
            LOGE("netwatcher") << "ThreadMain: nl_recvmsgs_default error rc=" << rc << ", stopping";
            stop_.store(true, std::memory_order_relaxed);
            break;
        }

        static auto last_resync = std::chrono::steady_clock::now();
        if (rc > 0)
        {
            LOGT("netwatcher") << "ThreadMain: processed " << rc << " netlink message(s)";
            try
            {
                LOGT("netwatcher") << "ThreadMain: recompute/apply on event";
                RecomputeAndApply_();
            }
            catch (const std::exception &)
            {
                LOGE("netwatcher") << "ThreadMain: recompute/apply failed, stopping";
                stop_.store(true, std::memory_order_relaxed);
                break;
            }
            last_resync = std::chrono::steady_clock::now();
        }
        else
        {
            // Rare periodic resync (e.g. missed event)
            auto now = std::chrono::steady_clock::now();
            if (now - last_resync >= std::chrono::seconds(10))
            {
                try
                {
                    LOGT("netwatcher") << "ThreadMain: periodic recompute/apply";
                    RecomputeAndApply_();
                }
                catch (const std::exception &)
                {
                    LOGE("netwatcher") << "ThreadMain: periodic recompute/apply failed, stopping";
                    stop_.store(true, std::memory_order_relaxed);
                    break;
                }
                last_resync = now;
            }
        }

        std::this_thread::sleep_for(200ms);
    }

    LOGI("netwatcher") << "ThreadMain: exit";
}

void NetWatcher::RecomputeAndApply_()
{
    // Вычисляем актуальные WAN-ы на основе текущего состояния маршрутов
    auto wan4 = NetConfig::find_default_oifname(sk_, AF_INET);
    auto wan6 = NetConfig::find_default_oifname(sk_, AF_INET6);

    LOGD("netwatcher") << "Recompute: wan4=" << (wan4 ? *wan4 : std::string("<none>"))
                       << " wan6=" << (wan6 ? *wan6 : std::string("<none>"));

    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (wan4 != last_wan4_ || wan6 != last_wan6_)
        {
            changed    = true;
            last_wan4_ = wan4;
            last_wan6_ = wan6;
        }
    }

    if (!changed)
    {
        LOGT("netwatcher") << "Recompute: no WAN change";
        return;
    }

    LOGI("netwatcher") << "Recompute: WAN changed, applying NAT/MSS";
    ApplyNatAndMss_(wan4, wan6, params_);
    LOGI("netwatcher") << "Recompute: NAT/MSS applied";
}

void NetWatcher::ApplyNatAndMss_(const std::optional<std::string> &wan4,
                                 const std::optional<std::string> &wan6,
                                 const NetConfig::Params          &p)
{
    LOGD("netwatcher") << "Apply: begin NAT/MSS (mtu=" << p.mtu << ")";

    // 1) NAT: чистим цепи в наших таблицах и, если WAN существует — ставим правило
    {
        // ip(v4)
        std::string cmd4;
        cmd4  = "add table ip flowforge_nat\n";
        cmd4 += "add chain ip flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd4 += "flush chain ip flowforge_nat postrouting\n";
        if (!NetConfig::nft_apply(cmd4))
        {
            LOGE("netwatcher") << "Apply: nft apply failed for IPv4 NAT bootstrap";
            throw std::runtime_error("NetWatcher: nft apply for IPv4 NAT bootstrap failed");
        }
        LOGT("netwatcher") << "Apply: IPv4 NAT table/chain ready";

        if (wan4 && !p.nat44_src.empty())
        {
            LOGD("netwatcher") << "Apply: ensure NAT44 on oif=" << *wan4
                               << " saddr=" << p.nat44_src;
            (void) NetConfig::ensure_nat44(*wan4, p.nat44_src);
        }
        else
        {
            LOGT("netwatcher") << "Apply: skip NAT44 (no wan4 or nat44_src empty)";
        }
    }
    {
        // ip6
        std::string cmd6;
        cmd6  = "add table ip6 flowforge_nat\n";
        cmd6 += "add chain ip6 flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd6 += "flush chain ip6 flowforge_nat postrouting\n";
        if (!NetConfig::nft_apply(cmd6))
        {
            LOGE("netwatcher") << "Apply: nft apply failed for IPv6 NAT bootstrap";
            throw std::runtime_error("NetWatcher: nft apply for IPv6 NAT bootstrap failed");
        }
        LOGT("netwatcher") << "Apply: IPv6 NAT table/chain ready";

        if (wan6 && !p.nat66_src.empty())
        {
            LOGD("netwatcher") << "Apply: ensure NAT66 on oif=" << *wan6
                               << " saddr=" << p.nat66_src;
            (void) NetConfig::ensure_nat66(*wan6, p.nat66_src);
        }
        else
        {
            LOGT("netwatcher") << "Apply: skip NAT66 (no wan6 or nat66_src empty)";
        }
    }

    // 2) MSS clamp: чистим и добавляем заново (как в Network.cpp)
    {
        // Шаг 1: гарантируем table/chain с ЧИСЛОВЫМ приоритетом (совместимо со старыми nft)
        std::string mk;
        mk  = "add table inet flowforge_post\n";
        mk += "add chain inet flowforge_post postrouting "
              "{ type filter hook postrouting priority -150; policy accept; }\n";

        if (!NetConfig::nft_apply(mk))
        {
            LOGW("netwatcher") << "Apply: MSS mk failed, retry after delete";
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            if (!NetConfig::nft_apply(mk))
            {
                LOGE("netwatcher") << "Apply: MSS table/chain creation failed";
                throw std::runtime_error("NetWatcher: nft apply for MSS table/chain failed");
            }
        }
        LOGT("netwatcher") << "Apply: MSS table/chain ready";

        // Шаг 2: отдельный flush (старые nft падают, если делать всё одним батчем)
        if (!NetConfig::nft_apply("flush chain inet flowforge_post postrouting\n"))
        {
            LOGW("netwatcher") << "Apply: MSS flush failed, recreate table/chain";
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            if (!NetConfig::nft_apply(mk))
            {
                LOGE("netwatcher") << "Apply: MSS flush/recreate failed";
                throw std::runtime_error("NetWatcher: nft flush/recreate for MSS chain failed");
            }
        }

        // Шаг 3: правила (сначала современный синтаксис RT MTU, затем фоллбэк)
        std::string rules_rt;

        if (wan4 && !p.nat44_src.empty())
        {
            rules_rt += "add rule inet flowforge_post postrouting "
                        "ip saddr " + p.nat44_src + " "
                        "oifname \"" + *wan4 + "\" "
                        "tcp flags syn tcp option maxseg size set rt mtu "
                        "comment \"flowforge:mss\"\n";
        }
        if (wan6 && !p.nat66_src.empty())
        {
            rules_rt += "add rule inet flowforge_post postrouting "
                        "ip6 saddr " + p.nat66_src + " "
                        "oifname \"" + *wan6 + "\" "
                        "tcp flags syn tcp option maxseg size set rt mtu "
                        "comment \"flowforge:mss6\"\n";
        }

        if (!rules_rt.empty())
        {
            if (!NetConfig::nft_apply(rules_rt))
            {
                const int mss4 = std::max(536, p.mtu - 40);
                const int mss6 = std::max(536, p.mtu - 60);

                LOGW("netwatcher") << "Apply: RT MTU rules failed, fallback to fixed MSS "
                                   << "(mss4=" << mss4 << ", mss6=" << mss6 << ")";

                std::string rules_fix;

                if (wan4 && !p.nat44_src.empty())
                {
                    rules_fix += "add rule inet flowforge_post postrouting "
                                 "ip saddr " + p.nat44_src + " "
                                 "oifname \"" + *wan4 + "\" "
                                 "tcp flags syn tcp option maxseg size set " + std::to_string(mss4) + " "
                                 "comment \"flowforge:mss\"\n";
                }
                if (wan6 && !p.nat66_src.empty())
                {
                    rules_fix += "add rule inet flowforge_post postrouting "
                                 "ip6 saddr " + p.nat66_src + " "
                                 "oifname \"" + *wan6 + "\" "
                                 "tcp flags syn tcp option maxseg size set " + std::to_string(mss6) + " "
                                 "comment \"flowforge:mss6\"\n";
                }

                if (!rules_fix.empty() && !NetConfig::nft_apply(rules_fix))
                {
                    LOGE("netwatcher") << "Apply: MSS fallback rules failed to apply";
                    throw std::runtime_error("NetWatcher: nft apply for MSS fallback rules failed");
                }
                else
                {
                    LOGD("netwatcher") << "Apply: MSS fallback rules applied";
                }
            }
            else
            {
                LOGD("netwatcher") << "Apply: MSS rules with RT MTU applied";
            }
        }
        else
        {
            LOGT("netwatcher") << "Apply: no MSS rules to apply (no WAN or sources empty)";
        }
    }

    LOGD("netwatcher") << "Apply: done NAT/MSS";
}
