// Client.cpp — Linux версия с поддержкой NetWatcher и FirewallRules (libnftables)
// Без внешних утилит; логирование через Boost.Log макросы LOG*.

#include "Core/Logger.hpp"
#include "Core/PluginWrapper.hpp"
#include "Core/TUN.hpp"
#include "Core/Config.hpp"
#include "Network.hpp"
#include "NetWatcher.hpp"
#include "FirewallRules.hpp"
#include "DNS.hpp"
#include "NetworkRollback.hpp"
#include "Client.hpp"

#include <csignal>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <boost/json.hpp>

static std::atomic<bool> g_started { false };
static volatile sig_atomic_t g_working = 1;
static std::thread g_thread;

static bool IsElevated()
{
    return (::geteuid() == 0);
}

static std::string StripBrackets(const std::string &s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
    {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static bool IsIpLiteral(const std::string &s)
{
    std::string x = StripBrackets(s);
    in_addr a4{};
    in6_addr a6{};
    return ::inet_pton(AF_INET, x.c_str(), &a4) == 1
           || ::inet_pton(AF_INET6, x.c_str(), &a6) == 1;
}

static int ClientMain(std::string& config)
{
    Logger::Options log_opts;
    log_opts.app_name             = "FlowForge";
    log_opts.directory            = "logs";
    log_opts.base_filename        = "flowforge";
    log_opts.file_min_severity    = boost::log::trivial::info;
    log_opts.console_min_severity = boost::log::trivial::debug;

    Logger::Guard lg(log_opts);
    LOGI("client") << "Starting FlowForge (Linux)";

    if (!IsElevated())
    {
        LOGE("client") << "Please run as root";
        return 1;
    }

    // Defaults (синхронизированы с Windows-версией)
    std::string tun         = "cvpn0";
    std::string server_ip   = "193.233.23.221";
    int         port        = 5555;
    std::string plugin_path = "./libPlugSRT.so";

    std::string local4 = "10.200.0.2";
    std::string peer4  = "10.200.0.1";
    std::string local6 = "fd00:dead:beef::2";
    std::string peer6  = "fd00:dead:beef::1";
    int mtu = 1400;

    std::vector<std::string> dns_cli = {"10.200.0.1", "1.1.1.1"};
    bool dns_overridden = false;

    LOGD("client") << "Parsing JSON config";

    auto trim_copy = [](const std::string& s) -> std::string
    {
        size_t b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return std::string();
        size_t e = s.find_last_not_of(" \t\r\n");
        return s.substr(b, e - b + 1);
    };

    boost::json::value jv = boost::json::parse(config);
        if (!jv.is_object())
            throw std::runtime_error("config root must be an object");

        boost::json::object& o = jv.as_object();

        // Обязательные поля (все):
        tun         = Config::RequireString(o, "tun");
        server_ip   = Config::RequireString(o, "server");
        port        = Config::RequireInt(o,    "port");
        plugin_path = Config::RequireString(o, "plugin");

        local4      = Config::RequireString(o, "local4");
        peer4       = Config::RequireString(o, "peer4");
        local6      = Config::RequireString(o, "local6");
        peer6       = Config::RequireString(o, "peer6");

        mtu         = Config::RequireInt(o,    "mtu");

        // dns: допускаем либо массив строк, либо строку "ip,ip,..."
        dns_cli.clear();
        if (const boost::json::value* dv = o.if_contains("dns"))
        {
            if (dv->is_array())
            {
                for (const boost::json::value& x : dv->as_array())
                {
                    if (!x.is_string())
                        throw std::runtime_error("dns array must contain strings");
                    std::string s = trim_copy(boost::json::value_to<std::string>(x));
                    if (!s.empty()) dns_cli.emplace_back(std::move(s));
                }
            }
            else if (dv->is_string())
            {
                std::string v = boost::json::value_to<std::string>(*dv);
                size_t start = 0;
                while (start < v.size())
                {
                    size_t pos = v.find(',', start);
                    std::string tok = (pos == std::string::npos) ? v.substr(start)
                                                                 : v.substr(start, pos - start);
                    tok = trim_copy(tok);
                    if (!tok.empty()) dns_cli.emplace_back(std::move(tok));
                    if (pos == std::string::npos) break;
                    start = pos + 1;
                }
            }
            else
            {
                throw std::runtime_error("dns must be either array of strings or comma-separated string");
            }
            dns_overridden = true;
        }
        else
        {
            throw std::runtime_error("missing required field 'dns'");
        }

        LOGD("client") << "Args: tun=" << tun << " server=" << server_ip << " port=" << port
                   << " plugin=" << plugin_path
                   << " local4=" << local4 << " peer4=" << peer4
                   << " local6=" << local6 << " peer6=" << peer6
                   << " mtu=" << mtu;

        // Базовая валидация
        if (server_ip.empty())
            throw std::runtime_error("'server' cannot be empty");
        if (port <= 0 || port > 65535)
            throw std::runtime_error("'port' must be in [1..65535]");
        if (mtu < 576 || mtu > 9200)
            throw std::runtime_error("'mtu' must be in [576..9200]");

    // Прокидываем адресный план/MTU в сетевой модуль до конфигурации
    {
        Network::Params np;
        np.local4 = local4;
        np.peer4 = peer4;
        np.local6 = local6;
        np.peer6 = peer6;
        np.mtu = mtu;
        Network::SetParams(np);
    }


    server_ip = StripBrackets(server_ip);
    if (!IsIpLiteral(server_ip))
    {
        LOGE("client") << "--server must be an IP literal for beta (no WAN-DNS bootstrap). Use IPv4 or [IPv6].";
        return 1;
    }
    LOGD("client") << "Server: " << server_ip << " port=" << port << " tun=" << tun;

    NetworkRollback::Params rbp;
    rbp.tun_ifname  = tun;                 // "cvpn0"
    rbp.server_ip   = server_ip;           // "193.233.23.221" или "[2001:db8::1]"
    rbp.revert_v4   = true;
    rbp.revert_v6   = true;
    rbp.flush_addrs = true;

    NetworkRollback rb(rbp);

    // Plugin
    LOGD("pluginwrapper") << "Loading plugin: " << plugin_path;
    auto plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    {
        LOGE("pluginwrapper") << "Failed to load plugin";
        return 1;
    }
    LOGI("pluginwrapper") << "Plugin loaded";

    // TUN
    LOGD("tun") << "Opening TUN: " << tun;
    int tun_fd = TunAlloc(tun);
    if (tun_fd < 0)
    {
        LOGE("tun") << "TunAlloc failed";
        PluginWrapper::Unload(plugin);
        return 1;
    }
    int fl = fcntl(tun_fd, F_GETFL, 0);
    if (fl >= 0) { fcntl(tun_fd, F_SETFL, fl | O_NONBLOCK); }
    LOGI("tun") << "Up: " << tun;

    // DNS: применяем выбранные серверы на интерфейсе TUN (RAII)
    DNS::Params dns_p;
    dns_p.ifname  = tun;
    dns_p.servers = dns_cli;
    DNS dns(dns_p);
    try
    {
        dns.Apply();
        LOGI("dns") << "DNS applied for " << tun;
    }
    catch (const std::exception &e)
    {
        LOGW("dns") << "DNS apply failed: " << e.what();
    }


    // Firewall: разрешаем только lo, TUN и сервер:порт.
    FirewallRules::Params fw_p;
    fw_p.tun_ifname    = tun;
    fw_p.server_ip     = server_ip;
    fw_p.server_port   = static_cast<std::uint16_t>(port);
    fw_p.allow_udp     = true;
    fw_p.allow_tcp     = true;
    fw_p.hook_priority = 0;

    fw_p.allow_dhcp          = true;
    fw_p.allow_icmp          = true;

    FirewallRules fw(fw_p);
    try
    {
        fw.Apply();
    }
    catch (const std::exception &e)
    {
        LOGE("firewall") << "Apply failed: " << e.what();
    }

    // Network configure (best-effort both families)
    auto ConfigureOnce = [&]() -> bool
    {
        LOGI("network") << "ConfigureNetwork begin";
        int rc = ConfigureNetwork(tun, server_ip);
        if (rc != 0)
        {
            LOGE("network") << "ConfigureNetwork failed rc=" << rc;
            return false;
        }
        LOGI("network") << "ConfigureNetwork done";
        return true;
    };

    if (!ConfigureOnce())
    {
        ::close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    // NetWatcher: пересобираем маршруты при изменениях в системе
    auto reapply = [&]()
    {
        LOGD("netwatcher") << "Reapply triggered";
        (void)ConfigureOnce();
    };

    NetWatcher watcher(reapply, std::chrono::milliseconds(1000));
    LOGD("netwatcher") << "Armed";

    // Connect
    if (!PluginWrapper::Client_Connect(plugin, o))
    {
        LOGE("pluginwrapper") << "Client_Connect failed";
        watcher.Stop();
        try { fw.Revert(); } catch (...) {}
        ::close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }
    LOGI("pluginwrapper") << "Connected";

    auto SendToNet = [tun_fd](const std::uint8_t* data, std::size_t len) -> ssize_t
    {
        ssize_t wr = ::write(tun_fd, data, len);
        if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
        if (wr < 0)
        {
            LOGW("tun") << "write() failed: " << std::strerror(errno);
            return -1;
        }
        LOGT("tun") << "TO_NET len=" << wr;
        return wr;
    };

    auto RecvFromNet = [tun_fd](std::uint8_t* buf, std::size_t cap) -> ssize_t
    {
        ssize_t rd = ::read(tun_fd, buf, cap);
        if (rd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
        if (rd < 0)
        {
            LOGW("tun") << "read() failed: " << std::strerror(errno);
            return -1;
        }
        LOGT("tun") << "FROM_NET len=" << rd;
        return rd;
    };

    LOGI("pluginwrapper") << "Serve begin";
    int rc = PluginWrapper::Client_Serve(plugin, RecvFromNet, SendToNet, &g_working);
    LOGI("pluginwrapper") << "Serve end rc=" << rc;

    PluginWrapper::Client_Disconnect(plugin);
    watcher.Stop();

    ::close(tun_fd);
    PluginWrapper::Unload(plugin);

    LOGI("client") << "Shutdown complete";
    return rc;
}

// Запуск клиента в отдельном потоке.
// cfg - json-данные конфига
EXPORT int32_t Start(char *cfg)
{
    if (g_started.load())
    {
        return -1; // уже запущено
    }

    // Снимем копию аргументов, чтобы не зависеть от времени жизни входных указателей.
    std::string config = cfg;
    g_working = 1;

    g_thread = std::thread([config]() mutable
       {
           ClientMain(config);
           g_started.store(false);
       });

    // Не детачим: хотим корректно join-ить в Stop() (без блокировки вызывающего).
    g_started.store(true);
    return 0;
}

// Мягкая остановка: сигналим рабочему коду и НЕ блокируем вызывающего.
EXPORT int32_t Stop(void)
{
    if (!g_started.load())
    {
        return -2; // не запущено
    }
    g_working = 0;

    // Фоновое ожидание завершения рабочего потока.
    std::thread([]()
    {
        if (g_thread.joinable())
        {
            g_thread.join();
        }
        g_started.store(false);
    }).detach();

    return 0;
}

// Статус работы: 1 — запущен, 0 — остановлен
EXPORT int32_t IsRunning(void)
{
    return g_started.load() ? 1 : 0;
}

