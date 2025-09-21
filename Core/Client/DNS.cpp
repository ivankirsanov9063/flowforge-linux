#include "DNS.hpp"
#include "Core/Logger.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <filesystem>
#include <cerrno>
#include <cstring>

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-bus.h>
#endif

namespace fs = std::filesystem;

// ---------- helpers ----------
std::string DNS::StripBrackets(const std::string &s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        return s.substr(1, s.size() - 2);
    return s;
}

bool DNS::IsIPv6(const std::string &ip)
{
    return ip.find(':') != std::string::npos;
}

int DNS::IfIndex(const std::string &ifname)
{
    return static_cast<int>(if_nametoindex(ifname.c_str()));
}

// ---------- ctor/dtor ----------
DNS::DNS(const Params &p)
        : p_(p)
{
    if (p_.ifname.empty())
        throw std::invalid_argument("DNS: ifname is empty");
    ifindex_ = IfIndex(p_.ifname);
    if (ifindex_ <= 0)
        throw std::runtime_error("DNS: if_nametoindex failed for " + p_.ifname);
}

DNS::~DNS()
{
    try { Revert(); } catch (...) {}
}

// ---------- public ----------
void DNS::Apply()
{
    LOGI("dns") << "Apply: if=" << p_.ifname
                << " servers=" << (int)p_.servers.size()
                << " systemd=" << (p_.use_systemd ? "1" : "0")
                << " default_route=" << (p_.make_default_route ? "1" : "0")
                << " resolv_fallback=" << (p_.resolv_conf_fallback ? "1" : "0");

#ifdef HAVE_LIBSYSTEMD
    if (p_.use_systemd && Systemd_Available())
    {
        if (Systemd_Apply())
        {
            applied_ = true;
            applied_systemd_ = true;
            return;
        }
        LOGW("dns") << "systemd-resolved apply failed, considering resolv.conf fallback";
    }
#else
    LOGD("dns") << "libsystemd not available at build time; skipping systemd-resolved path";
#endif

    if (p_.resolv_conf_fallback && Resolv_IsSafeToEdit())
    {
        if (Resolv_Apply())
        {
            applied_ = true;
            applied_resolv_ = true;
            return;
        }
        LOGW("dns") << "resolv.conf apply failed";
    }
    else
    {
        LOGD("dns") << "resolv.conf fallback is disabled or unsafe to edit";
    }
}

void DNS::Revert()
{
#ifdef HAVE_LIBSYSTEMD
    if (applied_systemd_ && p_.use_systemd && Systemd_Available())
    {
        try { Systemd_Revert(); } catch (...) {}
        applied_systemd_ = false;
    }
#endif
    if (applied_resolv_ && backup_done_)
    {
        try { Resolv_Revert(); } catch (...) {}
        applied_resolv_ = false;
    }
    applied_ = false;
}

// ---------- systemd-resolved ----------
#ifdef HAVE_LIBSYSTEMD
bool DNS::Systemd_Available() const
{
    sd_bus *bus = nullptr;
    if (sd_bus_open_system(&bus) < 0) return false;

    sd_bus_message *reply = nullptr;
    int rc = sd_bus_call_method(bus,
                                "org.freedesktop.resolve1",
                                "/org/freedesktop/resolve1",
                                "org.freedesktop.DBus.Peer",
                                "Ping",
                                nullptr, &reply, NULL);
    if (reply) sd_bus_message_unref(reply);
    sd_bus_unref(bus);
    return rc >= 0;
}

bool DNS::Systemd_Apply()
{
    sd_bus *bus = nullptr;
    int rc = sd_bus_open_system(&bus);
    if (rc < 0)
    {
        LOGW("dns") << "sd_bus_open_system failed: " << rc;
        return false;
    }

    // SetLinkDNS(ifindex, a(iay))
    sd_bus_message *m = nullptr, *reply = nullptr;
    rc = sd_bus_message_new_method_call(bus, &m,
                                        "org.freedesktop.resolve1",
                                        "/org/freedesktop/resolve1",
                                        "org.freedesktop.resolve1.Manager",
                                        "SetLinkDNS");
    if (rc < 0) { sd_bus_unref(bus); return false; }

    if ((rc = sd_bus_message_append(m, "i", ifindex_)) < 0) { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }
    if ((rc = sd_bus_message_open_container(m, 'a', "(iay)")) < 0) { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }

    for (const auto &raw : p_.servers)
    {
        const std::string ip = StripBrackets(raw);
        const int af = IsIPv6(ip) ? AF_INET6 : AF_INET;
        std::uint8_t buf[16] = {};
        if (inet_pton(af, ip.c_str(), buf) != 1)
        {
            LOGW("dns") << "Invalid DNS IP: " << ip;
            continue;
        }

        if ((rc = sd_bus_message_open_container(m, 'r', "iay")) < 0) { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }
        if ((rc = sd_bus_message_append(m, "i", af)) < 0)            { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }
        if ((rc = sd_bus_message_append_array(m, 'y', buf, (af == AF_INET) ? 4 : 16)) < 0)
        { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }
        if ((rc = sd_bus_message_close_container(m)) < 0)            { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }
    }

    if ((rc = sd_bus_message_close_container(m)) < 0) { sd_bus_message_unref(m); sd_bus_unref(bus); return false; }

    if ((rc = sd_bus_call(bus, m, 0, nullptr, &reply)) < 0)
    {
        LOGW("dns") << "SetLinkDNS failed: " << rc;
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        return false;
    }
    sd_bus_message_unref(m);
    if (reply) sd_bus_message_unref(reply);

    // DefaultRoute + "~." (route-only)
    if (p_.make_default_route)
    {
        if ((rc = sd_bus_call_method(bus,
                                     "org.freedesktop.resolve1",
                                     "/org/freedesktop/resolve1",
                                     "org.freedesktop.resolve1.Manager",
                                     "SetLinkDefaultRoute",
                                     nullptr, &reply,
                                     "ib", ifindex_, 1)) < 0)
        {
            LOGW("dns") << "SetLinkDefaultRoute failed: " << rc;
        }
        if (reply) sd_bus_message_unref(reply);

        rc = sd_bus_message_new_method_call(bus, &m,
                                            "org.freedesktop.resolve1",
                                            "/org/freedesktop/resolve1",
                                            "org.freedesktop.resolve1.Manager",
                                            "SetLinkDomains");
        if (rc >= 0)
        {
            rc = sd_bus_message_append(m, "i", ifindex_);
            if (rc >= 0) rc = sd_bus_message_open_container(m, 'a', "(sb)");
            if (rc >= 0)
            {
                rc = sd_bus_message_open_container(m, 'r', "sb");
                if (rc >= 0) rc = sd_bus_message_append(m, "s", "~.");
                if (rc >= 0) rc = sd_bus_message_append(m, "b", 1); // route-only
                if (rc >= 0) rc = sd_bus_message_close_container(m);
            }
            if (rc >= 0) rc = sd_bus_message_close_container(m);
            if (rc >= 0) rc = sd_bus_call(bus, m, 0, nullptr, &reply);
            if (m) sd_bus_message_unref(m);
            if (reply) sd_bus_message_unref(reply);
            if (rc < 0) LOGW("dns") << "SetLinkDomains(~.) failed: " << rc;
        }
    }

    sd_bus_unref(bus);
    LOGI("dns") << "systemd-resolved: per-link DNS applied";
    return true;
}

void DNS::Systemd_Revert()
{
    sd_bus *bus = nullptr;
    if (sd_bus_open_system(&bus) < 0) return;

    // clear LinkDomains
    sd_bus_message *m = nullptr, *reply = nullptr;
    if (sd_bus_message_new_method_call(bus, &m,
                                       "org.freedesktop.resolve1",
                                       "/org/freedesktop/resolve1",
                                       "org.freedesktop.resolve1.Manager",
                                       "SetLinkDomains") >= 0)
    {
        sd_bus_message_append(m, "i", ifindex_);
        sd_bus_message_open_container(m, 'a', "(sb)");
        sd_bus_message_close_container(m);
        sd_bus_call(bus, m, 0, nullptr, &reply);
    }
    if (m) sd_bus_message_unref(m);
    if (reply) sd_bus_message_unref(reply);

    // clear LinkDNS
    m = reply = nullptr;
    if (sd_bus_message_new_method_call(bus, &m,
                                       "org.freedesktop.resolve1",
                                       "/org/freedesktop/resolve1",
                                       "org.freedesktop.resolve1.Manager",
                                       "SetLinkDNS") >= 0)
    {
        sd_bus_message_append(m, "i", ifindex_);
        sd_bus_message_open_container(m, 'a', "(iay)");
        sd_bus_message_close_container(m);
        sd_bus_call(bus, m, 0, nullptr, &reply);
    }
    if (m) sd_bus_message_unref(m);
    if (reply) sd_bus_message_unref(reply);

    // default route false
    sd_bus_call_method(bus,
                       "org.freedesktop.resolve1",
                       "/org/freedesktop/resolve1",
                       "org.freedesktop.resolve1.Manager",
                       "SetLinkDefaultRoute",
                       nullptr, &reply, "ib", ifindex_, 0);
    if (reply) sd_bus_message_unref(reply);

    sd_bus_unref(bus);
    LOGI("dns") << "systemd-resolved: per-link DNS reverted";
}
#endif // HAVE_LIBSYSTEMD

// ---------- resolv.conf fallback ----------
bool DNS::Resolv_IsSafeToEdit() const
{
    // 1) если symlink на systemd/NM/openresolv — НЕ трогаем
    try
    {
        if (fs::is_symlink(p_.resolv_conf_path))
        {
            auto target = fs::read_symlink(p_.resolv_conf_path).string();
            if (target.find("systemd/resolve") != std::string::npos) return false;
            if (target.find("NetworkManager")  != std::string::npos) return false;
            if (target.find("resolvconf")      != std::string::npos) return false;
        }
    }
    catch (...) {}

    // 2) есть ли права на запись к файлу или каталогу
    if (::access(p_.resolv_conf_path.c_str(), W_OK) == 0) return true;

    try
    {
        auto parent = fs::path(p_.resolv_conf_path).parent_path();
        if (fs::exists(parent) && ::access(parent.c_str(), W_OK) == 0) return true;
    }
    catch (...) {}

    return false;
}

bool DNS::Resolv_Apply()
{
    // бэкап
    try
    {
        if (fs::exists(p_.resolv_conf_path))
        {
            backup_path_ = p_.resolv_conf_path + ".flowforge.bak";
            fs::copy_file(p_.resolv_conf_path, backup_path_, fs::copy_options::overwrite_existing);
            backup_done_ = true;
            LOGD("dns") << "Backup: " << backup_path_;
        }
    }
    catch (const std::exception &e)
    {
        LOGE("dns") << "Backup resolv.conf failed: " << e.what();
        return false;
    }

    std::ostringstream out;
    out << "# Generated by FlowForge (temporary)\n";
    for (const auto &raw : p_.servers)
    {
        const auto ip = StripBrackets(raw);
        out << "nameserver " << ip << "\n";
    }
    out << "options edns0\n";

    try
    {
        std::ofstream f(p_.resolv_conf_path, std::ios::binary | std::ios::trunc);
        f << out.str();
        f.close();
        LOGI("dns") << "resolv.conf written";
        return true;
    }
    catch (const std::exception &e)
    {
        LOGE("dns") << "Write resolv.conf failed: " << e.what();
        return false;
    }
}

void DNS::Resolv_Revert()
{
    if (!backup_done_) return;
    try
    {
        fs::copy_file(backup_path_, p_.resolv_conf_path, fs::copy_options::overwrite_existing);
        fs::remove(backup_path_);
        LOGI("dns") << "resolv.conf restored";
    }
    catch (const std::exception &e)
    {
        LOGW("dns") << "Restore resolv.conf failed: " << e.what();
    }
}
