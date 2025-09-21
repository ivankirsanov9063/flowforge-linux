#include "NetworkRollback.hpp"
#include "Core/Logger.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <string>
#include <vector>
#include <optional>
#include <cctype>

#include <nftables/libnftables.h>

namespace
{
    std::string ToProcSysPath(const std::string &dotted)
    {
        LOGT("networkrollback") << "ToProcSysPath: key=" << dotted;
        std::string p = "/proc/sys/";
        p.reserve(p.size() + dotted.size());
        for (char c : dotted)
        {
            p.push_back(c == '.' ? '/' : c);
        }
        return p;
    }

    std::string ReadAllFromFd(int fd)
    {
        LOGT("networkrollback") << "ReadAllFromFd: begin";
        std::string out;
        char        buf[4096];
        for (;;)
        {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n > 0)
            {
                out.append(buf, buf + n);
                continue;
            }
            if (n == 0)
            {
                break;
            }
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        LOGT("networkrollback") << "ReadAllFromFd: read=" << out.size() << " bytes";
        return out;
    }
}

std::optional<std::string> NetworkRollback::ReadSysctl(const std::string &dotted)
{
    LOGD("networkrollback") << "ReadSysctl: key=" << dotted;
    const std::string path = ToProcSysPath(dotted);
    int               fd   = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        LOGW("networkrollback") << "ReadSysctl: open failed path=" << path << " errno=" << errno;
        return std::nullopt;
    }

    std::string data = ReadAllFromFd(fd);
    ::close(fd);

    if (data.empty())
    {
        LOGW("networkrollback") << "ReadSysctl: empty value path=" << path;
        return std::nullopt;
    }

    while (!data.empty() &&
           (data.back() == '\n' || data.back() == ' ' || data.back() == '\t'))
    {
        data.pop_back();
    }
    LOGT("networkrollback") << "ReadSysctl: ok key=" << dotted << " value='" << data << "'";
    return data;
}

bool NetworkRollback::WriteSysctl(const std::string &dotted,
                                  const std::string &value)
{
    LOGD("networkrollback") << "WriteSysctl: key=" << dotted << " value='" << value << "'";
    const std::string path = ToProcSysPath(dotted);
    int               fd   = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno != ENOENT)
        {
            LOGE("networkrollback") << "WriteSysctl: open failed path=" << path << " errno=" << errno;
        }
        else
        {
            LOGT("networkrollback") << "WriteSysctl: ENOENT path=" << path << " (skipped)";
        }
        return errno == ENOENT ? true : false;
    }

    const size_t  need = value.size();
    const ssize_t n    = ::write(fd, value.c_str(), need);

    ::close(fd);

    if (n != static_cast<ssize_t>(need))
    {
        LOGE("networkrollback") << "WriteSysctl: short write path=" << path << " need=" << need << " wrote=" << n;
        return false;
    }
    LOGD("networkrollback") << "WriteSysctl: ok key=" << dotted;
    return true;
}

std::vector<std::string> NetworkRollback::ListIpv6ConfIfaces()
{
    LOGT("networkrollback") << "ListIpv6ConfIfaces: begin";
    std::vector<std::string> names;

    DIR *d = ::opendir("/proc/sys/net/ipv6/conf");
    if (!d)
    {
        LOGW("networkrollback") << "ListIpv6ConfIfaces: opendir failed errno=" << errno;
        return names;
    }

    while (dirent *e = ::readdir(d))
    {
        if (e->d_name[0] == '.')
        {
            continue;
        }
        names.emplace_back(e->d_name);
    }

    ::closedir(d);
    LOGD("networkrollback") << "ListIpv6ConfIfaces: count=" << names.size();
    return names;
}

std::string NetworkRollback::NftList(const std::string &list_cmd)
{
    LOGT("networkrollback") << "NftList: cmd='" << list_cmd << "'";
    nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
    {
        LOGE("networkrollback") << "NftList: nft_ctx_new failed";
        return {};
    }

    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);

    int rc = nft_run_cmd_from_buffer(ctx, list_cmd.c_str());
    if (rc != 0)
    {
        LOGW("networkrollback") << "NftList: rc=" << rc << " (returning empty)";
        nft_ctx_free(ctx);
        return {};
    }

    const char  *buf = nft_ctx_get_output_buffer(ctx);
    std::string  out = buf ? std::string(buf) : std::string();

    nft_ctx_free(ctx);
    LOGD("networkrollback") << "NftList: bytes=" << out.size();
    return out;
}

bool NetworkRollback::NftRun(const std::string &script)
{
    LOGT("networkrollback") << "NftRun: script (" << script.size() << " bytes)";
    nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
    {
        LOGE("networkrollback") << "NftRun: nft_ctx_new failed";
        return false;
    }

    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);

    int rc = nft_run_cmd_from_buffer(ctx, script.c_str());
    if (rc != 0)
    {
        const char *err = nft_ctx_get_error_buffer(ctx);

        std::string e = err ? std::string(err) : std::string();
        std::string s = script;

        std::transform(e.begin(),
                       e.end(),
                       e.begin(),
                       [](unsigned char c)
                       {
                           return static_cast<char>(std::tolower(c));
                       });
        std::transform(s.begin(),
                       s.end(),
                       s.begin(),
                       [](unsigned char c)
                       {
                           return static_cast<char>(std::tolower(c));
                       });

        const bool benign_delete =
            (s.find("delete ") != std::string::npos) &&
            (e.find("no such file or directory") != std::string::npos);

        if (!benign_delete)
        {
            LOGE("networkrollback") << "NftRun: rc=" << rc << " err=" << (err ? err : "(none)");
        }
        else
        {
            LOGD("networkrollback") << "NftRun: benign delete error rc=" << rc;
        }

        nft_ctx_free(ctx);
        return benign_delete;
    }

    nft_ctx_free(ctx);
    LOGD("networkrollback") << "NftRun: ok";
    return true;
}

NetworkRollback::NetworkRollback()
{
    LOGI("networkrollback") << "Ctor: snapshot sysctls and nftables";
    ip_forward_prev_  = ReadSysctl("net.ipv4.ip_forward");
    ip6_forward_prev_ = ReadSysctl("net.ipv6.conf.all.forwarding");

    for (const std::string &iface : ListIpv6ConfIfaces())
    {
        const std::string key = "net.ipv6.conf." + iface + ".accept_ra";
        if (auto v = ReadSysctl(key))
        {
            accept_ra_prev_.emplace(iface, *v);
        }
    }

    nft_ip_nat_prev_    = NftList("list table ip flowforge_nat");
    nft_ip6_nat_prev_   = NftList("list table ip6 flowforge_nat");
    nft_inet_post_prev_ = NftList("list table inet flowforge_post");
    nft_inet_fw_prev_   = NftList("list table inet flowforge_fw");

    ok_ = true;

    ip6_accept_ra_all_prev_  = ReadSysctl("net.ipv6.conf.all.accept_ra");
    ip6_accept_ra_def_prev_  = ReadSysctl("net.ipv6.conf.default.accept_ra");

    ip4_acc_redir_all_prev_  = ReadSysctl("net.ipv4.conf.all.accept_redirects");
    ip4_acc_redir_def_prev_  = ReadSysctl("net.ipv4.conf.default.accept_redirects");
    ip4_send_redir_all_prev_ = ReadSysctl("net.ipv4.conf.all.send_redirects");
    ip4_send_redir_def_prev_ = ReadSysctl("net.ipv4.conf.default.send_redirects");

    ip6_acc_redir_all_prev_  = ReadSysctl("net.ipv6.conf.all.accept_redirects");
    ip6_acc_redir_def_prev_  = ReadSysctl("net.ipv6.conf.default.accept_redirects");

    ip4_accept_local_all_prev_ = ReadSysctl("net.ipv4.conf.all.accept_local");
    ip4_accept_local_def_prev_ = ReadSysctl("net.ipv4.conf.default.accept_local");

    LOGD("networkrollback") << "Ctor: snapshot complete";
}

NetworkRollback::~NetworkRollback()
{
    LOGI("networkrollback") << "Dtor: revert baseline begin";
    Restore_();
    LOGI("networkrollback") << "Dtor: revert baseline done";
}

bool NetworkRollback::Ok() const
{
    LOGT("networkrollback") << "Ok: " << (ok_ ? "true" : "false");
    return ok_;
}

void NetworkRollback::Restore_() noexcept
{
    LOGD("networkrollback") << "Restore_: begin";

    if (ip_forward_prev_)
    {
        (void) WriteSysctl("net.ipv4.ip_forward", *ip_forward_prev_);
    }
    if (ip6_forward_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.all.forwarding", *ip6_forward_prev_);
    }
    for (const auto &kv : accept_ra_prev_)
    {
        const std::string key = "net.ipv6.conf." + kv.first + ".accept_ra";
        (void) WriteSysctl(key, kv.second);
    }

    if (ip6_accept_ra_all_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.all.accept_ra", *ip6_accept_ra_all_prev_);
    }
    if (ip6_accept_ra_def_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.default.accept_ra", *ip6_accept_ra_def_prev_);
    }

    if (ip4_acc_redir_all_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.all.accept_redirects", *ip4_acc_redir_all_prev_);
    }
    if (ip4_acc_redir_def_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.default.accept_redirects", *ip4_acc_redir_def_prev_);
    }
    if (ip4_send_redir_all_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.all.send_redirects", *ip4_send_redir_all_prev_);
    }
    if (ip4_send_redir_def_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.default.send_redirects", *ip4_send_redir_def_prev_);
    }

    if (ip6_acc_redir_all_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.all.accept_redirects", *ip6_acc_redir_all_prev_);
    }
    if (ip6_acc_redir_def_prev_)
    {
        (void) WriteSysctl("net.ipv6.conf.default.accept_redirects", *ip6_acc_redir_def_prev_);
    }

    if (ip4_accept_local_all_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.all.accept_local", *ip4_accept_local_all_prev_);
    }
    if (ip4_accept_local_def_prev_)
    {
        (void) WriteSysctl("net.ipv4.conf.default.accept_local", *ip4_accept_local_def_prev_);
    }

    (void) NftRun("delete table inet flowforge_post");
    if (!nft_inet_post_prev_.empty())
    {
        (void) NftRun(nft_inet_post_prev_);
    }

    (void) NftRun("delete table ip flowforge_nat");
    if (!nft_ip_nat_prev_.empty())
    {
        (void) NftRun(nft_ip_nat_prev_);
    }

    (void) NftRun("delete table ip6 flowforge_nat");
    if (!nft_ip6_nat_prev_.empty())
    {
        (void) NftRun(nft_ip6_nat_prev_);
    }

    (void) NftRun("delete table inet flowforge_fw");
    if (!nft_inet_fw_prev_.empty())
    {
        (void) NftRun(nft_inet_fw_prev_);
    }

    LOGD("networkrollback") << "Restore_: done";
}
