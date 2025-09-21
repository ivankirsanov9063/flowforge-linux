#include "PluginWrapper.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <functional>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <boost/json/object.hpp>

#include <unistd.h>
#include <dlfcn.h>

namespace PluginWrapper
{
    void* Sym(void       *h,
                     const char *name)
    {
        void* ptr = nullptr;
        ptr = dlsym(h, name);
        if (!ptr)
        {
            std::cerr << "Error in get symbol from plugin\n";
        }
        return ptr;
    }

    Plugin Load(const std::string &path)
    {
        Plugin plugin;
        plugin.handle = dlopen(path.c_str(),
                               RTLD_NOW | RTLD_LOCAL);

        if (!plugin.handle)
        {
            std::cerr << "Error in load plugin\n";
            return plugin;
        }

        plugin.Client_Connect =
                reinterpret_cast<Client_Connect_t>(
                        Sym(plugin.handle, "Client_Connect"));

        plugin.Client_Disconnect =
                reinterpret_cast<Client_Disconnect_t>(
                        Sym(plugin.handle, "Client_Disconnect"));

        plugin.Client_Serve =
                reinterpret_cast<Client_Serve_t>(
                        Sym(plugin.handle, "Client_Serve"));

        plugin.Server_Bind =
                reinterpret_cast<Server_Bind_t>(
                        Sym(plugin.handle, "Server_Bind"));

        plugin.Server_Serve =
                reinterpret_cast<Server_Serve_t>(
                        Sym(plugin.handle, "Server_Serve"));

        const bool fine =
                plugin.Client_Connect &&
                plugin.Client_Disconnect &&
                plugin.Client_Serve &&
                plugin.Server_Bind &&
                plugin.Server_Serve;

        if (!fine)
        {
            std::cerr << "Plugin missing required symbols\n";
            dlclose(plugin.handle);
            plugin.handle = nullptr;
        }

        return plugin;
    }

    void Unload(const Plugin &plugin)
    {
        if (plugin.handle)
        {
            dlclose(plugin.handle);
        }
    }

    bool Client_Connect(const Plugin     &plugin,
                        boost::json::object& config) noexcept
    {
        return plugin.Client_Connect(config);
    }

    void Client_Disconnect(const Plugin &plugin) noexcept
    {
        plugin.Client_Disconnect();
    }

    int Client_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *,
                                                 std::size_t)> &receive_from_net,
                     const std::function<ssize_t(const std::uint8_t *,
                                                 std::size_t)> &send_to_net,
                     const volatile sig_atomic_t *working_flag) noexcept
    {
        return plugin.Client_Serve(receive_from_net,
            send_to_net,
            working_flag);
    }

    bool Server_Bind(const Plugin &plugin,
                     boost::json::object& config) noexcept
    {
        return plugin.Server_Bind(config);
    }

    int Server_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *,
                                                 std::size_t)> &receive_from_net,
                     const std::function<ssize_t(const std::uint8_t *,
                                                 std::size_t)> &send_to_net,
                     const volatile sig_atomic_t *working_flag) noexcept
    {
        return plugin.Server_Serve(receive_from_net,
            send_to_net,
            working_flag);
    }
}
