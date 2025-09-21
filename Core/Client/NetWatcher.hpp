#pragma once

// NetWatcher.hpp — Linux: отслеживает изменения link/addr/route через netlink
// и коалесцирует события (debounce), вызывая callback reapply().

#include <functional>
#include <chrono>
#include <thread>
#include <stop_token>

class NetWatcher
{
public:
    using ReapplyFn = std::function<void()>;

    explicit NetWatcher(ReapplyFn reapply,
                        std::chrono::milliseconds debounce = std::chrono::milliseconds(2000));

    ~NetWatcher();

    NetWatcher(const NetWatcher&)            = delete;
    NetWatcher& operator=(const NetWatcher&) = delete;
    NetWatcher(NetWatcher&&)                 = delete;
    NetWatcher& operator=(NetWatcher&&)      = delete;

    // Сообщить вотчеру «пересчитать» (коалесцируется по debounce)
    void Kick();

    // Остановить вотчер и освободить ресурсы
    void Stop();

    // Идёт ли фоновой мониторинг
    bool IsRunning() const;

private:
    void Start_();
    void Shutdown_();
    void ThreadLoop_(std::stop_token st);
    void SignalEventFd_(int fd);

private:
    // public контракт
    ReapplyFn reapply_;
    std::chrono::milliseconds debounce_;
    // backoff & state
    std::chrono::milliseconds backoff_min_{std::chrono::milliseconds(2000)};
    std::chrono::milliseconds backoff_max_{std::chrono::milliseconds(15000)};
    std::chrono::milliseconds backoff_cur_{backoff_min_};
    std::chrono::steady_clock::time_point next_earliest_apply_{};
    std::atomic<bool> apply_in_progress_{false};
    std::atomic<bool> kick_pending_{false};

    // платформа (Linux)
    struct nl_sock* nl_sock_ = nullptr;
    int nl_fd_   = -1;
    int stop_fd_ = -1;
    int kick_fd_ = -1;
    std::jthread thread_;
};
