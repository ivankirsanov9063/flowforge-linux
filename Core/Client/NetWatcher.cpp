#include "NetWatcher.hpp"
#include "Core/Logger.hpp"

#include <thread>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <stop_token>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/cache.h>
#include <netlink/handlers.h>
#include <linux/rtnetlink.h>

namespace
{
    static int OnNlValid(struct nl_msg* /*msg*/, void* arg)
    {
        auto* self = reinterpret_cast<NetWatcher*>(arg);
        if (self != nullptr)
        {
            self->Kick();
        }
        return NL_OK;
    }

    static void DrainEventFd(int fd)
    {
        std::uint64_t val = 0;
        while (true)
        {
            ssize_t rc = ::read(fd, &val, sizeof(val));
            if (rc < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                if (errno == EINTR) continue;
                return;
            }
            if (rc == 0) return;
        }
    }
}

NetWatcher::NetWatcher(ReapplyFn reapply, std::chrono::milliseconds debounce)
        : reapply_(std::move(reapply))
        , debounce_(debounce.count() > 0 ? debounce : std::chrono::milliseconds(2000))
{
    next_earliest_apply_ = std::chrono::steady_clock::now();
    Start_();
}

NetWatcher::~NetWatcher()
{
    Shutdown_();
}

bool NetWatcher::IsRunning() const
{
    return thread_.joinable();
}

void NetWatcher::SignalEventFd_(int fd)
{
    if (fd < 0) return;
    std::uint64_t one = 1;
    (void)::write(fd, &one, sizeof(one)); // неблокирующая запись; overflow игнорируем
}

void NetWatcher::Kick()
{
    SignalEventFd_(kick_fd_);
}

void NetWatcher::Stop()
{
    Shutdown_();
}

void NetWatcher::Start_()
{
    if (thread_.joinable()) return;

    stop_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    kick_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (stop_fd_ < 0 || kick_fd_ < 0)
    {
        LOGE("netwatcher") << "eventfd create failed";
        if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
        if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
        return;
    }

    nl_sock_ = nl_socket_alloc();
    if (!nl_sock_)
    {
        LOGE("netwatcher") << "nl_socket_alloc failed";
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    if (nl_connect(nl_sock_, NETLINK_ROUTE) != 0)
    {
        LOGE("netwatcher") << "nl_connect(NETLINK_ROUTE) failed";
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    int rc = nl_socket_add_memberships(nl_sock_,
                                       RTNLGRP_LINK,
                                       RTNLGRP_IPV4_IFADDR,
                                       RTNLGRP_IPV6_IFADDR,
                                       RTNLGRP_IPV4_ROUTE,
                                       RTNLGRP_IPV6_ROUTE,
                                       0);
    if (rc != 0)
    {
        LOGE("netwatcher") << "nl_socket_add_memberships rc=" << rc;
        nl_close(nl_sock_);
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
        ::close(stop_fd_); ::close(kick_fd_);
        stop_fd_ = kick_fd_ = -1;
        return;
    }

    nl_socket_disable_seq_check(nl_sock_);
    nl_socket_modify_cb(nl_sock_, NL_CB_VALID, NL_CB_CUSTOM, &OnNlValid, this);
    nl_socket_set_nonblocking(nl_sock_);
    nl_fd_ = nl_socket_get_fd(nl_sock_);

    thread_ = std::jthread([this](std::stop_token st)
                           {
                                  LOGI("netwatcher") << "Thread started";
                                  pollfd pfds[3]{};
                                  bool stop_now = false;

                                  while (true)
                                  {
                                      if (st.stop_requested()) { stop_now = true; break; }
                                      pfds[0] = { stop_fd_, POLLIN, 0 };
                                      pfds[1] = { kick_fd_, POLLIN, 0 };
                                      pfds[2] = { nl_fd_,   POLLIN, 0 };

                                      int rc2 = ::poll(pfds, 3, -1);
                                      if (rc2 < 0)
                                      {
                                          if (errno == EINTR) continue;
                                          LOGE("netwatcher") << "poll failed";
                                          break;
                                      }

                                      if (pfds[0].revents & POLLIN)
                                      {
                                          DrainEventFd(stop_fd_);
                                          LOGD("netwatcher") << "Stop signal";
                                          break;
                                      }

                                      if (pfds[2].revents & POLLIN)
                                      {
                                          // Коллбек OnNlValid вызовет Kick()
                                          (void)nl_recvmsgs_default(nl_sock_);
                                      }

                                      if (pfds[1].revents & POLLIN)
                                      {
                                          // собираем "kick", время последнего события и помечаем pending
                                          DrainEventFd(kick_fd_);

                                          kick_pending_.store(true, std::memory_order_relaxed);
                                          auto last_event = std::chrono::steady_clock::now();

                                          // 1) дебаунс: ждём ещё события до окна debounce_
                                          while (!st.stop_requested())
                                          {
                                              const auto elapsed = std::chrono::steady_clock::now() - last_event;
                                              if (elapsed >= debounce_) break;

                                              const int timeout_ms = static_cast<int>(
                                                      std::chrono::duration_cast<std::chrono::milliseconds>(
                                                              debounce_ - elapsed).count()
                                              );

                                              pollfd p2[2] = {
                                                      {stop_fd_, POLLIN, 0},
                                                      {kick_fd_, POLLIN, 0}
                                              };
                                              int rc3 = ::poll(p2, 2, timeout_ms);
                                              if (rc3 < 0)
                                              {
                                                  if (errno == EINTR) continue;
                                                  LOGE("netwatcher") << "poll(inner) failed";
                                                  break;
                                              }
                                              if (p2[0].revents & POLLIN)
                                              {
                                                  DrainEventFd(stop_fd_);
                                                  LOGD("netwatcher") << "Stop during debounce";
                                                  stop_now = true;
                                                  break;
                                              }
                                              if (p2[1].revents & POLLIN)
                                              {
                                                  // ещё один kick — коалесцируем
                                                  DrainEventFd(kick_fd_);
                                                  kick_pending_.store(true, std::memory_order_relaxed);
                                                  last_event = std::chrono::steady_clock::now();
                                                  continue;
                                              }

                                              if (rc3 == 0) break; // тишина до конца окна
                                          }

                                          if (stop_now) break;

                                          // 2) если ранний backoff активен — ждём его окончания, параллельно коалесцируя события
                                          while (!st.stop_requested())
                                          {
                                              auto now = std::chrono::steady_clock::now();
                                              if (now >= next_earliest_apply_) break;

                                              auto to_wait = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      next_earliest_apply_ - now).count();
                                              if (to_wait <= 0) break;

                                              pollfd p2[2] = {
                                                      {stop_fd_, POLLIN, 0},
                                                      {kick_fd_, POLLIN, 0}
                                              };
                                              int rc4 = ::poll(p2, 2, (int) to_wait);
                                              if (rc4 < 0)
                                              {
                                                  if (errno == EINTR) continue;
                                                  LOGE("netwatcher") << "poll(backoff) failed";
                                                  break;
                                              }
                                              if (p2[0].revents & POLLIN)
                                              {
                                                  DrainEventFd(stop_fd_);
                                                  stop_now = true;
                                                  break;
                                              }
                                              if (p2[1].revents & POLLIN)
                                              {
                                                  DrainEventFd(kick_fd_);
                                                  kick_pending_.store(true, std::memory_order_relaxed);
                                                  // не двигаем next_earliest_apply_, просто продолжаем ждать
                                              }
                                              if (rc4 == 0) break; // backoff истёк
                                          }
                                          if (stop_now) break;

                                          // 3) один reapply, не реэнтерабельно
                                          if (apply_in_progress_.exchange(true, std::memory_order_acq_rel))
                                          {
                                              // уже идёт — ничего не делаем, события склеены флагом kick_pending_
                                              continue;
                                          }

                                          bool success = true;
                                          bool had_pending_after = false;

                                          try
                                          {
                                              LOGI("netwatcher") << "Reapply begin";
                                              reapply_();
                                              LOGI("netwatcher") << "Reapply end";
                                          }
                                          catch (const std::exception &e)
                                          {
                                              LOGE("netwatcher") << "Reapply exception: " << e.what();
                                              success = false;
                                          }
                                          catch (...)
                                          {
                                              LOGE("netwatcher") << "Reapply unknown exception";
                                              success = false;
                                          }
                                          // во время reapply могли прийти новые события — сливаем и фиксируем флаг
                                          DrainEventFd(kick_fd_);
                                          had_pending_after = kick_pending_.exchange(false, std::memory_order_acq_rel);
                                          apply_in_progress_.store(false, std::memory_order_release);

                                          // 4) обновляем backoff
                                          if (!success || had_pending_after)
                                          {
                                              // удвоение до max
                                              auto next = backoff_cur_ * 2;
                                              if (next > backoff_max_) next = backoff_max_;
                                              backoff_cur_ = next;
                                          }
                                          else {
                                              // плавный спад к min
                                              if (backoff_cur_ > backoff_min_)
                                              {
                                                  backoff_cur_ = std::chrono::milliseconds(
                                                          backoff_cur_.count() * 2 / 3);
                                                  if (backoff_cur_ < backoff_min_) backoff_cur_ = backoff_min_;
                                              }
                                          }
                                          next_earliest_apply_ = std::chrono::steady_clock::now() + backoff_cur_;
                                      }
                                  }

                                  LOGI("netwatcher") << "Thread exiting";
                              });

    LOGD("netwatcher") << "Armed (debounce=" << debounce_.count() << " ms)";
}

void NetWatcher::Shutdown_()
{
    if (!thread_.joinable())
    {
        if (nl_sock_ != nullptr)
        {
            nl_close(nl_sock_);
            nl_socket_free(nl_sock_);
            nl_sock_ = nullptr;
        }
        if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
        if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
        nl_fd_ = -1;
        return;
    }

    if (thread_.joinable())
    {
        thread_.request_stop();
        SignalEventFd_(stop_fd_);
        thread_.join();
    }

    if (nl_sock_ != nullptr)
    {
        nl_close(nl_sock_);
        nl_socket_free(nl_sock_);
        nl_sock_ = nullptr;
    }

    if (stop_fd_ >= 0) { ::close(stop_fd_); stop_fd_ = -1; }
    if (kick_fd_ >= 0) { ::close(kick_fd_); kick_fd_ = -1; }
    nl_fd_ = -1;

    LOGD("netwatcher") << "Stopped";
}
