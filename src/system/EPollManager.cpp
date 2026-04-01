#include "EPollManager.hpp"
#include "EPollBinding.hpp"
#include <csignal>
#include <fcntl.h>
#include <sys/signalfd.h>
#include <system_error>
#include <unistd.h>

template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::System {

EPollManager::~EPollManager() {

  if (!m_epoll_fd) {
    return;
  }

  for (auto &[file_descriptor, binding] : m_subscriptions) {
    if (binding != nullptr) {
      epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr);
      binding->m_manager = nullptr;
      binding->m_active  = false;
    }
  }
}

Result<EPollManager> EPollManager::create() {
  int raw_ep_fd = ::epoll_create1(EPOLL_CLOEXEC);

  if (raw_ep_fd == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  auto ep_fd = FD::adopt(raw_ep_fd);

  if (!ep_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  // --- INTERNAL SIGNAL SETUP ---
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);

  // Block signals so they don't terminate the process immediately
  if (::sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  // Create the signalfd
  int raw_sig = ::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (raw_sig == -1) {
    // If we return here, ep_fd's destructor runs and closes the epoll FD.
    return std::unexpected(std::error_code(errno, std::system_category()));
  }
  auto sig_fd = FD::adopt(raw_sig);
  if (!sig_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  // 4. Register signalfd with epoll
  struct epoll_event event{};
  event.events   = EPOLLIN;
  // We explicitly set ptr to nullptr so the 'else' block in poll() is triggered
  event.data.ptr = nullptr;
  if (::epoll_ctl(ep_fd->get(), EPOLL_CTL_ADD, sig_fd->get(), &event) == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  return EPollManager(std::move(*ep_fd), std::move(*sig_fd));
}

Result<void> EPollManager::subscribe(int file_descriptor, EPollBinding *binding, uint32_t events) {
  if (binding == nullptr || file_descriptor < 0) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  // Force Non-Blocking for Edge-Triggered mode
  // Check if flags contain EPOLLET and no a unsigned int with value 0
  if ((events & EPOLLET) != 0U) {
    const int current_flags = fcntl(file_descriptor, F_GETFL, 0);
    if (current_flags == -1) {
      return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Check if O_NONBLOCK is missing using explicit bitwise comparison
    if ((static_cast<uint32_t>(current_flags) & O_NONBLOCK) == 0U) {
      if (fcntl(file_descriptor, F_SETFL, current_flags | O_NONBLOCK) == -1) {
        return std::unexpected(std::error_code(errno, std::system_category()));
      }
    }
  }

  struct epoll_event event{};
  event.events   = events;
  event.data.ptr = binding; // The kernel now holds this raw address

  if (!m_epoll_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  int ret = epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_ADD, file_descriptor, &event);

  if (ret == -1 && errno == EEXIST) {
    ret = epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_MOD, file_descriptor, &event);
  }

  if (ret == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  binding->m_active                = true;
  m_subscriptions[file_descriptor] = binding;
  return {};
}

Result<void> EPollManager::unsubscribe(int file_descriptor, EPollBinding *binding) {
  if (binding == nullptr) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  binding->m_active = false;

  if (!m_epoll_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  if (epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr) == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  m_subscriptions.erase(file_descriptor);
  return {};
}

Result<size_t> EPollManager::poll(int timeout_ms) {
  struct epoll_event local_events[MAX_EVENTS]; // 64
  size_t             total_processed = 0;

  if (!m_epoll_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  for (int i = 0; i < MAX_RETRIES; ++i) {
    int nfds = epoll_wait(m_epoll_fd.get(), local_events, MAX_EVENTS, timeout_ms);

    if (nfds < 0) {
      if (errno == EINTR) {
        continue; // Just retry the wait
      }

      return std::unexpected(std::error_code(errno, std::system_category()));
    }

    if (nfds == 0) {
      break; // Kernel is empty
    }

    // Dispatch the 64 events
    for (int j = 0; j < nfds; ++j) {
      auto *binding = static_cast<EPollBinding *>(local_events[j].data.ptr);
      if (binding != nullptr) {
        binding->dispatch(local_events[j].events);
        total_processed++;
      }

      else {
        // If it's NOT a binding, it MUST be our internal signalfd.
        // We deal with it right here. No extra "if" required for sockets.
        if (!m_sig_fd) {
          return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        }

        struct signalfd_siginfo fdsi;
        if (read(m_sig_fd.get(), &fdsi, sizeof(fdsi)) > 0) {
          m_running = false;
        }
      }
    }

    // If we got less than 64, we've cleared the "backlog"
    if (static_cast<size_t>(nfds) < MAX_EVENTS) {
      break;
    }

    // If we're looping again to drain more, don't "halt" the game anymore
    timeout_ms = 0;
  }
  return total_processed;
}

} // namespace OdinSight::System
