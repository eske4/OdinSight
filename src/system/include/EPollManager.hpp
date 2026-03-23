#pragma once

#include "system/FD.hpp"
#include <expected>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

namespace ACName::System {

enum class EPollError : uint8_t {
  Interrupted = 0,
  SysCallFailed = 1,
  Timeout = 2,
  InvalidFD = 3
};

// Forward declaration!
class EPollBinding;

class EPollManager {
  friend class EPollBinding;

private:
  static constexpr int MAX_EVENTS = 64;
  static constexpr int MAX_RETRIES = 15;

  FD m_epoll_fd;
  std::unordered_map<int, EPollBinding *> m_subscriptions;
  explicit EPollManager(FD &&file_descriptor)
      : m_epoll_fd(std::move(file_descriptor)) {}

  [[nodiscard]] bool subscribe(int file_descriptor, EPollBinding *binding,
                               uint32_t events);
  [[nodiscard]] bool unsubscribe(int file_descriptor, EPollBinding *binding);

public:
  ~EPollManager();

  // Disable copying
  EPollManager(const EPollManager &) = delete;
  EPollManager &operator=(const EPollManager &) = delete;

  // Allow moving
  EPollManager(EPollManager &&) noexcept = default;

  static std::expected<EPollManager, EPollError> create();
  std::expected<size_t, EPollError> poll(int timeout_ms = -1);
};

} // namespace ACName::System
