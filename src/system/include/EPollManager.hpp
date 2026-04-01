#pragma once

#include <expected>
#include <sys/epoll.h>
#include <sys/types.h>
#include <system_error>
#include <unordered_map>

#include "system/FD.hpp"

namespace OdinSight::System {

// Forward declaration
class EPollBinding;

class EPollManager {
  friend class EPollBinding;

private:
  /** --- Private Type Aliases & Constants --- **/
  template <typename T> using Result = std::expected<T, std::error_code>;

  using SubscriptionMap = std::unordered_map<int, EPollBinding *>;

  static constexpr int MAX_EVENTS  = 64;
  static constexpr int MAX_RETRIES = 15;

  /** --- Members (State) --- **/
  FD              m_epoll_fd;
  FD              m_sig_fd;
  SubscriptionMap m_subscriptions;
  bool            m_running{true};

  /** --- Internal Interface (Called by EPollBinding) --- **/
  explicit EPollManager(FD &&epoll_fd, FD &&sig_fd)
      : m_epoll_fd(std::move(epoll_fd)), m_sig_fd(std::move(sig_fd)) {}

  [[nodiscard]] Result<void> subscribe(int file_descriptor, EPollBinding *binding, uint32_t events);
  [[nodiscard]] Result<void> unsubscribe(int file_descriptor, EPollBinding *binding);

public:
  /** --- Lifecycle --- **/
  EPollManager() = delete;
  ~EPollManager();

  // Rule of Five: No copying, Move allowed
  EPollManager(const EPollManager &)            = delete;
  EPollManager &operator=(const EPollManager &) = delete;

  EPollManager(EPollManager &&) noexcept            = default;
  EPollManager &operator=(EPollManager &&) noexcept = default;

  bool isRunning() const { return m_running; }

  /** --- Factory & Core Logic --- **/
  static Result<EPollManager> create();

  /**
   * @brief Wait for events on registered file descriptors.
   * @return Number of events processed, or an EPollError.
   */
  Result<size_t> poll(int timeout_ms = -1);
};

} // namespace OdinSight::System
