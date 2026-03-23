#pragma once

#include <stdint.h>
#include <sys/epoll.h>

// Forward declare to avoid header loops
namespace ACName::System {

class EPollManager;

class EPollBinding {
  friend class EPollManager;

private:
  static constexpr uint64_t MAGIC_CONSTANT = 0x5459524553454355;
  using Handler = void (*)(void *context, uint32_t events);

  uint64_t m_instance_magic = MAGIC_CONSTANT;
  EPollManager *m_manager = nullptr; // Initialize!
  int m_fd = -1;                     // Initialize!
  void *m_ctx = nullptr;
  Handler m_on_event = nullptr;
  bool m_active = false;
  uint32_t m_event_mask = 0;

  void invalidate();

public:
  // Updated Constructor to actually receive the state
  EPollBinding(EPollManager *manager, int file_descriptor, void *ctx,
               Handler handler);
  ~EPollBinding();

  // Move Constructor: MUST transfer the manager and FD
  EPollBinding(EPollBinding &&other) noexcept;

  // Disable copy
  EPollBinding(const EPollBinding &) = delete;
  EPollBinding &operator=(const EPollBinding &) = delete;

  // Standard Move Assignment (Optional but recommended)
  EPollBinding &operator=(EPollBinding &&other) noexcept;

  [[nodiscard]] bool subscribe(uint32_t events);
  [[nodiscard]] bool unsubscribe();

  [[nodiscard]] bool isValid() const noexcept {
    return (m_instance_magic == MAGIC_CONSTANT) && (m_on_event != nullptr) &&
           m_active;
  }

  [[nodiscard]] bool isActive() const { return m_active; }

  void dispatch(uint32_t incoming_events) const {
    // We care if:
    // 1. One of our requested bits is set
    // 2. OR a system error bit is set (HUP/ERR/RDHUP)
    const uint32_t critical_bits =
        incoming_events & (m_event_mask | EPOLLERR | EPOLLHUP);

    if (isValid() && critical_bits != 0U) {
      m_on_event(m_ctx, incoming_events);
    }
  }
};
} // namespace ACName::System
