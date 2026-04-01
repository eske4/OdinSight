#include "SyscallModule.hpp"
#include "print_test.skel.h"
#include <iostream>

template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::Daemon::Monitor::Kernel::Modules {

// Constructor body (initialization of m_skel, etc.)

Result<void> SyscallModule::open() {
  m_skel.reset(print_test__open());
  if (!m_skel) {
    // Return the specific reason open failed (e.g., file not found)
    return std::unexpected(std::error_code(errno, std::system_category()));
  }
  return {}; // Success
}

Result<void> SyscallModule::load(int shared_rb_fd) {
  if (!m_skel) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  // CRITICAL: Tell this module to use the shared Ring Buffer FD
  // instead of creating its own internal 'rb' map.
  if (shared_rb_fd >= 0) {
    if (int err = bpf_map__reuse_fd(m_skel->maps.rb, shared_rb_fd); err < 0) {
      return std::unexpected(std::error_code(-err, std::system_category()));
    }
  }

  // 2. Load into Kernel
  if (int err = print_test__load(m_skel.get()); err < 0) {
    return std::unexpected(std::error_code(-err, std::system_category()));
  }

  return {};
}

Result<void> SyscallModule::attach() {
  if (!m_skel) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  if (int err = print_test__attach(m_skel.get()); err < 0) {
    return std::unexpected(std::error_code(-err, std::system_category()));
  }

  return {}; // Success
}

void SyscallModule::processEvent(const ebpf_event *event, size_t size) {
  // Logic to handle the specific event type for this module
  std::cout << "[" << getName() << "] Event Type: " << event->event_type << event->timestamp
            << std::endl;
}

} // namespace OdinSight::Daemon::Monitor::Kernel::Modules
