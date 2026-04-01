#include "EbpfManager.hpp"
#include "EPollManager.hpp"
#include "master.skel.h"
#include <bpf/libbpf.h>
#include <cstdint>
#include <memory>
#include <stdint.h>
#include <sys/epoll.h>

template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::Daemon::Monitor::Kernel {

Result<std::unique_ptr<EbpfManager>> EbpfManager::create() {
  auto instance = std::unique_ptr<EbpfManager>(new EbpfManager());

  instance->m_modules = {};

  master *skel = master__open();
  if (skel == nullptr) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  instance->m_master_skel.reset(skel);

  // 2. Load (Integer: Check negative + return value)
  if (int err = master__load(instance->m_master_skel.get()); err < 0) {
    return std::unexpected(std::error_code(-err, std::system_category()));
  }

  // 3. Map Identification (Null check FIRST)
  instance->m_shared_rb_map = instance->m_master_skel->maps.rb;

  int raw_fd = bpf_map__fd(instance->m_shared_rb_map);
  if (raw_fd < 0) {
    return std::unexpected(std::error_code(-raw_fd, std::system_category()));
  }

  auto shared_rb_fd = FD::adopt(raw_fd);
  if (!shared_rb_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  instance->m_shared_rb_fd = std::move(shared_rb_fd.value());

  auto *ring_buffer =
      ring_buffer__new(instance->m_shared_rb_fd.get(), handleEvent, instance.get(), nullptr);
  if (ring_buffer == nullptr) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  instance->m_ringbuf_reader.reset(ring_buffer);

  // Set this ONLY when everything is guaranteed to work
  return instance;
}

int EbpfManager::handleEvent(void *ctx, void *data, size_t data_sz) {
  auto *self = static_cast<EbpfManager *>(ctx);
  if (self == nullptr || data == nullptr || data_sz != sizeof(ebpf_event)) {
    return -1;
  }

  const auto *event = static_cast<const ebpf_event *>(data);
  size_t      index = static_cast<size_t>(event->module_id);

  if (index >= self->m_modules.size()) {
    return 0;
  }

  auto &mod = self->m_modules[index];
  if (mod) {

    mod->processEvent(event, data_sz);
  }
  return 0;
}

Result<void> EbpfManager::addModule(std::unique_ptr<IEbpfModule> mod) {
  // 1. Basic Parameter Validation
  if (mod == nullptr) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  // 2. Manager State Validation
  if (!isActive() || !isReady()) {
    return std::unexpected(std::make_error_code(std::errc::not_connected));
  }

  // 3. Slot Availability Check (DO THIS BEFORE ATTACHING TO KERNEL)
  size_t index = static_cast<size_t>(mod->getId());
  if (index >= m_modules.size()) {
    return std::unexpected(std::make_error_code(std::errc::result_out_of_range));
  }

  if (m_modules[index] != nullptr) {
    return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
  }

  // 4. Kernel Lifecycle
  int shared_fd = m_shared_rb_fd.get();

  if (auto res = mod->open(); !res) {
    return res;
  }
  if (auto res = mod->load(shared_fd); !res) {
    return res;
  }
  if (auto res = mod->attach(); !res) {
    return res;
  }

  // 5. Final Commitment
  m_modules[index] = std::move(mod);
  return {};
}

bool EbpfManager::createEPollBinding(EPollManager &manager) {
  // Safety check: don't create if no ring buffer, no initilization and already
  // have a binding
  if (m_ringbuf_reader == nullptr || m_binding != nullptr || !isActive()) {
    return false;
  }

  int poll_fd = ring_buffer__epoll_fd(m_ringbuf_reader.get());
  if (poll_fd < 0) {
    return false; // Libbpf couldn't provide a pollable file descriptor
  }

  auto on_event = [](void *ctx, uint32_t events) {
    auto *self = static_cast<EbpfManager *>(ctx);
    // We only care about data being ready (EPOLLIN)
    // or the buffer being closed (ERR/HUP)
    if (self && self->m_ringbuf_reader && (events & (EPOLLIN | EPOLLERR | EPOLLHUP))) {
      // consume() is more efficient than poll() when we already
      // know data is there. It drains the buffer and calls handleEvent.
      ring_buffer__consume(self->m_ringbuf_reader.get());
    }
  };

  m_binding = std::make_unique<EPollBinding>(&manager, poll_fd, this, on_event);

  if (!m_binding->subscribe(EPOLLIN | EPOLLET)) {

    m_binding.reset();
    return false;
  }

  return true;
}

} // namespace OdinSight::Daemon::Monitor::Kernel
