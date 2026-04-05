#include "EbpfManager.hpp"
#include "master.skel.h"
#include <bpf/libbpf.h>
#include <memory>
#include <stdint.h>
#include <sys/epoll.h>

using Error = Odin::Error;

namespace OdinSight::Daemon::Monitor::Kernel {

Odin::Result<std::unique_ptr<EbpfManager>> EbpfManager::create() {
  auto instance = std::unique_ptr<EbpfManager>(new EbpfManager());

  instance->m_modules = {};

  master* skel = master__open();
  if (skel == nullptr) { return std::unexpected(Error::System(name, "master__open", errno)); }

  instance->m_master_skel.reset(skel);

  // 2. Load (Integer: Check negative + return value)
  if (int err = master__load(instance->m_master_skel.get()); err < 0) {
    return std::unexpected(Error::System(name, "master__load", -err));
  }

  // 3. Map Identification (Null check FIRST)
  instance->m_shared_rb_map = instance->m_master_skel->maps.rb;

  int raw_fd = bpf_map__fd(instance->m_shared_rb_map);
  if (raw_fd < 0) { return std::unexpected(Error::System(name, "bpf_map__fd", -raw_fd)); }

  auto shared_rb_fd = FD::adopt(raw_fd);
  if (!shared_rb_fd) {
    return std::unexpected(Error::Logic(name, "FD::adopt", "Failed to adopt map file descriptor"));
  }

  instance->m_shared_rb_fd = std::move(shared_rb_fd.value());

  auto* ring_buffer =
      ring_buffer__new(instance->m_shared_rb_fd.get(), handleEvent, instance.get(), nullptr);
  if (ring_buffer == nullptr) {
    return std::unexpected(Error::System(name, "ring_buffer__new", errno));
  }

  instance->m_ringbuf_reader.reset(ring_buffer);

  // Set this ONLY when everything is guaranteed to work
  return instance;
}

int EbpfManager::handleEvent(void* ctx, void* data, size_t data_sz) {
  auto* self = static_cast<EbpfManager*>(ctx);
  if (self == nullptr || data == nullptr || data_sz != sizeof(ebpf_event)) { return -1; }

  const auto* event = static_cast<const ebpf_event*>(data);
  size_t      index = static_cast<size_t>(event->module_id);

  if (index >= self->m_modules.size()) { return 0; }

  auto& mod = self->m_modules[index];
  if (mod) { mod->processEvent(event, data_sz); }
  return 0;
}

Odin::Result<void> EbpfManager::addModule(std::unique_ptr<IEbpfModule> mod) {
  // 1. Basic Parameter Validation
  if (mod == nullptr) {
    return std::unexpected(Error::Logic(name, "addModule", "Module pointer is null"));
  }

  // 2. Manager State Validation
  if (!isActive() || !isReady()) {
    return std::unexpected(Error::Logic(name, "addModule", "Manager is not in a ready state"));
  }

  // 3. Slot Availability Check (DO THIS BEFORE ATTACHING TO KERNEL)
  size_t index = static_cast<size_t>(mod->getId());
  if (index >= m_modules.size()) {
    return std::unexpected(Error::Logic(name, "addModule", "Module ID out of registered range"));
  }

  if (m_modules[index] != nullptr) {
    return std::unexpected(Error::Logic(name, "addModule", "Module slot already occupied"));
  }

  int shared_fd = m_shared_rb_fd.get();

  // 4. Kernel Lifecycle
  if (auto res = mod->open(); !res) { return res; }
  if (auto res = mod->load(shared_fd); !res) { return res; }
  if (auto res = mod->attach(); !res) { return res; }

  // 5. Final Commitment
  m_modules[index] = std::move(mod);
  return {};
}

Odin::Result<void> EbpfManager::removeModule(EbpfModuleId mod_id) {
  size_t index = static_cast<size_t>(mod_id);

  // 2. Proper validation with error messages
  if (index >= m_modules.size()) {
    return std::unexpected(Error::Logic(name, "removeModule", "Module ID out of range"));
  }

  if (!m_modules[index]) {
    // If it's already gone, we can consider this a success (idempotent)
    // or return an error if your logic strictly requires it to exist.
    return {};
  }

  // 3. Reset the unique_ptr (this calls the module's destructor/cleanup)
  m_modules[index].reset();

  return {}; // Return success
}
} // namespace OdinSight::Daemon::Monitor::Kernel
