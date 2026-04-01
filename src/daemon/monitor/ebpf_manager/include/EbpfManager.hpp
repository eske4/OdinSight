#pragma once

#include <array>
#include <bpf/libbpf.h>
#include <memory>

#include "EPollBinding.hpp"
#include "IEbpfModule.hpp"
#include "ebpf_types.h"
#include "master.skel.h"
#include "system/FD.hpp"

namespace OdinSight::Daemon::Monitor::Kernel {

class EbpfManager final {
private:
  /** --- Private Type Aliases (Zero External Exposure) --- **/
  using FD           = OdinSight::System::FD;
  using EPollBinding = OdinSight::System::EPollBinding;
  using EPollManager = OdinSight::System::EPollManager;

  template <typename T> using Result = std::expected<T, std::error_code>;

  using ModuleArray = std::array<std::unique_ptr<IEbpfModule>, EBPF_MODULE_MAX>;

  // Aliasing the complex BPF types to keep the member list readable
  using RingBufferPtr = std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)>;
  using MasterSkelPtr = std::unique_ptr<struct master, decltype(&master__destroy)>;

  /** --- Members --- **/
  ModuleArray   m_modules = {};
  RingBufferPtr m_ringbuf_reader{nullptr, ring_buffer__free};
  MasterSkelPtr m_master_skel{nullptr, master__destroy};

  FD              m_shared_rb_fd  = FD::empty();
  struct bpf_map *m_shared_rb_map = nullptr;

  EbpfManager() = default;

  std::unique_ptr<EPollBinding> m_binding;

  static int handleEvent(void *ctx, void *data, size_t data_sz);

public:
  static Result<std::unique_ptr<EbpfManager>> create();
  ~EbpfManager() = default;

  // Rule of Five singleton design
  EbpfManager(const EbpfManager &)                = delete;
  EbpfManager &operator=(const EbpfManager &)     = delete;
  EbpfManager(EbpfManager &&) noexcept            = delete;
  EbpfManager &operator=(EbpfManager &&) noexcept = delete;

  /** --- Public API --- **/
  [[nodiscard]] Result<void> addModule(std::unique_ptr<IEbpfModule> mod);
  [[nodiscard]] Result<void> removeModule(EbpfModuleId mod_id);
  [[nodiscard]] bool         isActive() const {
    return m_master_skel != nullptr && m_ringbuf_reader != nullptr;
  }

  bool isReady() const { return m_ringbuf_reader != nullptr && m_shared_rb_fd.isValid(); }

  // Note: Using the internal alias for the parameter
  [[nodiscard]] bool createEPollBinding(EPollManager &manager);
};

} // namespace OdinSight::Daemon::Monitor::Kernel
