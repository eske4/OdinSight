#pragma once

#include "ebpf_types.h"
#include <bpf/libbpf.h>
#include <expected>
#include <memory>
#include <system_error>

namespace OdinSight::Daemon::Monitor::Kernel {

/**
 * @brief Base interface for all eBPF monitoring modules.
 * * This class enforces a strict factory-based lifecycle (Open -> Load -> Attach).
 * Modules are designed to be owned by a Manager and share a common Ring Buffer.
 */
class IEbpfModule {

public:
  template <typename T> using Result = std::expected<T, std::error_code>;

private:
  EbpfModuleId m_id;
  std::string  m_name;

protected:
  /**
   * @brief Protected constructor to enforce the Factory Pattern.
   * @param mod_id Unique ID assigned from the EbpfModuleId enum.
   * @param mod_name String identifier for logging/telemetry.
   */
  explicit IEbpfModule(EbpfModuleId mod_id, std::string mod_name)
      : m_id(mod_id), m_name(std::move(mod_name)) {}

public:
  /**
   * @brief The Universal Factory.
   * SyscallModule must 'friend' IEbpfModule to allow this to work.
   */
  template <typename T, typename... Args> static Result<std::unique_ptr<T>> create(Args &&...args) {
    // We use 'new' here because std::make_unique cannot access private constructors.
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
  }

  /** * @note Implementation Requirement:
   * Derived classes MUST implement a static factory function:
   * static Result<std::unique_ptr<DerivedModule>> create();
   */

  /** --- Rule of Five singleton --- **/
  virtual ~IEbpfModule()                      = default;
  // Disable Copying
  IEbpfModule(const IEbpfModule &)            = delete;
  IEbpfModule &operator=(const IEbpfModule &) = delete;

  IEbpfModule(IEbpfModule &&)            = delete;
  IEbpfModule &operator=(IEbpfModule &&) = delete;

  /** --- Lifecycle --- **/
  virtual Result<void> open()                 = 0;
  virtual Result<void> load(int shared_rb_fd) = 0;
  virtual Result<void> attach()               = 0;

  /** --- Event Handling --- **/

  /**
   * @brief Callback invoked when the Manager consumes an event from the Ring Buffer.
   * @param event Pointer to the raw event data.
   * @param size Size of the received data.
   */
  virtual void processEvent(const ebpf_event *event, size_t size) = 0;

  /** --- Accessors --- **/

  /** @brief Returns the unique identifier for this module type. */
  EbpfModuleId getId() const { return m_id; }

  /** @brief Returns the human-readable name of the module. */
  std::string_view getName() const { return m_name; }
};

} // namespace OdinSight::Daemon::Monitor::Kernel
