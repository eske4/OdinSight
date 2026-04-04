#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "IEbpfModule.hpp"
#include "Runner.hpp"
#include "common/Protocol.hpp"
#include "system/CGroup.hpp"
#include "system/FD.hpp"
#include <memory>

namespace OdinSight::Daemon::Session {

class ExitHandler : public System::IEPollListener {
  using FD              = System::FD;
  using CGroup          = System::CGroup;
  using CommandPacket   = OdinSight::Common::CommandPacket;
  using CommandListener = OdinSight::Daemon::Control::CommandListener;
  using Runner          = OdinSight::Daemon::Launcher::Runner;
  using EbpfManager     = OdinSight::Daemon::Monitor::Kernel::EbpfManager;
  using IEbpfModule     = OdinSight::Daemon::Monitor::Kernel::IEbpfModule;

  template <typename T> using Result = std::expected<T, std::error_code>;

private:
  // CommandListener ref
  CommandListener *m_listener;
  Runner          *m_runner;
  EbpfManager     *m_ebpf_mgr;

  uint32_t m_events = EPOLLIN | EPOLLONESHOT;

  ExitHandler(Runner *runner, EbpfManager *ebpf_mgr, CommandListener *listener);

public:
  ExitHandler(const ExitHandler &)            = delete;
  ExitHandler &operator=(const ExitHandler &) = delete;
  ExitHandler(ExitHandler &&)                 = delete;
  ExitHandler &operator=(ExitHandler &&)      = delete;

  ~ExitHandler() override = default;

  [[nodiscard]] Result<void> deattachProtection();

  [[nodiscard]] static Result<std::unique_ptr<IEPollListener>>
  create(Runner *runner, EbpfManager *ebpf_mgr, CommandListener *listener);

  void onEpollEvent(uint32_t events) override;

  [[nodiscard]] uint32_t getEvents() const override { return m_events; }

  [[nodiscard]] const FD &getFd() const override { return m_runner->getFd(); }
};
} // namespace OdinSight::Daemon::Session
