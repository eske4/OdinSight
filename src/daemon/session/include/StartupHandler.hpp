#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "IEbpfModule.hpp"
#include "Runner.hpp"
#include "common/Protocol.hpp"
#include "common/Result.hpp"
#include "system/CGroup.hpp"
#include "system/FD.hpp"
#include <memory>
#include <optional>

namespace OdinSight::Daemon::Session {

class StartupHandler : public System::IEPollListener {
  using FD              = System::FD;
  using CGroup          = System::CGroup;
  using CommandPacket   = OdinSight::Common::CommandPacket;
  using CommandListener = OdinSight::Daemon::Control::CommandListener;
  using Runner          = OdinSight::Daemon::Launcher::Runner;
  using EbpfManager     = OdinSight::Daemon::Monitor::Kernel::EbpfManager;
  using IEbpfModule     = OdinSight::Daemon::Monitor::Kernel::IEbpfModule;
  using EPollManager    = System::EPollManager;

private:
  // CommandListener ref
  CommandListener*      m_listener;
  Runner*               m_runner;
  EbpfManager*          m_ebpf_mgr;
  EPollManager*         m_epoll_mgr;
  std::weak_ptr<CGroup> m_cg_parent;

  static constexpr std::string_view ctx = "StartupHandler";

  uint32_t m_events = EPOLLIN | EPOLLET;
  // EbpfManager ref

  [[nodiscard]] static std::optional<CommandPacket> validatePacket(const CommandPacket& pkt);
  [[nodiscard]] Odin::Result<void>                  prepareGame(const CommandPacket& pkt);
  [[nodiscard]] Odin::Result<void>                  attachProtection();
  [[nodiscard]] Odin::Result<void>                  launchGame();
  [[nodiscard]] Odin::Result<void> setupModule(Odin::Result<std::unique_ptr<IEbpfModule>> mod_res);

  StartupHandler(Runner* runner, EbpfManager* ebpf_mgr, CommandListener* listener,
                 EPollManager* epoll_mgr, std::weak_ptr<CGroup> cg_parent);

public:
  StartupHandler(const StartupHandler&)            = delete;
  StartupHandler& operator=(const StartupHandler&) = delete;
  StartupHandler(StartupHandler&&)                 = delete;
  StartupHandler& operator=(StartupHandler&&)      = delete;

  ~StartupHandler() override = default;

  [[nodiscard]] static Odin::Result<std::unique_ptr<IEPollListener>>
  create(Runner* runner, EbpfManager* ebpf_mgr, CommandListener* listener, EPollManager* epoll_mgr,
         std::shared_ptr<CGroup> cg_parent);

  void onEpollEvent(uint32_t events) override;

  [[nodiscard]] uint32_t getEvents() const override { return m_events; }

  [[nodiscard]] const FD& getFd() const override { return m_listener->getFd(); }
};
} // namespace OdinSight::Daemon::Session
