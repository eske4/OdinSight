#include "ExitHandler.hpp"

#include "EPollManager.hpp"
#include <optional>
#include <sys/epoll.h>

namespace Kernel = OdinSight::Daemon::Monitor::Kernel;
namespace Common = OdinSight::Common;
namespace System = OdinSight::System;

using CommandPacket  = Common::CommandPacket;
using GameID         = Common::GameID;
using DaemonCommand  = Common::DaemonCommand;
using IEbpfModule    = Kernel::IEbpfModule;
using IEPollListener = System::IEPollListener;

template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::Daemon::Session {

ExitHandler::ExitHandler(Runner *runner, EbpfManager *ebpf_mgr, CommandListener *listener)
    : m_listener(listener), m_runner(runner), m_ebpf_mgr(ebpf_mgr) {}

Result<std::unique_ptr<IEPollListener>> ExitHandler::create(Runner *runner, EbpfManager *ebpf_mgr,
                                                            CommandListener *listener) {
  if (runner == nullptr || ebpf_mgr == nullptr || listener == nullptr) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  return std::unique_ptr<ExitHandler>(new ExitHandler(runner, ebpf_mgr, listener));
}

void ExitHandler::onEpollEvent(uint32_t events) {
  std::cout << "[ExitHandler] Epoll event received: " << events << std::endl;

  if (auto res = deattachProtection(); !res) {
    std::cerr << "[Error] Failed attaching eBPF protection: " << res.error().message() << std::endl;
    return;
  }

  m_runner->stop();
}

Result<void> ExitHandler::deattachProtection() { return {}; }

} // namespace OdinSight::Daemon::Session
