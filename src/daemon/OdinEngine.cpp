#include "OdinEngine.hpp"
#include "EPollManager.hpp"
#include "ExitHandler.hpp"
#include "StartupHandler.hpp"
#include "common/Result.hpp"

namespace OdinSight::Daemon {

template <typename T> using Result = std::expected<T, std::error_code>;
using StartupHandler               = OdinSight::Daemon::Session::StartupHandler;
using ExitHandler                  = OdinSight::Daemon::Session::ExitHandler;

using Error = Odin::Error;

Odin::Result<OdinEngine> OdinEngine::create(std::shared_ptr<CGroup> parent_cg) {
  // 1. Construct the engine (calls private OdinEngine())
  OdinEngine engine;

  auto epoll_res = EPollManager::create();
  if (!epoll_res) { return std::unexpected(Error::Enrich(ctx, "create_epoll", epoll_res.error())); }

  // 2. Setup Ebpf }

  auto ebpf_res = EbpfManager::create();

  if (!ebpf_res) { return std::unexpected(Error::Enrich(ctx, "create_ebpf", ebpf_res.error())); }

  auto cg_res = CGroup::createAt(parent_cg, "daemon");
  if (!cg_res) { return std::unexpected(Error::Enrich(ctx, "create_cgroup", cg_res.error())); }

  auto runner_res = Runner::create();
  if (!runner_res) {
    return std::unexpected(Error::Enrich(ctx, "create_runner", runner_res.error()));
  }

  auto listener_res = CommandListener::create();
  if (!listener_res) {
    return std::unexpected(Error::Enrich(ctx, "create_listener", listener_res.error()));
  }

  engine.m_epoll_mgr = std::move(epoll_res.value());
  engine.m_ebpf_mgr  = std::move(ebpf_res.value());
  engine.m_cgroup    = std::move(cg_res.value());
  engine.m_runner    = std::move(runner_res.value());
  engine.m_listener  = std::move(listener_res.value());

  return std::move(engine);
}

Odin::Result<void> OdinEngine::initializeManagers() {
  if (m_listener == nullptr) {
    return std::unexpected(Error::Logic(ctx, "init_managers", "Listener not initialized"));
  }

  if (auto res = m_listener->start(); !res) {
    return std::unexpected(Error::Enrich(ctx, "start_listener", res.error()));
  }

  return {};
}

Odin::Result<void> OdinEngine::initializeListeners() {
  auto startup_res = StartupHandler::create(m_runner.get(), m_ebpf_mgr.get(), m_listener.get(),
                                            m_epoll_mgr.get(), m_cgroup);

  // auto exit_handler_res = ExitHandler::create(m_runner.get(), m_ebpf_mgr.get(),
  // m_listener.get());

  if (!startup_res) {
    return std::unexpected(Error::Enrich(ctx, "create_startup_handler", startup_res.error()));
  }

  // if (!exit_handler_res) {
  //   return std::unexpected(exit_handler_res.error());
  // }
  //
  if (auto res = m_epoll_mgr->subscribe(std::move(*startup_res)); !res) {
    return std::unexpected(Error::Enrich(ctx, "subscribe_startup", res.error()));
  }
  // auto exit_module    = std::move(exit_handler_res.value());

  return {};
}

Odin::Result<void> OdinEngine::init() {
  if (auto res = initializeManagers(); !res) { return res; }
  if (auto res = initializeListeners(); !res) { return res; }
  return {};
}

Odin::Result<void> OdinEngine::run() {
  if (!m_epoll_mgr) { return std::unexpected(Error::Logic(ctx, "run", "EPollManager missing")); }

  while (m_epoll_mgr->isRunning()) {
    if (auto res = m_epoll_mgr->poll(); !res) {
      return std::unexpected(Error::Enrich(ctx, "poll_loop", res.error()));
    }
  }
  return {};
}

// This triggers a 'move' into the Result wrapper
} // namespace OdinSight::Daemon
