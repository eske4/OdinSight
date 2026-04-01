#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "SyscallModule.hpp"
#include <iostream>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace KMod   = OdinSight::Daemon::Monitor::Kernel::Modules;
namespace Kernel = OdinSight::Daemon::Monitor::Kernel;
namespace sys    = OdinSight::System;

int main() {

  auto epoll_manager = sys::EPollManager::create();
  auto ebpf_manager  = Kernel::EbpfManager::create();

  auto &epoll_mgr = epoll_manager.value();
  auto &ebpf      = ebpf_manager.value();
  auto  mod       = Kernel::IEbpfModule::create<KMod::SyscallModule>();

  if (!ebpf->addModule(std::move(mod.value()))) {
    return 1;
  }
  // 1. Add your modules

  // 3. Setup the Epoll Binding
  if (!ebpf->createEPollBinding(epoll_mgr)) {
    std::cerr << "Failed to create epoll binding" << std::endl;
    return 1;
  }

  while (epoll_mgr.isRunning()) {
    int events = epoll_mgr.poll(100).value();
  }
}
