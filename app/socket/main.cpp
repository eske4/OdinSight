#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include <iostream>

int main() {
  auto epoll_manager = sys::EPollManager::create().value();

  // 1. Define logic outside the class (no clutter, just a lambda!)
  auto validator = [](common::DaemonCommand cmd, common::GameID game) {
    std::cout << "[Validator] Checking Cmd: " << static_cast<int>(cmd)
              << " Game: " << static_cast<int>(game) << std::endl;
    return cmd == common::DaemonCommand::Launch; // Only allow "Launch"
  };

  auto handler = [](common::DaemonCommand cmd, common::GameID game) {
    std::cout << "[Handler] SUCCESS: Launching Game ID "
              << static_cast<int>(game) << "..." << std::endl;
  };

  // 2. Initialize (Using the abstract path "ac_test_socket")
  CommandListener daemon(common::COMMAND_SOCKET_PATH, validator, handler);

  if (!daemon.start()) {
    std::cerr << "Failed to start daemon. Are you root?" << std::endl;
    return 1;
  }

  daemon.createEPollBinding(&epoll_manager);

  std::cout << "Daemon listening on abstract socket: \\0ac_test_socket"
            << std::endl;

  // 3. Simple Manual Epoll Loop (Since we aren't using your full EPollManager
  // yet)

  while (true) {
    int events = epoll_manager.poll(100).value();
  }

  return 0;
}
