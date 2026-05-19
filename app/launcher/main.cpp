#include "common/Protocol.hpp"
#include "system/FD.hpp"
#include <arpa/inet.h> // for htonl
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>

namespace sys    = OdinSight::System;
namespace common = OdinSight::Common;

common::GameID selectGame() {
    constexpr int numGames = static_cast<int>(common::GameID::NUM_GAMES);

    constexpr int nameWidth = 24;
    constexpr int indexWidth = 7;

    constexpr std::string_view topBorder =
        "┌─────────────────────────────────┐";
    constexpr std::string_view middleBorder =
        "├─────────────────────────────────┤";
    constexpr std::string_view bottomBorder =
        "└─────────────────────────────────┘";

    std::cout << topBorder << '\n';

    std::cout << "│ "
              << std::left  << std::setw(nameWidth)  << std::string_view{"Game Title"}
              << std::right << std::setw(indexWidth) << std::string_view{"Index"}
              << " │\n";

    std::cout << middleBorder << '\n';

    for (int i = 1; i < numGames; ++i) {
        const auto game = static_cast<common::GameID>(i);
        const std::string_view name = common::gameToString(game);
        const std::string index = "[" + std::to_string(i) + "]";

        std::cout << "│ "
                  << std::left  << std::setw(nameWidth)  << name
                  << std::right << std::setw(indexWidth) << index
                  << " │\n";
    }

    std::cout << bottomBorder << "\n\n";

    std::cout << "Enter Game Index: ";

    int choice = 0;
    std::cin >> choice;

    if (!std::cin || choice <= 0 || choice >= numGames) {
        return common::GameID::Unknown;
    }

    return static_cast<common::GameID>(choice);
}

int main() {
  common::GameID selected_game = selectGame();

  if (selected_game == common::GameID::Unknown) {
    std::cerr << "[ERROR] Invalid game selection\n";
    return 1;
  }

  auto file_descriptor = sys::FD::adopt(::socket(AF_UNIX, SOCK_STREAM, 0));
  if (!file_descriptor) { return 1; }

  if (file_descriptor->get() < 0) {
    std::cerr << "[ERROR] Failed to create socket\n";
    return 1;
  }

  // 1. Prepare the Abstract Address
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;

  // The first byte must be \0 for abstract namespace
  addr.sun_path[0] = '\0';

  // Copy the name starting at index 1
  std::string path = common::COMMAND_SOCKET_PATH;
  std::memcpy(addr.sun_path + 1, path.c_str(), path.size());

  // Calculate exact length: family + null byte + path string
  socklen_t addrLen = offsetof(struct sockaddr_un, sun_path) + 1 + path.size();

  // 2. Attempt to connect
  if (connect(file_descriptor->get(), reinterpret_cast<sockaddr*>(&addr), addrLen) == -1) {
    std::cerr << "[ERROR] Could not connect to abstract socket: " << std::strerror(errno) << "\n";
    return 1;
  }

  // 3. Prepare and Send Message (with Byte Order conversion)
  common::CommandPacket msg;
  msg.command_id = common::DaemonCommand::Launch;
  msg.game_id    = selected_game;

  if (send(file_descriptor->get(), &msg, sizeof(msg), 0) == -1) {
    std::cerr << "[ERROR] Failed to send message\n";
    return 1;
  }

  std::cout << "Launch request sent successfully to " << common::COMMAND_SOCKET_PATH << "\n";

  return 0;
}
