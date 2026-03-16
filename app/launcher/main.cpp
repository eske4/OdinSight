#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "common/local_protocol.hpp"
#include "system/FD.hpp"

int main() {
    sys::FD file_descriptor;

    // Create the socket
    file_descriptor.reset(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (!file_descriptor) {
        std::cerr << "[ERROR] Failed to create socket: " << std::strerror(errno) << "\n";
        return 0;
    }

    // Prepare the address
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Attempt to connect
    if (connect(file_descriptor.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
        std::cerr << "[ERROR] Could not connect to the launcher socket at '"
                  << SOCKET_PATH << "': " << std::strerror(errno) << "\n";
        return 0;
    }

    // Prepare the message
    LaunchMessage msg;
    msg.magic = MAGIC_VAL;
    msg.cmd = Command::LAUNCH_GAME;
    msg.game_id = common::GameID::AssaultCube;

    // Send the message
    if (send(file_descriptor.get(), &msg, sizeof(msg), 0) == -1) {
        std::cerr << "[ERROR] Failed to send message: " << std::strerror(errno) << "\n";
        return 0;
    }

    std::cout << "Launch request sent successfully\n";

    // Close the socket
    file_descriptor.reset(); // properly closes FD

    return 0;
}

