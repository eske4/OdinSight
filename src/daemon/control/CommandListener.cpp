#include "CommandListener.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace OdinSight::Daemon::Control {

namespace sys    = OdinSight::System;
namespace common = OdinSight::Common;

template <typename T> using Result = std::expected<T, std::error_code>;
using DaemonCommand                = OdinSight::Common::DaemonCommand;
using CommadPacket                 = OdinSight::Common::CommandPacket;

CommandListener::~CommandListener() { stop(); }

Result<std::unique_ptr<CommandListener>> CommandListener::create() {
  // 1. Define the internal defaults
  std::string defaultPath    = Common::COMMAND_SOCKET_PATH;
  Handler     defaultHandler = nullptr;

  // 2. Instantiate via the private constructor
  auto instance = std::unique_ptr<CommandListener>(
      new CommandListener(std::move(defaultPath), std::move(defaultHandler)));

  // 3. Safety Check: If for some reason 'new' failed (rare but possible)
  if (!instance) {
    return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
  }

  // 4. Wrap and return
  return instance;
}

Result<void> CommandListener::start() {
  stop();

  // 1. Create Socket
  if (auto server_fd =
          FD::adopt(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0))) {
    m_serverFD = std::move(*server_fd);
  }
  if (!m_serverFD) {
    return std::unexpected(make_error_code(static_cast<std::errc>(errno)));
  }

  sockaddr_un addr{};
  addr.sun_family  = AF_UNIX;
  // The first byte is \0, making it an "abstract" socket
  addr.sun_path[0] = '\0';

  if (m_path.size() + 1 > sizeof(addr.sun_path)) {
    closeServer();
    return std::unexpected(make_error_code(std::errc::invalid_argument));
  }

  std::memcpy(addr.sun_path + 1, m_path.c_str(), m_path.size());

  socklen_t addrLen = offsetof(struct sockaddr_un, sun_path) + 1 + m_path.size();

  // 3. Bind
  const void     *raw_ptr    = &addr;
  const sockaddr *socket_ptr = static_cast<const sockaddr *>(raw_ptr);
  if (::bind(m_serverFD.get(), socket_ptr, addrLen) < 0) {
    closeServer();
    return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
  }

  // 4. Listen
  if (::listen(m_serverFD.get(), MAX_PENDING_CONNECTIONS) < 0) {
    closeServer();
    return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
  }

  return {};
}

void CommandListener::handleEvents(uint32_t events) {
  // 1. Check for Critical Errors on the Server Socket
  if ((events & (EPOLLERR | EPOLLHUP)) != 0U) {
    return;
  }

  if ((events & EPOLLIN) == 0U) {
    return;
  }

  // 1. ALWAYS accept the connection to clear the kernel backlog
  auto client_fd_res =
      FD::adopt(::accept4(m_serverFD.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
  if (!client_fd_res) {
    return;
  }

  auto &client_fd = client_fd_res.value();

  // 2. NOW check rate limiting. If too fast, the FD goes out of scope and closes.
  auto now = std::chrono::steady_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastAcceptTime).count();

  if (elapsed < COMMAND_COOLDOWN_MS) {
    return;
  }

  m_lastAcceptTime = now;

  // 3. Set small buffer to prevent memory-based DoS
  int smallBuf = sizeof(CommandPacket);
  ::setsockopt(client_fd.get(), SOL_SOCKET, SO_RCVBUF, &smallBuf, sizeof(smallBuf));

  CommandPacket packet{};

  ssize_t bytesReceived = ::recv(client_fd.get(), &packet, sizeof(packet), MSG_DONTWAIT);

  if (bytesReceived != static_cast<ssize_t>(sizeof(packet))) {
    return;
  }

  uint32_t rawCmd    = static_cast<uint32_t>(packet.command_id);
  uint32_t rawGameId = static_cast<uint32_t>(packet.game_id);

  if (rawGameId >= static_cast<uint32_t>(common::GameID::NUM_GAMES)) {
    return;
  }

  if (rawCmd >= static_cast<uint32_t>(common::DaemonCommand::NUM_COMMANDS)) {
    return;
  }

  if (m_handler) {
    m_handler(packet);
  }
}

void CommandListener::stop() { closeServer(); }

void CommandListener::closeServer() {
  // Assuming sys::FD::release() or reset() handles the close() call
  m_serverFD.close();
}

// In UnixCommandDaemon.hpp
bool CommandListener::createEPollBinding(sys::EPollManager &manager) {
  // Safety check:
  // 1. Manager must exist
  // 2. Server socket must be initialized (m_serverFD > 0)
  // 3. We shouldn't already have an active binding
  if (m_serverFD.get() < 0 || m_binding != nullptr) {
    return false;
  }

  // The lambda matches the signature expected by your EPollBinding
  auto on_event = [](void *context, uint32_t events) {
    auto *self = static_cast<CommandListener *>(context);
    if (self) {
      self->handleEvents(events);
    }
  };

  // Create the managed binding
  m_binding = std::make_unique<sys::EPollBinding>(&manager, m_serverFD.get(), this, on_event);

  // Attempt to subscribe.
  // Note: Using Level Triggered (default) instead of EPOLLET
  // because we want the manager to keep poking us if we don't
  // drain the accept queue in one go.
  if (!m_binding->subscribe(EPOLLIN)) {
    m_binding.reset(); // Clean up on failure
    return false;
  }

  return true;
}

} // namespace OdinSight::Daemon::Control
