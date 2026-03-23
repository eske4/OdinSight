#pragma once

#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "common/Protocol.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <sys/epoll.h>

namespace ACName::Daemon::Control {

class CommandListener {
public:
  using CommandPacket = ACName::Common::CommandPacket;
  using FD = ACName::System::FD;
  using EPollManager = ACName::System::EPollManager;
  using EPollBinding = ACName::System::EPollBinding;

  using Validator = std::function<bool(const CommandPacket &packet)>;
  using Handler = std::function<void(const CommandPacket &packet)>;

private:
  std::string m_path;
  Validator m_validator;
  Handler m_handler;
  FD m_serverFD;

  std::unique_ptr<EPollBinding> m_binding;
  std::chrono::steady_clock::time_point m_lastAcceptTime{
      std::chrono::steady_clock::now() -
      std::chrono::milliseconds(COMMAND_COOLDOWN_MS)};

  static constexpr int MAX_PENDING_CONNECTIONS = 16;
  static constexpr int COMMAND_COOLDOWN_MS = 1000;

public:
  explicit CommandListener(std::string path, Validator validator = nullptr,
                           Handler handler = nullptr);
  ~CommandListener();

  // Disable copying
  CommandListener(const CommandListener &) = delete;
  CommandListener &operator=(const CommandListener &) = delete;

  bool start();
  void stop();

  // The "Hook" for your EPollManager
  bool createEPollBinding(EPollManager *manager);
  void handleEvents(uint32_t events);
  int getFd() const { return m_serverFD; }

private:
  void processClient(const FD &file_descriptor);
  static bool setNonBlocking(const FD &file_descriptor);
  void closeServer();

  static bool defaultValidator(const CommandPacket &packet) { return true; }
  static void defaultHandler(const CommandPacket &packet) {}
};

} // namespace ACName::Daemon::Control
