#pragma once

#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <sys/epoll.h> // For epoll event constants

class CommandListener {
public:
  using Validator = std::function<bool(common::DaemonCommand, common::GameID)>;
  using Handler = std::function<void(common::DaemonCommand, common::GameID)>;

private:
  std::string m_path;
  Validator m_validator;
  Handler m_handler;
  sys::FD m_serverFD;
  std::unique_ptr<sys::EPollBinding> m_binding;
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
  bool createEPollBinding(sys::EPollManager *manager);
  void handleEvents(uint32_t events);
  int getFd() const { return m_serverFD; }

private:
  void processClient(const sys::FD &file_descriptor);
  static bool setNonBlocking(const sys::FD &file_descriptor);
  void closeServer();

  static bool defaultValidator(common::DaemonCommand cmd_id,
                               common::GameID game_id) {
    return true;
  }
  static void defaultHandler(common::DaemonCommand cmd_id,
                             common::GameID game_id) {}
};
