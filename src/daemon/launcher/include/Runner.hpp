#pragma once

#include "Context.hpp"
#include "common/GameID.hpp"
#include "system/CGroup.hpp"

#include <linux/sched.h>
#include <optional>
#include <sys/syscall.h>
#include <sys/types.h>

namespace ACName::Daemon::Launcher {

class Runner {

  using GameID = ACName::Common::GameID;
  using CGroup = ACName::System::CGroup;

public:
  enum class LauncherStatus : int {
    Success = 0,
    SetGroupsFailed = 100,
    SetGidFailed = 101,
    SetUidFailed = 102,
    ChdirFailed = 103,
    NoNewPrivsFailed = 104,
    SetDumpableFailed = 105,
    ExecveFailed = 106
  };

private:
  /**
   * @brief The internal syscall logic (clone3/fexecve).
   * @param target_ctx The local context prepared by start().
   */
  void launch(const Context &ctx);
  std::optional<Context> m_ctx;
  pid_t m_gpid = -1;

public:
  Runner() = default;
  ~Runner() { stop(); }

  Runner(const Runner &) = delete;
  Runner &operator=(const Runner &) = delete;
  Runner(Runner &&) = delete;
  Runner &operator=(Runner &&) = delete;

  /**
   * @brief Prepares the environment for the launcher.
   * @param game_id: Path to the executable.
   * @param cgroup: The parents cgroup.
   */
  [[nodiscard]] bool setup(const GameID &game_id, const CGroup &cgroup_parent);
  void start();
  void stop();

  [[nodiscard]] bool isActive() const {
    return m_ctx.has_value() && m_gpid != -1;
  }
  [[nodiscard]] bool isPrepared() const {
    return m_ctx.has_value() && m_gpid == -1;
  }
  [[nodiscard]] bool canLaunch();
  [[nodiscard]] pid_t getGpid() const { return m_gpid; }
  [[nodiscard]] const Context *getSessionInfo() const;
};
} // namespace ACName::Daemon::Launcher
