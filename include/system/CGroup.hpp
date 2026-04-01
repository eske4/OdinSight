#pragma once

#include "FD.hpp"
#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace OdinSight::System {

class CGroup final {
  template <typename T> using Result = std::expected<T, std::error_code>;

  static constexpr int MAX_RETRY_ATTEMPTS = 10;
  static constexpr int MAX_SLEEP_TIME     = 100;

private:
  std::string           m_name;
  std::filesystem::path m_path;
  FD                    m_fd;
  uint64_t              m_id = 0;

  // Private constructor for factories
  CGroup(std::string name, std::filesystem::path path, FD file_descriptor, uint64_t cg_id)
      : m_name(std::move(name)), m_path(std::move(path)), m_fd(std::move(file_descriptor)),
        m_id(cg_id) {}

  inline void cleanup() noexcept;

public:
  CGroup()                          = delete;
  CGroup(const CGroup &)            = delete;
  CGroup &operator=(const CGroup &) = delete;

  // Move Constructor
  CGroup(CGroup &&other) noexcept
      : m_name(std::move(other.m_name)), m_path(std::move(other.m_path)),
        m_fd(std::move(other.m_fd)), m_id(std::exchange(other.m_id, 0)) {}

  // Move Assignment
  CGroup &operator=(CGroup &&other) noexcept {
    if (this != &other) {
      cleanup();
      m_name = std::move(other.m_name);
      m_path = std::move(other.m_path);
      m_fd   = std::move(other.m_fd);
      m_id   = std::exchange(other.m_id, 0);
    }
    return *this;
  }

  ~CGroup() { cleanup(); }

  // --- Factories ---
  [[nodiscard]] static Result<CGroup> create(std::string_view name) noexcept;
  [[nodiscard]] static Result<CGroup> createAt(const FD                    &parent_fd,
                                               const std::filesystem::path &parent_path,
                                               std::string                  name) noexcept;
  [[nodiscard]] static CGroup         empty() noexcept { return CGroup("", {}, FD::empty(), 0); };

  void close() { cleanup(); }

  // --- Accessors ---
  [[nodiscard]] explicit           operator bool() const noexcept { return m_fd && m_id > 0; }
  [[nodiscard]] const FD          &getFD() const noexcept { return m_fd; }
  [[nodiscard]] const std::string &getName() const noexcept { return m_name; }
  [[nodiscard]] const std::filesystem::path &getPath() const noexcept { return m_path; }
  [[nodiscard]] uint64_t                     getID() const noexcept { return m_id; }
};

// =================================================================
// Implementatio
// =================================================================

inline void CGroup::cleanup() noexcept {
  if (m_name.empty() || !m_fd.isValid()) {
    return;
  }

  // 1. Send the Kill Signal
  if (auto kill_res = FD::openAt(m_fd, "cgroup.kill", O_WRONLY)) {
    FD kfd = std::move(*kill_res);
    (void)::write(kfd.get(), "1", 1);
  }

  // 2. Release handle so rmdir isn't busy
  m_fd.close();

  // 3. The Guarantee Loop
  std::error_code err;
  for (int attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
    if (std::filesystem::remove(m_path, err) || err == std::errc::no_such_file_or_directory) {
      return;
    }

    if (err == std::errc::device_or_resource_busy) {
      int sleep_ms = std::min(MAX_SLEEP_TIME, (1 << attempt) * 10);
      std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
      continue;
    }
    break;
  }

  if (err) {
    std::clog << "[Cleanup] FATAL: Could not remove " << m_path << " - " << err.message() << "\n";
  }
}

inline CGroup::Result<CGroup> CGroup::create(std::string_view name) noexcept {
  if (name.empty()) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  std::filesystem::path target_path = std::filesystem::path("/sys/fs/cgroup") / name;
  std::error_code       err_code;

  if (!std::filesystem::create_directories(target_path, err_code) && err_code) {
    return std::unexpected(err_code);
  }

  auto fd_res = FD::open(target_path.string(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (!fd_res) {
    return std::unexpected(fd_res.error());
  }

  auto id_res = fd_res->getID();
  if (!id_res) {
    return std::unexpected(id_res.error());
  }

  return CGroup(std::string(name), std::move(target_path), std::move(*fd_res), *id_res);
}

inline CGroup::Result<CGroup> CGroup::createAt(const FD                    &parent_fd,
                                               const std::filesystem::path &parent_path,
                                               std::string                  name) noexcept {
  if (name.empty()) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  if (::mkdirat(parent_fd.get(), name.c_str(), 0755) < 0) {
    const int err = errno;
    if (err != EEXIST) {
      return std::unexpected(std::error_code(err, std::system_category()));
    }
  }

  auto child_fd_res = FD::openAt(parent_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (!child_fd_res) {
    return std::unexpected(child_fd_res.error());
  }

  auto id_res = child_fd_res->getID();
  if (!id_res) {
    return std::unexpected(id_res.error());
  }

  std::filesystem::path full_path = parent_path / name;

  return CGroup(std::move(name), std::move(full_path), std::move(*child_fd_res), *id_res);
}

} // namespace OdinSight::System
