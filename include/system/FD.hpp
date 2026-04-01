#pragma once

#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <stdint.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace OdinSight::System {

class FD final {
  template <typename T> using Result = std::expected<T, std::error_code>;

private:
  int m_fd = -1;

  // Private constructor used by factories
  explicit FD(int file_descriptor) noexcept : m_fd(file_descriptor) {}
  inline void reset() noexcept;

public:
  FD() noexcept = delete;
  ~FD() { reset(); }

  // Disable copies
  FD(const FD &)            = delete;
  FD &operator=(const FD &) = delete;

  // Move semantics
  FD(FD &&other) noexcept : m_fd(std::exchange(other.m_fd, -1)) {}
  FD &operator=(FD &&other) noexcept {
    if (this != &other) {
      reset();
      m_fd = std::exchange(other.m_fd, -1);
    }
    return *this;
  }

  // --- Actions ---
  [[nodiscard]] int release() noexcept { return std::exchange(m_fd, -1); }
  void              close() noexcept { reset(); }

  // --- Factories ---
  [[nodiscard]] static Result<FD> open(const std::string &path, int flags,
                                       mode_t mode = 0) noexcept;
  [[nodiscard]] static Result<FD> openAt(const FD &dir_fd, const std::string &rel_path,
                                         uint64_t flags) noexcept;
  [[nodiscard]] static Result<FD> adopt(int file_descriptor) noexcept;
  [[nodiscard]] static FD         empty() noexcept { return FD(-1); }

  // --- Accessors ---
  [[nodiscard]] bool             isValid() const noexcept { return m_fd >= 0; }
  [[nodiscard]] int              get() const noexcept { return m_fd; }
  [[nodiscard]] Result<uint64_t> getID() const noexcept;

  explicit operator bool() const noexcept { return isValid(); }
  int      operator*() const noexcept { return m_fd; }
};
//
// =================================================================
// Implementation
// =================================================================

inline void FD::reset() noexcept {
  if (m_fd >= 0) {
    ::close(m_fd);
    m_fd = -1;
  }
}

inline auto FD::openAt(const FD &dir_fd, const std::string &rel_path, uint64_t flags) noexcept
    -> Result<FD> {
  if (!dir_fd.isValid()) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  struct open_how how = {.flags   = flags | O_CLOEXEC,
                         .resolve = RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH};

  // Note: Ensure your environment has the openat2 syscall wrapper or use syscall()
  int res = ::openat2(dir_fd.get(), rel_path.c_str(), &how, sizeof(how));

  if (res < 0) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  return FD(res);
}

inline auto FD::open(const std::string &path, int flags, mode_t mode) noexcept -> Result<FD> {
  if (path.empty()) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  int file_descriptor = ::open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW, mode);

  if (file_descriptor < 0) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  return FD(file_descriptor);
}

inline auto FD::adopt(int file_descriptor) noexcept -> Result<FD> {
  if (file_descriptor < 0) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }
  return FD(file_descriptor);
}

inline auto FD::getID() const noexcept -> Result<uint64_t> {
  if (m_fd < 0) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  struct stat targetStat;
  if (::fstat(m_fd, &targetStat) == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  return static_cast<uint64_t>(targetStat.st_ino);
}

} // namespace OdinSight::System
