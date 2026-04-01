#include "CGroupService.hpp"
#include "system/CGroup.hpp"

#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs                       = std::filesystem;
template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::System {

Result<void> CGService::writeCG(const CGroup &cgroup, const std::string &file_name,
                                std::string_view value) {
  // 1. Basic validation of the handle
  if (!cgroup.getFD().isValid()) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  if (file_name.empty()) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  // 2. Open relative to the CGroup directory FD
  // We use your FD::openAt which likely uses RESOLVE_BENEATH for security.
  auto open_res = FD::openAt(cgroup.getFD(), file_name, O_WRONLY | O_CLOEXEC);

  if (!open_res) {
    // Propagate why we couldn't open the file (e.g., file_name doesn't exist)
    return std::unexpected(open_res.error());
  }

  // 3. Perform the write syscall
  // We use the underlying FD from the expected object
  auto &raw_fd = open_res.value();
  if (!raw_fd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  ssize_t bytes_written = ::write(raw_fd.get(), value.data(), value.size());

  // 4. Validate the write result
  if (bytes_written < 0) {
    // Return the actual system error (e.g., EINVAL if the kernel dislikes the value)
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  if (static_cast<size_t>(bytes_written) != value.size()) {
    // Partial writes in CGroup virtual files are rare but technically errors
    return std::unexpected(std::make_error_code(std::errc::io_error));
  }

  return {}; // Success
}
// Resource Limits (Stateless & Static)
Result<void> CGService::setMemoryLimit(const CGroup &cgroup, size_t max_bytes) {
  return writeCG(cgroup, "memory.max", std::to_string(max_bytes));
}

Result<void> CGService::setProcLimit(const CGroup &cgroup, int max_pids) {
  return writeCG(cgroup, "pids.max", std::to_string(max_pids));
}

Result<void> CGService::setCpuLimit(const CGroup &cgroup, std::string_view weight) {
  // weight is usually 1-10000, default 100
  return writeCG(cgroup, "cpu.weight", weight);
}

Result<void> CGService::enableSubtreeControllers(const CGroup &parent_cgroup) {
  // Enable the most common controllers for children
  // Note: '+' prefix is required in subtree_control
  return writeCG(parent_cgroup, "cgroup.subtree_control", "+cpuset +cpu +io +memory +pids");
}

Result<void> CGService::killProcs(const CGroup &cgroup) {
  return writeCG(cgroup, "cgroup.kill", "1");
}

} // namespace OdinSight::System
