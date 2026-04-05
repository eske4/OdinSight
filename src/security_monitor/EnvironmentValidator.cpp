#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"
#include <array>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
template <typename T> using Result = std::expected<T, std::error_code>;

namespace OdinSight::System::Environment {

Result<void> Validator::isSecureBootEnabled() {
  const std::string dirPath = "/sys/firmware/efi/efivars/";
  std::string       secureBootFileName;

  if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
        return std::unexpected(std::make_error_code(std::errc::is_a_directory));
  }

  for (const auto &entry : fs::directory_iterator(dirPath)) {
    const auto &filename = entry.path().filename().string();

    if (filename.rfind("SecureBoot-", 0) == 0) {
      secureBootFileName = filename;
      break;
    }
  }

  if (secureBootFileName.empty()) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }

  FD dirFd(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (!dirFd) {
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  FD secureBootFd(dirFd, secureBootFileName, O_RDONLY);
  if (!secureBootFd) {
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }
  uint8_t data[5];
  if (::read(secureBootFd.get(), data, sizeof(data)) != 5) {
        return std::unexpected(std::error_code(errno, std::system_category()));
  }

  return {}; // Success
}

Result<void> Validator::isKernelLockdownEnabled() {
  const std::string lockdownFilePath = "/sys/kernel/security/lockdown";

  FD lockdownFd(lockdownFilePath, O_RDONLY);
  if (!lockdownFd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));;
  }
  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(lockdownFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  buffer[bytesRead] = '\0';
  const std::string lockdownStatus(buffer.data());

  bool lockdownEnabled = lockdownStatus.find("[confidentiality]") != std::string::npos;

  if (!lockdownEnabled){
    return std::unexpected(std::make_error_code(std::errc::invalid_seek));
  }

  return {};
}

Result<void> Validator::isKernelModuleSignatureEnforcementEnabled() {
  const std::string sigEnforceFilePath = "/sys/module/module/parameters/sig_enforce";

  FD sigEnforceFd(sigEnforceFilePath, O_RDONLY);
  if (!sigEnforceFd) {
    return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
  }

  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(sigEnforceFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
        return std::unexpected(std::error_code(errno, std::system_category()));
  }

  buffer[bytesRead] = '\0';

  std::string sigEnforce(buffer.data());
  while (!sigEnforce.empty() && (sigEnforce.back() == '\n' || sigEnforce.back() == '\r')) {
    sigEnforce.pop_back();
  }

  bool kernelModuleSignatureEnforcementEnabled = sigEnforce == "1" || sigEnforce == "Y" || sigEnforce == "y";

  if(!kernelModuleSignatureEnforcementEnabled){
        return std::unexpected(std::make_error_code(std::errc::invalid_seek));
  }

  return {};
}

Result<void> Validator::isValid() {
  Result<void> secureBootEnabled                       = isSecureBootEnabled();
  Result<void> kLockdownEnabled                        = isKernelLockdownEnabled();
  Result<void> kernelModuleSignatureEnforcementEnabled = isKernelModuleSignatureEnforcementEnabled();

  if (!secureBootEnabled) {
    std::cout << "Error: Secure Boot - disabled." << std::endl;
  }

  if (!kLockdownEnabled) {
    std::cout << "Error: Kernel lockdown(Confidential Mode) - disabled." << std::endl;
  }

  if (!kernelModuleSignatureEnforcementEnabled) {
    std::cout << "Error: Kernel module signature enforcement - disabled." << std::endl;
  }

  // Verifying whether unsigned modules are loadable
  const UnsignedKernelModuleLoadProbe::Result unsignedKernelModuleLoadProbeResult =
      isUnsignedKernelModuleLoadBlocked();

  if (!unsignedKernelModuleLoadProbeResult.isBlocked) {
    switch (unsignedKernelModuleLoadProbeResult.status) {
    case UnsignedKernelModuleLoadProbe::Status::kAllowed:
      std::cout << "Error: Runtime unsigned kernel modules are allowed." << std::endl;
      break;
    default:
      std::cout << "Error: Unsigned Module loab probe failure" << std::endl;
      break;
    }
  }

  return {};
}
} // namespace OdinSight::System::Environment
