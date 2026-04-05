#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"
#include <array>
#include <cerrno>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace OdinSight::System::Environment {

constexpr char errorCtx[] = "EnvironmentValidator";

Result<void> Validator::isSecureBootEnabled() {
  const std::string dirPath = "/sys/firmware/efi/efivars/";
  std::string       secureBootFileName;

  if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
    return std::unexpected(
        Odin::Error::Logic(errorCtx, "check secure boot", "EFI variables directory is unavailable"));
  }

  for (const auto &entry : fs::directory_iterator(dirPath)) {
    const auto &filename = entry.path().filename().string();

    if (filename.rfind("SecureBoot-", 0) == 0) {
      secureBootFileName = filename;
      break;
    }
  }

  if (secureBootFileName.empty()) {
    return std::unexpected(
        Odin::Error::Logic(errorCtx, "check secure boot", "SecureBoot EFI variable is missing"));
  }

  FD dirFd(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (!dirFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open EFI variables directory", errno));
  }

  FD secureBootFd(dirFd, secureBootFileName, O_RDONLY);
  if (!secureBootFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open SecureBoot EFI variable", errno));
  }
  uint8_t data[5];
  if (::read(secureBootFd.get(), data, sizeof(data)) != 5) {
    return std::unexpected(Odin::Error::System(errorCtx, "read SecureBoot EFI variable", errno));
  }

  return {}; // Success
}

Result<void> Validator::isKernelLockdownEnabled() {
  const std::string lockdownFilePath = "/sys/kernel/security/lockdown";

  FD lockdownFd(lockdownFilePath, O_RDONLY);
  if (!lockdownFd) {
    return std::unexpected(Odin::Error::System(errorCtx, "open kernel lockdown state", errno));
  }
  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(lockdownFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return std::unexpected(Odin::Error::System(errorCtx, "read kernel lockdown state", errno));
  }

  buffer[bytesRead] = '\0';
  const std::string lockdownStatus(buffer.data());

  bool lockdownEnabled = lockdownStatus.find("[confidentiality]") != std::string::npos;

  if (!lockdownEnabled){
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "check kernel lockdown",
        "Kernel lockdown confidentiality mode is not enabled"));
  }

  return {};
}

Result<void> Validator::isKernelModuleSignatureEnforcementEnabled() {
  const std::string sigEnforceFilePath = "/sys/module/module/parameters/sig_enforce";

  FD sigEnforceFd(sigEnforceFilePath, O_RDONLY);
  if (!sigEnforceFd) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "open module signature enforcement state", errno));
  }

  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(sigEnforceFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return std::unexpected(
        Odin::Error::System(errorCtx, "read module signature enforcement state", errno));
  }

  buffer[bytesRead] = '\0';

  std::string sigEnforce(buffer.data());
  while (!sigEnforce.empty() && (sigEnforce.back() == '\n' || sigEnforce.back() == '\r')) {
    sigEnforce.pop_back();
  }

  bool kernelModuleSignatureEnforcementEnabled = sigEnforce == "1" || sigEnforce == "Y" || sigEnforce == "y";

  if(!kernelModuleSignatureEnforcementEnabled){
    return std::unexpected(Odin::Error::Logic(
        errorCtx,
        "check module signature enforcement",
        "Kernel module signature enforcement is disabled"));
  }

  return {};
}

Result<void> Validator::isValid() {
  Result<void> secureBootEnabled                       = isSecureBootEnabled();
  Result<void> kLockdownEnabled                        = isKernelLockdownEnabled();
  Result<void> kernelModuleSignatureEnforcementEnabled = isKernelModuleSignatureEnforcementEnabled();

  if (!secureBootEnabled) {
    return std::unexpected(secureBootEnabled.error());
  }

  if (!kLockdownEnabled) {
    return std::unexpected(kLockdownEnabled.error());
  }

  if (!kernelModuleSignatureEnforcementEnabled) {
    return std::unexpected(kernelModuleSignatureEnforcementEnabled.error());
  }

  // Verifying whether unsigned modules are loadable
  const UnsignedKernelModuleLoadProbe::Result unsignedKernelModuleLoadProbeResult =
      isUnsignedKernelModuleLoadBlocked();

  if (!unsignedKernelModuleLoadProbeResult.isBlocked) {
    switch (unsignedKernelModuleLoadProbeResult.status) {
    case UnsignedKernelModuleLoadProbe::Status::kAllowed:
      return std::unexpected(Odin::Error::Logic(
          errorCtx,
          "check unsigned kernel module loading",
          "Runtime unsigned kernel modules are allowed"));
    default:
      return std::unexpected(Odin::Error::Logic(
          errorCtx,
          "check unsigned kernel module loading",
          "Unsigned kernel module probe failure"));
    }
  }

  if(!isSecureBootEnabled && !kLockdownEnabled && !kernelModuleSignatureEnforcementEnabled){
            Odin::Error::Logic(errorCtx, "validate environment", "Failed");
  }

  return {};
}
} // namespace OdinSight::System::Environment
