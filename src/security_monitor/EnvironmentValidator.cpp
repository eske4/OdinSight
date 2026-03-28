#include "EnvironmentValidator.hpp"
#include "system/FD.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace OdinSight::System::Environment {

bool Validator::isSecureBootEnabled() {
  const std::string dirPath = "/sys/firmware/efi/efivars/";
  std::string       secureBootFileName;

  if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
    return false;
  }

  for (const auto &entry : fs::directory_iterator(dirPath)) {
    const auto &filename = entry.path().filename().string();

    if (filename.rfind("SecureBoot-", 0) == 0) {
      secureBootFileName = filename;
      break;
    }
  }

  if (secureBootFileName.empty()) {
    return false;
  }

  FD dirFd(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (!dirFd) {
    return false;
  }

  FD secureBootFd(dirFd, secureBootFileName, O_RDONLY);
  if (!secureBootFd) {
    return false;
  }
  uint8_t data[5];
  if (::read(secureBootFd.get(), data, sizeof(data)) != 5) {
    return false;
  }

  return data[4] == 1;
}

bool Validator::isKernelLockdownEnabled() {
  const std::string lockdownFilePath = "/sys/kernel/security/lockdown";

  FD lockdownFd(lockdownFilePath, O_RDONLY);
  if (!lockdownFd) {
    return false;
  }
  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(lockdownFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return false;
  }

  buffer[bytesRead] = '\0';
  const std::string lockdownStatus(buffer.data());

  return lockdownStatus.find("[confidentiality]") != std::string::npos;
}

bool Validator::isKernelModuleLoadingEnabled() {
  const std::string modulesDisabledFilePath = "/proc/sys/kernel/modules_disabled";

  FD modulesDisabledFd(modulesDisabledFilePath, O_RDONLY);
  if (!modulesDisabledFd) {
    return false;
  }

  std::array<char, 256> buffer{};
  const ssize_t bytesRead = ::read(modulesDisabledFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return false;
  }

  buffer[bytesRead] = '\0';

  std::string modulesDisabled(buffer.data());
  while (!modulesDisabled.empty() &&
         (modulesDisabled.back() == '\n' || modulesDisabled.back() == '\r')) {
    modulesDisabled.pop_back();
  }

  return modulesDisabled == "0";
}

bool Validator::isKernelModuleSignatureEnforcementEnabled() {
  const std::string sigEnforceFilePath = "/sys/module/module/parameters/sig_enforce";

  FD sigEnforceFd(sigEnforceFilePath, O_RDONLY);
  if (!sigEnforceFd) {
    return false;
  }

  std::array<char, 256> buffer{};
  const ssize_t         bytesRead = ::read(sigEnforceFd.get(), buffer.data(), buffer.size() - 1);

  if (bytesRead <= 0) {
    return false;
  }

  buffer[bytesRead] = '\0';

  std::string sigEnforce(buffer.data());
  while (!sigEnforce.empty() && (sigEnforce.back() == '\n' || sigEnforce.back() == '\r')) {
    sigEnforce.pop_back();
  }

  return sigEnforce == "1" || sigEnforce == "Y" || sigEnforce == "y";
}

bool Validator::isValid() {
  bool secureBootEnabled                       = isSecureBootEnabled();
  bool kLockdownEnabled                        = isKernelLockdownEnabled();
  bool kernelModulesEnabled                    = isKernelModuleLoadingEnabled();
  bool kernelModuleSignatureEnforcementEnabled = isKernelModuleSignatureEnforcementEnabled();

  bool valid = true;

  /*Mandatory*/
  if (!secureBootEnabled) {
    std::cout << "Error: Secure Boot is not enabled." << std::endl;
    valid = false;
  }

  if (!kLockdownEnabled) {
    std::cout << "Error: Kernel lockdown(Confidential Mode) is not enabled." << std::endl;
    valid = false;
  }
  /*Optional*/
  if (!kernelModulesEnabled) {
    std::cout << "Warning: Kernel module loading is disabled." << std::endl;
  } else if (!kernelModuleSignatureEnforcementEnabled) {
    std::cout << "Error: Kernel module signature enforcement is disabled." << std::endl;
  }

  return valid;
}
} // namespace OdinSight::System::Environment
