#include <filesystem>
#include <pwd.h>
#include <string>
#include <sys/types.h>

namespace OdinSight::Util::FSUtil {

std::filesystem::path expandToFullPath(std::string path_str, uid_t uid) {
  const size_t tilde_pos = path_str.find('~');
  if (tilde_pos == std::string::npos) { return std::filesystem::weakly_canonical(path_str); }

  std::string home_dir;
  if (const struct passwd* pwd = ::getpwuid(uid); pwd != nullptr && pwd->pw_dir != nullptr) {
    home_dir = pwd->pw_dir;
  }

  // Trim trailing slash efficiently if present
  if (!home_dir.empty() && home_dir.back() == '/') { home_dir.pop_back(); }

  path_str.replace(tilde_pos, 1, home_dir);
  return std::filesystem::weakly_canonical(path_str);
}

} // namespace OdinSight::Util::FSUtil
