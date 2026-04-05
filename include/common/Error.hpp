#pragma once

#include <expected>
#include <format>
#include <string_view>
#include <system_error>

namespace Odin {

/**
 * @struct Error
 * @brief A lightweight, zero-allocation container for system and logic errors.
 *
 * This struct uses std::string_view to point to static string literals
 * (e.g., "EbpfManager"), ensuring that creating and returning errors
 * involves no heap allocations.
 */
struct Error {
  std::string_view context;
  std::string_view operation;
  std::error_code  code;
  std::string_view detail;

  /**
   * @brief Creates an Error object from a system error number (e.g., errno).
   * @param ctx The module or class name.
   * @param operation The function or action name.
   * @param err_num The raw error integer (handles negative kernel returns).
   * @return A populated Error object using the system_category.
   */
  static Error System(std::string_view ctx, std::string_view operation, int err_num) {
    return {ctx, operation, std::error_code(err_num, std::system_category()), ""};
  }

  /**
   * @brief Creates an Error object for internal logic failures (e.g., null pointers).
   * @param ctx The module or class name.
   * @param operation The function or action name.
   * @param msg A static string literal describing the specific failure.
   * @return A populated Error object with no system code.
   */
  static Error Logic(std::string_view ctx, std::string_view operation, std::string_view msg) {
    return {ctx, operation, {}, msg};
  }

  /**
   * @brief Wraps an existing error with new high-level context.
   * @param ctx The higher-level module name.
   * @param operation The higher-level operation being attempted.
   * @param prev The original error returned by a sub-component.
   */
  static Error Enrich(std::string_view ctx, std::string_view operation, const Error &prev) {
    return {ctx, operation, prev.code, prev.detail.empty() ? prev.operation : prev.detail};
  }

  /**
   * @brief Formats the error into a human-readable string.
   * @return A string in the format "[Context] Operation failed: Reason (Code)"
   */
  [[nodiscard]] std::string message() const {
    if (code) {
      return std::format("[{}] {} failed: {} ({})", context, operation, code.message(), code.value());
    }

    return std::format("[{}] {} failed: {}", context, operation, detail.empty() ? "Internal error" : detail);
  }
};

template <typename T> using Result = std::expected<T, Error>;

} // namespace Odin
