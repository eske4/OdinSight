#include "OdinEngine.hpp"
#include "system/CGroup.hpp"
#include <cstdlib>
#include <ostream>

using CGroup = OdinSight::System::CGroup;

using OdinEngine = OdinSight::Daemon::OdinEngine;
int main() {
  auto cg_res = CGroup::create("OdinSight");

  if (!cg_res) {
    std::cerr << "[FATAL] Root CGroup initialization failed\n"
              << "Reason: " << cg_res.error().message() << std::endl;
    return EXIT_FAILURE;
  }

  auto cg_root = std::move(cg_res.value());

  auto engine_res = OdinEngine::create(cg_root);

  if (!engine_res) {
    std::cerr << "[FATAL] Engine construction failed\n"
              << "Trace: " << engine_res.error().message() << std::endl;
    return EXIT_FAILURE;
  }

  auto& engine = engine_res.value();

  if (auto res = engine.init(); !res) {
    std::cerr << "[FATAL] Daemon initialization failed\n"
              << "Trace: " << res.error().message() << std::endl;
    return EXIT_FAILURE;
  }

  if (auto res = engine.run(); !res) {
    std::cerr << "[RUNTIME] Engine encountered a critical error\n"
              << "Trace: " << res.error().message() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
