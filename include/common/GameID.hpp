#pragma once

#include <cstdint>
#include <string_view>

namespace OdinSight::Common {

enum class GameID : uint32_t { Unknown = 0, AssaultCube, SuperTuxKart, ASAMU, BG3, NUM_GAMES };

inline std::string_view gameToString(GameID game) {
  switch (game) {
  case GameID::AssaultCube:
    return "AssaultCube";
  case GameID::SuperTuxKart:
    return "SuperTuxKart";
  case GameID::ASAMU:
    return "A Story About My Uncle";
  case GameID::BG3:
    return "Baldur's Gate 3";
  default:
    return "INVALID";
  }
}

} // namespace OdinSight::Common
