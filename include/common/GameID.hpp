#pragma once

#include <cstdint>
#include <string_view>

namespace OdinSight::Common {

enum class GameID : uint32_t { Unknown = 0, AssaultCube, SuperTuxKart, NUM_GAMES };

inline std::string_view gameToString(GameID game) {
    switch (game) {
    case GameID::AssaultCube:
        return "AssaultCube";
    case GameID::SuperTuxKart:
        return "SuperTuxKart";
    default:
        return "INVALID";
    }
}

}
