#include "GameWhitelist.hpp"
#include "common/GameID.hpp"
#include <unordered_map>

// Using an anonymous namespace keeps this map "private" to this file.
namespace {

using OdinSight::Daemon::Launcher::GameEntry;
using GameID = OdinSight::Common::GameID;

const std::unordered_map<GameID, GameEntry>& getWhitelist() {
  static const std::unordered_map<GameID, GameEntry> whitelist = {
      {GameID::AssaultCube,
       {
           "~/.games/AssaultCube_v1.2.0.2/bin_unix/linux_64_client",
           "~/.games/AssaultCube_v1.2.0.2/",
           {} // No custom environment
       }},
      {GameID::SuperTuxKart,
       {
           "~/.games/SuperTuxKart-1.5-linux-x86_64/bin/supertuxkart",
           "~/.games/SuperTuxKart-1.5-linux-x86_64/",
           {
               "SUPERTUXKART_DATADIR=~/.games/SuperTuxKart-1.5-linux-x86_64",
               "SUPERTUXKART_ASSETS_DIR=~/.games/SuperTuxKart-1.5-linux-x86_64/data/",
               "LD_LIBRARY_PATH=~/.games/SuperTuxKart-1.5-linux-x86_64/lib:/usr/lib:/usr/lib32:/lib:/lib32",
           }
       }},
      // Add games here
  };
  return whitelist;
}
} // namespace
// namespace

namespace OdinSight::Daemon::Launcher {

std::optional<GameEntry> findGame(const GameID& game_id) {
  const auto& whitelist = getWhitelist();
  auto        iterator  = whitelist.find(game_id);

  if (iterator != whitelist.end()) { return iterator->second; }
  return std::nullopt;
}

} // namespace OdinSight::Daemon::Launcher
