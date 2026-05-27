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
       {"~/.games/AssaultCube/bin_unix/linux_64_client",
        "~/.games/AssaultCube/",
        {/*"LD_PRELOAD=~/Documents/git/ac_rhack/target/release/libac_rhack.so"*/}}},
      {GameID::SuperTuxKart,
       {"~/.games/SuperTuxKart/bin/supertuxkart",
        "~/.games/SuperTuxKart/",
        {
            "SUPERTUXKART_DATADIR=~/.games/SuperTuxKart",
            "SUPERTUXKART_ASSETS_DIR=~/.games/SuperTuxKart/data/",
            "LD_LIBRARY_PATH=~/.games/SuperTuxKart/lib:/usr/lib:/usr/lib32:/lib:/"
            "lib32",
        }}},
      {GameID::ASAMU,
       {// 1. Path to binary
        "~/.local/share/Steam/steamapps/common/A Story About My Uncle/Binaries/linux-amd64/ASAMU",

        // 2. WORKING DIRECTORY: Must be set here so ../../ hits the root folder correctly!
        "~/.local/share/Steam/steamapps/common/A Story About My Uncle/Binaries/linux-amd64/",

        {"LD_LIBRARY_PATH=~/.local/share/Steam/steamapps/common/A Story About My "
         "Uncle/Binaries/linux-amd64/:/usr/lib:/usr/lib32:/lib:/lib32"},
        false}},
      {GameID::BG3,
       {// 1. Path to binary
        "~/.local/share/Steam/steamapps/common/Baldurs Gate 3/bin/bg3",

        // 2. WORKING DIRECTORY: Must be set here so ../../ hits the root folder correctly!
        "~/.local/share/Steam/steamapps/common/Baldurs Gate 3/",

        {"LD_LIBRARY_PATH=~/.local/share/Steam/steamapps/common/Baldurs Gate "
         "3/bin/:/lib32:/usr/lib32:"},
        false}},

      {GameID::Valheim,
       {// 1. Path to binary
        "~/.local/share/Steam/steamapps/common/Valheim/valheim.x86_64",

        // 2. WORKING DIRECTORY: Must be set here so ../../ hits the root folder correctly!
        "~/.local/share/Steam/steamapps/common/Valheim/",

        {"LD_LIBRARY_PATH=~/.local/share/Steam/steamapps/common/Valheim/",
         "~/.local/share/Steam/steamapps/common/Valheim/valheim_Data/Plugins/"},
        false}},

      {GameID::Unturned,
       {// 1. Path to binary
        "~/.local/share/Steam/steamapps/common/Unturned/Unturned.x86_64",

        // 2. WORKING DIRECTORY: Must be set here so ../../ hits the root folder correctly!
        "~/.local/share/Steam/steamapps/common/Unturned/",

        {"LD_LIBRARY_PATH=~/.local/share/Steam/steamapps/common/Unturned/",
         "~/.local/share/Steam/steamapps/common/Unturned/Unturned_Data/Plugins/"},
        false}},

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
