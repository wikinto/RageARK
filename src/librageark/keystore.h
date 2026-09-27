// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "keys.h"

namespace rageark
{

// Key resolution order (ANALYSIS 4.4):
//   1. ~/.cache/rageark/keys.dat
//   2. $RAGEARK_GTA_EXE
//   3. configured exe path (ragearkrc [Keys] gta_exe, passed in by the plugin)
//   4. nullptr -> caller asks the user (exe-picker popup) and calls fromExe()
class KeyStore
{
public:
    static std::string cachePath();
    static std::string findMagicDat();

    static std::shared_ptr<const Keys> loadCached();
    static std::shared_ptr<const Keys> resolve(const std::string &configuredExe, const ProgressFn &progress = {});
    static std::shared_ptr<const Keys> fromExe(const std::string &exePath, const ProgressFn &progress = {});
    // Keys with NG encrypt tables: returns keys itself when present, else generates them
    // (one-time, seconds to minutes) and updates the cache.
    static std::shared_ptr<const Keys> withEncryptTables(const std::shared_ptr<const Keys> &keys, const ProgressFn &progress = {});
};

} // namespace rageark
