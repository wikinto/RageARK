// SPDX-License-Identifier: GPL-2.0-or-later
#include "keystore.h"

#include <cstdlib>
#include <sys/stat.h>

#ifndef RAGEARK_MAGIC_DAT_INSTALL_PATH
#define RAGEARK_MAGIC_DAT_INSTALL_PATH ""
#endif

namespace rageark
{

static bool fileExists(const std::string &p)
{
    struct stat st {};
    return !p.empty() && ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

static std::string envOr(const char *name, const std::string &fallback)
{
    const char *v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

static void mkdirs(const std::string &dir)
{
    std::string cur;
    for (size_t i = 0; i < dir.size(); ++i) {
        cur += dir[i];
        if ((dir[i] == '/' && i > 0) || i + 1 == dir.size()) {
            ::mkdir(cur.c_str(), 0700);
        }
    }
}

std::string KeyStore::cachePath()
{
    const std::string home = envOr("HOME", "/tmp");
    return envOr("XDG_CACHE_HOME", home + "/.cache") + "/rageark/keys.dat";
}

std::string KeyStore::findMagicDat()
{
    const std::string home = envOr("HOME", "/tmp");
    const std::vector<std::string> candidates = {
        envOr("RAGEARK_MAGIC_DAT", ""),
        envOr("XDG_DATA_HOME", home + "/.local/share") + "/rageark/magic.dat",
        RAGEARK_MAGIC_DAT_INSTALL_PATH,
        "/usr/local/share/rageark/magic.dat",
        "/usr/share/rageark/magic.dat",
    };
    for (const auto &c : candidates) {
        if (fileExists(c)) {
            return c;
        }
    }
    return {};
}

std::shared_ptr<const Keys> KeyStore::loadCached()
{
    try {
        auto k = loadKeysCache(cachePath());
        return k ? std::shared_ptr<const Keys>(std::move(k)) : nullptr;
    } catch (const std::exception &) {
        return nullptr;
    }
}

std::shared_ptr<const Keys> KeyStore::fromExe(const std::string &exePath, const ProgressFn &progress)
{
    if (!fileExists(exePath)) {
        throw Error("game executable not found: " + exePath);
    }
    const std::string magic = findMagicDat();
    auto keys = std::make_shared<Keys>(deriveKeys(exePath, magic, progress));
    try {
        const std::string cache = cachePath();
        mkdirs(cache.substr(0, cache.find_last_of('/')));
        saveKeysCache(*keys, cache);
    } catch (const std::exception &) {
        // cache is an optimisation only
    }
    return keys;
}

std::shared_ptr<const Keys> KeyStore::withEncryptTables(const std::shared_ptr<const Keys> &keys, const ProgressFn &progress)
{
    if (!keys || keys->hasEncryptTables()) {
        return keys;
    }
    auto full = std::make_shared<Keys>(*keys);
    generateNgEncryptTables(*full, progress);
    try {
        const std::string cache = cachePath();
        mkdirs(cache.substr(0, cache.find_last_of('/')));
        saveKeysCache(*full, cache);
    } catch (const std::exception &) {
        // cache is an optimisation only
    }
    return full;
}

std::shared_ptr<const Keys> KeyStore::resolve(const std::string &configuredExe, const ProgressFn &progress)
{
    if (auto k = loadCached()) {
        return k;
    }
    const std::string envExe = envOr("RAGEARK_GTA_EXE", "");
    if (fileExists(envExe)) {
        return fromExe(envExe, progress);
    }
    if (fileExists(configuredExe)) {
        return fromExe(configuredExe, progress);
    }
    return nullptr;
}

} // namespace rageark
