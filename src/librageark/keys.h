// SPDX-License-Identifier: GPL-2.0-or-later
// GTA V key material and the AES / NG ciphers.
// Port of CodeWalker GTACrypto.cs / GTAKeys.cs (Copyright (c) 2015 Neodymium, MIT).
#pragma once

#include "rpf.h"

#include <array>
#include <functional>
#include <memory>
#include <string>

namespace rageark
{

// Game profile: exe names + key source. GTA V only for now (RDR2 would be a new profile).
struct GameProfile {
    std::string id;
    std::vector<std::string> exeNames;
    static const GameProfile &gta5();
};

struct Keys {
    std::array<uint8_t, 32> aesKey{};
    std::vector<std::array<uint32_t, 68>> ngKeys; // 101 keys, 17 subkeys x 4 words
    std::vector<uint32_t> ngDecryptTables; // 17 rounds x 16 tables x 256
    std::array<uint8_t, 256> hashLut{};
    std::array<uint32_t, 4> awcKey{};

    const uint32_t *table(int round, int t) const
    {
        return ngDecryptTables.data() + (size_t(round) * 16 + size_t(t)) * 256;
    }
};

using ProgressFn = std::function<void(const std::string &)>;

// Scan the game exe (SHA-1 window search) for the AES key; NG keys/tables come
// from the exe when present (Legacy) or from CodeWalker's magic.dat (required for Enhanced).
Keys deriveKeys(const std::string &exePath, const std::string &magicDatPath, const ProgressFn &progress = {});

// Unpack magic.dat with a known AES key (CodeWalker UseMagicData).
void applyMagicData(Keys &keys, const Bytes &magic);

// Cache of derived keys (never distributed: lives in the user's cache dir).
void saveKeysCache(const Keys &keys, const std::string &path);
std::unique_ptr<Keys> loadKeysCache(const std::string &path);

// hash used for NG key selection (GTA5Hash.CalculateHash)
uint32_t gta5Hash(const Keys &keys, const std::string &text);
uint32_t jenkHash(const uint8_t *data, size_t len);

class KeyCrypto : public Crypto
{
public:
    explicit KeyCrypto(std::shared_ptr<const Keys> keys);

    void decryptAes(uint8_t *data, size_t len) const override;
    void encryptAes(uint8_t *data, size_t len) const override;
    void decryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const override;
    void encryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const override;
    bool canEncryptNg() const override
    {
        return false; // encrypt tables: M3
    }

    const Keys &keys() const
    {
        return *m_keys;
    }
    void decryptNgWithKey(uint8_t *data, size_t len, const uint32_t *key) const;

private:
    std::shared_ptr<const Keys> m_keys;
};

} // namespace rageark
