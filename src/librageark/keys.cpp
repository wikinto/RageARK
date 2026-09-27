// SPDX-License-Identifier: GPL-2.0-or-later
// Port of CodeWalker GTACrypto.cs / GTAKeys.cs (Copyright (c) 2015 Neodymium, MIT).
#include "keys.h"

#include "deflate.h"
#include "keyhashes.h"

#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <fcntl.h>
#include <mutex>
#include <random>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace rageark
{

const GameProfile &GameProfile::gta5()
{
    static const GameProfile p{"gta5", {"GTA5_Enhanced.exe", "GTA5.exe"}};
    return p;
}

// ---- .NET Framework System.Random(int seed) (Knuth subtractive generator) ----
namespace
{
class NetRandom
{
public:
    explicit NetRandom(int32_t seed)
    {
        const int32_t mbig = 0x7FFFFFFF;
        const int32_t mseed = 161803398;
        const int32_t subtraction = (seed == INT32_MIN) ? mbig : std::abs(seed);
        int32_t mj = mseed - subtraction;
        m_seed[55] = mj;
        int32_t mk = 1;
        for (int i = 1; i < 55; ++i) {
            const int ii = (21 * i) % 55;
            m_seed[ii] = mk;
            mk = mj - mk;
            if (mk < 0) {
                mk += mbig;
            }
            mj = m_seed[ii];
        }
        for (int k = 1; k < 5; ++k) {
            for (int i = 1; i < 56; ++i) {
                // wrap like C# int arithmetic
                m_seed[i] = int32_t(uint32_t(m_seed[i]) - uint32_t(m_seed[1 + (i + 30) % 55]));
                if (m_seed[i] < 0) {
                    m_seed[i] += mbig;
                }
            }
        }
    }

    int32_t sample()
    {
        if (++m_inext >= 56) {
            m_inext = 1;
        }
        if (++m_inextp >= 56) {
            m_inextp = 1;
        }
        int32_t r = int32_t(uint32_t(m_seed[m_inext]) - uint32_t(m_seed[m_inextp]));
        if (r == 0x7FFFFFFF) {
            --r;
        }
        if (r < 0) {
            r += 0x7FFFFFFF;
        }
        m_seed[m_inext] = r;
        return r;
    }

    void nextBytes(uint8_t *out, size_t n)
    {
        for (size_t i = 0; i < n; ++i) {
            out[i] = uint8_t(sample() % 256);
        }
    }

private:
    int32_t m_seed[56] = {};
    int m_inext = 0;
    int m_inextp = 21;
};

void sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    unsigned int outLen = 20;
    EVP_Digest(data, len, out, &outLen, EVP_sha1(), nullptr);
}

void aesEcb(const uint8_t key[32], uint8_t *data, size_t len, bool encrypt)
{
    const size_t n = len - len % 16;
    if (n == 0) {
        return;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw Error("EVP_CIPHER_CTX_new failed");
    }
    int outl = 0;
    bool ok = EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr, encrypt ? 1 : 0) == 1;
    ok = ok && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
    ok = ok && EVP_CipherUpdate(ctx, data, &outl, data, int(n)) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok || size_t(outl) != n) {
        throw Error("AES operation failed");
    }
}

// Parallel SHA-1 window search over 8-byte aligned offsets (CodeWalker HashSearch).
std::vector<Bytes> searchHashes(const Bytes &exe, const uint8_t (*hashes)[20], size_t count, size_t length)
{
    std::vector<Bytes> result(count);
    if (exe.size() < length) {
        return result;
    }
    const size_t positions = (exe.size() - length) / 8 + 1;
    const unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    std::mutex mtx;
    std::atomic<size_t> found{0};
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t) {
        pool.emplace_back([&, t] {
            uint8_t h[20];
            for (size_t i = t; i < positions && found.load() < count; i += threads) {
                const uint8_t *w = exe.data() + i * 8;
                sha1(w, length, h);
                for (size_t j = 0; j < count; ++j) {
                    if (std::memcmp(h, hashes[j], 20) == 0) {
                        std::lock_guard<std::mutex> lock(mtx);
                        if (result[j].empty()) {
                            result[j].assign(w, w + length);
                            ++found;
                        }
                    }
                }
            }
        });
    }
    for (auto &th : pool) {
        th.join();
    }
    return result;
}

void readNgKeys(Keys &keys, const uint8_t *p)
{
    keys.ngKeys.assign(101, {});
    for (size_t i = 0; i < 101; ++i) {
        for (size_t w = 0; w < 68; ++w) {
            keys.ngKeys[i][w] = readU32(p + i * 272 + w * 4);
        }
    }
}

void readNgTables(Keys &keys, const uint8_t *p)
{
    keys.ngDecryptTables.resize(17 * 16 * 256);
    for (size_t i = 0; i < keys.ngDecryptTables.size(); ++i) {
        keys.ngDecryptTables[i] = readU32(p + i * 4);
    }
}
} // namespace

uint32_t jenkHash(const uint8_t *data, size_t len)
{
    uint32_t h = 0;
    for (size_t i = 0; i < len; ++i) {
        h += data[i];
        h += h << 10;
        h ^= h >> 6;
    }
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
    return h;
}

uint32_t gta5Hash(const Keys &keys, const std::string &text)
{
    uint32_t result = 0;
    for (unsigned char c : text) {
        const uint32_t temp = 1025u * (keys.hashLut[c] + result);
        result = (temp >> 6) ^ temp;
    }
    return 32769u * (((9u * result) >> 11) ^ (9u * result));
}

void applyMagicData(Keys &keys, const Bytes &magic)
{
    NetRandom rnd(int32_t(jenkHash(keys.aesKey.data(), keys.aesKey.size())));
    Bytes db(magic.size());
    Bytes r(magic.size());
    std::copy(magic.begin(), magic.end(), db.begin());
    for (int k = 0; k < 4; ++k) {
        rnd.nextBytes(r.data(), r.size());
        for (size_t i = 0; i < db.size(); ++i) {
            db[i] = uint8_t(db[i] - r[i]);
        }
    }
    aesEcb(keys.aesKey.data(), db.data(), db.size(), false);
    auto b = tryInflateRaw(db.data(), db.size(), 306272);
    if (!b || b->size() < 306272) {
        throw Error("magic.dat could not be decoded (wrong AES key or wrong magic.dat)");
    }
    const uint8_t *p = b->data();
    readNgKeys(keys, p);
    readNgTables(keys, p + 27472);
    std::copy(p + 306000, p + 306256, keys.hashLut.begin());
    for (size_t i = 0; i < 4; ++i) {
        keys.awcKey[i] = readU32(p + 306256 + i * 4);
    }
}

Keys deriveKeys(const std::string &exePath, const std::string &magicDatPath, const ProgressFn &progress)
{
    auto say = [&](const std::string &s) {
        if (progress) {
            progress(s);
        }
    };
    say("Reading " + exePath);
    const Bytes exe = readWholeFile(exePath);

    Keys keys;
    say("Searching for AES key...");
    auto aes = searchHashes(exe, &keyhashes::AesKey, 1, 32);
    if (aes[0].empty()) {
        throw Error("AES key not found: " + exePath + " is not a supported GTA V executable");
    }
    std::copy(aes[0].begin(), aes[0].end(), keys.aesKey.begin());

    if (!magicDatPath.empty()) {
        say("Decoding magic.dat...");
        applyMagicData(keys, readWholeFile(magicDatPath));
        return keys;
    }

    // no magic.dat: full scan (works for Legacy exes that contain the NG tables)
    say("Searching for NG keys...");
    auto ng = searchHashes(exe, keyhashes::NgKeys, 101, 0x110);
    say("Searching for NG decrypt tables...");
    auto tabs = searchHashes(exe, keyhashes::NgDecryptTables, 272, 0x400);
    auto lut = searchHashes(exe, &keyhashes::HashLut, 1, 0x100);
    for (const auto &k : ng) {
        if (k.empty()) {
            throw Error("NG keys not found in the executable; magic.dat is required (GTA V Enhanced)");
        }
    }
    for (const auto &t : tabs) {
        if (t.empty()) {
            throw Error("NG tables not found in the executable; magic.dat is required (GTA V Enhanced)");
        }
    }
    if (lut[0].empty()) {
        throw Error("hash lookup table not found in the executable");
    }
    Bytes keyBlob;
    for (const auto &k : ng) {
        keyBlob.insert(keyBlob.end(), k.begin(), k.end());
    }
    readNgKeys(keys, keyBlob.data());
    Bytes tabBlob;
    for (const auto &t : tabs) {
        tabBlob.insert(tabBlob.end(), t.begin(), t.end());
    }
    readNgTables(keys, tabBlob.data());
    std::copy(lut[0].begin(), lut[0].end(), keys.hashLut.begin());
    return keys;
}


// ---- NG encryption tables (CodeWalker GTAKeys.Generate, "Calculating NG encryption tables") ----
namespace
{
struct GaussRow {
    uint64_t a[16] = {};
    bool b = false;
    bool get(int i) const
    {
        return (a[i >> 6] >> (i & 63)) & 1;
    }
    void set(int i)
    {
        a[i >> 6] |= uint64_t(1) << (i & 63);
    }
    void operator^=(const GaussRow &o)
    {
        for (int i = 0; i < 16; ++i) {
            a[i] ^= o.a[i];
        }
        b ^= o.b;
    }
};

// RandomGauss.Solve(tables, inByte0..3, outByte, outBit): the 1024 one-hot coefficients of one
// output bit of the inverse round as XOR of four per-byte tables (gauge fixed like CodeWalker).
std::vector<bool> gaussSolveBit(const uint32_t *tables, const int in[4], int outByte, int outBit, uint64_t seed)
{
    std::mt19937_64 rng(seed);
    std::vector<GaussRow> pivots(1024);
    pivots[0].set(0);
    pivots[0].b = true;
    uint8_t enc[16], dec[16];
    for (int pivotIdx = 1; pivotIdx < 1024; ++pivotIdx) {
        for (int attempt = 0;; ++attempt) {
            if (attempt > 1000000) {
                throw Error("NG encrypt table generation did not converge");
            }
            GaussRow row;
            if (pivotIdx == 0x2FF || pivotIdx == 0x3FF) {
                row.set(pivotIdx);
                row.b = true;
            } else {
                for (int i = 0; i < 16; i += 8) {
                    const uint64_t r = rng();
                    std::memcpy(enc + i, &r, 8);
                }
                for (int w = 0; w < 4; ++w) { // DecryptNGRoundA with a zero key
                    const uint32_t x = tables[(4 * w + 0) * 256 + enc[4 * w + 0]] ^ tables[(4 * w + 1) * 256 + enc[4 * w + 1]]
                        ^ tables[(4 * w + 2) * 256 + enc[4 * w + 2]] ^ tables[(4 * w + 3) * 256 + enc[4 * w + 3]];
                    writeU32(dec + 4 * w, x);
                }
                row.set(0 + dec[in[0]]);
                row.set(256 + dec[in[1]]);
                row.set(512 + dec[in[2]]);
                row.set(768 + dec[in[3]]);
                row.b = (enc[outByte] >> outBit) & 1;
            }
            // eliminate with pivots below pivotIdx (pivot k has no bits below k)
            for (int k = 0; k < pivotIdx;) {
                const int word = k >> 6;
                const uint64_t bits = row.a[word] >> (k & 63);
                if (bits == 0) {
                    k = (word + 1) << 6;
                    continue;
                }
                k += __builtin_ctzll(bits);
                if (k >= pivotIdx) {
                    break;
                }
                row ^= pivots[size_t(k)];
                ++k;
            }
            if (row.get(pivotIdx)) {
                pivots[size_t(pivotIdx)] = row;
                break;
            }
        }
    }
    std::vector<bool> result(1024);
    for (int j = 1023; j >= 0; --j) {
        const bool val = pivots[size_t(j)].b;
        result[size_t(j)] = val;
        for (int k = 0; k < j; ++k) {
            if (pivots[size_t(k)].get(j)) {
                pivots[size_t(k)].b ^= val;
            }
        }
    }
    return result;
}

template<typename F>
void parallelFor(int count, F f)
{
    const int threads = int(std::max(1u, std::thread::hardware_concurrency()));
    std::atomic<int> next{0};
    std::exception_ptr failure;
    std::mutex mtx;
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&] {
            for (int i = next++; i < count; i = next++) {
                try {
                    f(i);
                } catch (...) {
                    std::lock_guard<std::mutex> lock(mtx);
                    failure = std::current_exception();
                }
            }
        });
    }
    for (auto &th : pool) {
        th.join();
    }
    if (failure) {
        std::rethrow_exception(failure);
    }
}

// RandomGauss.Solve(tables): encrypt tables for a round-A round.
void solveRoundA(const uint32_t *tables, uint32_t *out)
{
    std::fill(out, out + 16 * 256, 0u);
    std::mutex mtx;
    parallelFor(128, [&](int bitIdx) {
        const int outByte = bitIdx / 8;
        const int uintIdx = outByte / 4;
        const int in[4] = {4 * uintIdx, 4 * uintIdx + 1, 4 * uintIdx + 2, 4 * uintIdx + 3};
        const int z = bitIdx % 32;
        const auto bits = gaussSolveBit(tables, in, outByte, bitIdx % 8, 0x5241474541524bULL + uint64_t(bitIdx));
        std::lock_guard<std::mutex> lock(mtx);
        for (int i = 0; i < 256; ++i) {
            for (int j = 0; j < 4; ++j) {
                if (bits[size_t(256 * j + i)]) {
                    out[in[j] * 256 + i] |= uint32_t(1) << z;
                }
            }
        }
    });
}

// LookUpTableGenerator.BuildLUTs2: inverse of a round-B round as 16 byte LUTs.
void buildLuts(const uint32_t *tables, NgLut *luts)
{
    auto t = [tables](int i) {
        return tables + size_t(i) * 256;
    };
    std::vector<std::array<uint8_t, 65536>> temp(16);
    std::vector<Bytes> tempLuts(16, Bytes(size_t(1) << 24));
    // output word w of the decrypt round reads bytes {w, w+4.., ...}: words 0..3 use
    // (t0,t7,t10,t13) (t1,t4,t11,t14) (t2,t5,t8,t15) (t3,t6,t9,t12) for b0..b3
    static constexpr int use[4][4] = {{0, 7, 10, 13}, {1, 4, 11, 14}, {2, 5, 8, 15}, {3, 6, 9, 12}};
    parallelFor(256, [&](int b3) {
        for (int b2 = 0; b2 < 256; ++b2) {
            for (int b1 = 0; b1 < 256; ++b1) {
                uint32_t p[4];
                for (int w = 0; w < 4; ++w) {
                    p[w] = t(use[w][1])[b1] ^ t(use[w][2])[b2] ^ t(use[w][3])[b3];
                }
                for (int b0 = 0; b0 < 256; ++b0) {
                    for (int w = 0; w < 4; ++w) {
                        const uint32_t x = t(use[w][0])[b0] ^ p[w];
                        if (x < 65536) {
                            temp[size_t(use[w][0])][x] = uint8_t(b0);
                            temp[size_t(use[w][1])][x] = uint8_t(b1);
                            temp[size_t(use[w][2])][x] = uint8_t(b2);
                            temp[size_t(use[w][3])][x] = uint8_t(b3);
                        }
                        if ((x & 0xFF) == 0) {
                            tempLuts[size_t(use[w][0])][x >> 8] = uint8_t(b0);
                            tempLuts[size_t(use[w][1])][x >> 8] = uint8_t(b1);
                            tempLuts[size_t(use[w][2])][x >> 8] = uint8_t(b2);
                            tempLuts[size_t(use[w][3])][x >> 8] = uint8_t(b3);
                        }
                    }
                }
            }
        }
    });
    for (int i = 0; i < 16; ++i) {
        NgLut &lut = luts[i];
        for (int blk = 0; blk < 256; ++blk) {
            const uint8_t *xl = temp[size_t(i)].data() + 256 * blk;
            std::copy(xl, xl + 256, lut.lut0[xl[0]].begin());
        }
        for (int blk = 0; blk < 256; ++blk) {
            const uint8_t *xl = tempLuts[size_t(i)].data() + 256 * blk;
            std::copy(xl, xl + 256, lut.lut1[xl[0]].begin());
        }
        for (int blk = 0; blk < 65536; ++blk) {
            lut.indices[size_t(blk)] = tempLuts[size_t(i)][size_t(256) * size_t(blk)];
        }
    }
}
} // namespace

void generateNgEncryptTables(Keys &keys, const ProgressFn &progress)
{
    if (keys.ngDecryptTables.size() != 17 * 16 * 256) {
        throw Error("NG decrypt tables are not loaded");
    }
    auto say = [&](const std::string &s) {
        if (progress) {
            progress(s);
        }
    };
    std::vector<uint32_t> enc(3 * 16 * 256);
    std::vector<NgLut> luts(14 * 16);
    const int roundsA[3] = {0, 1, 16};
    for (int i = 0; i < 3; ++i) {
        say("Calculating NG encryption tables (round " + std::to_string(roundsA[i] + 1) + "/17)...");
        solveRoundA(keys.table(roundsA[i], 0), enc.data() + size_t(i) * 16 * 256);
    }
    for (int r = 2; r <= 15; ++r) {
        say("Calculating NG encryption tables (round " + std::to_string(r + 1) + "/17)...");
        buildLuts(keys.table(r, 0), luts.data() + size_t(r - 2) * 16);
    }
    keys.ngEncryptTables = std::move(enc);
    keys.ngEncryptLuts = std::move(luts);
}

// ---- cache ----
static const char CacheMagic[8] = {'R', 'A', 'G', 'E', 'K', 'E', 'Y', '1'};
static const char CacheMagic2[8] = {'R', 'A', 'G', 'E', 'K', 'E', 'Y', '2'}; // + NG encrypt tables
static constexpr size_t CacheSize = 8 + 32 + 101 * 272 + 17 * 16 * 256 * 4 + 256 + 16;
static constexpr size_t EncSize = 3 * 16 * 256 * 4 + 14 * 16 * sizeof(NgLut);
static_assert(sizeof(NgLut) == 3 * 65536, "NgLut must be tightly packed");

void saveKeysCache(const Keys &keys, const std::string &path)
{
    const bool withEnc = keys.hasEncryptTables();
    Bytes b;
    b.reserve(CacheSize + (withEnc ? EncSize : 0));
    b.insert(b.end(), withEnc ? CacheMagic2 : CacheMagic, (withEnc ? CacheMagic2 : CacheMagic) + 8);
    b.insert(b.end(), keys.aesKey.begin(), keys.aesKey.end());
    for (const auto &k : keys.ngKeys) {
        for (uint32_t w : k) {
            appendU32(b, w);
        }
    }
    for (uint32_t w : keys.ngDecryptTables) {
        appendU32(b, w);
    }
    b.insert(b.end(), keys.hashLut.begin(), keys.hashLut.end());
    for (uint32_t w : keys.awcKey) {
        appendU32(b, w);
    }
    if (withEnc) {
        for (uint32_t w : keys.ngEncryptTables) {
            appendU32(b, w);
        }
        for (const auto &lut : keys.ngEncryptLuts) {
            const auto *p = reinterpret_cast<const uint8_t *>(&lut);
            b.insert(b.end(), p, p + sizeof(NgLut));
        }
    }
    // derived keys are private to the user
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        throw Error("cannot write key cache " + tmp);
    }
    size_t off = 0;
    while (off < b.size()) {
        const ssize_t n = ::write(fd, b.data() + off, b.size() - off);
        if (n <= 0) {
            ::close(fd);
            throw Error("cannot write key cache " + tmp);
        }
        off += size_t(n);
    }
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        throw Error("cannot move key cache into place: " + path);
    }
}

std::unique_ptr<Keys> loadKeysCache(const std::string &path)
{
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0 || (size_t(st.st_size) != CacheSize && size_t(st.st_size) != CacheSize + EncSize)) {
        return nullptr;
    }
    const Bytes b = readWholeFile(path);
    const bool withEnc = b.size() == CacheSize + EncSize;
    if (std::memcmp(b.data(), withEnc ? CacheMagic2 : CacheMagic, 8) != 0) {
        return nullptr;
    }
    auto keys = std::make_unique<Keys>();
    const uint8_t *p = b.data() + 8;
    std::copy(p, p + 32, keys->aesKey.begin());
    p += 32;
    readNgKeys(*keys, p);
    p += 101 * 272;
    readNgTables(*keys, p);
    p += 17 * 16 * 256 * 4;
    std::copy(p, p + 256, keys->hashLut.begin());
    p += 256;
    for (size_t i = 0; i < 4; ++i) {
        keys->awcKey[i] = readU32(p + i * 4);
    }
    p += 16;
    if (withEnc) {
        keys->ngEncryptTables.resize(3 * 16 * 256);
        for (size_t i = 0; i < keys->ngEncryptTables.size(); ++i) {
            keys->ngEncryptTables[i] = readU32(p + 4 * i);
        }
        p += 3 * 16 * 256 * 4;
        keys->ngEncryptLuts.resize(14 * 16);
        for (auto &lut : keys->ngEncryptLuts) {
            std::memcpy(&lut, p, sizeof(NgLut));
            p += sizeof(NgLut);
        }
    }
    return keys;
}

// ---- ciphers ----
KeyCrypto::KeyCrypto(std::shared_ptr<const Keys> keys)
    : m_keys(std::move(keys))
{
}

void KeyCrypto::decryptAes(uint8_t *data, size_t len) const
{
    aesEcb(m_keys->aesKey.data(), data, len, false);
}

void KeyCrypto::encryptAes(uint8_t *data, size_t len) const
{
    aesEcb(m_keys->aesKey.data(), data, len, true);
}

namespace
{
inline void roundA(uint8_t *b, const uint32_t *key, const Keys &k, int round)
{
    uint32_t x[4];
    for (int w = 0; w < 4; ++w) {
        x[w] = k.table(round, 4 * w)[b[4 * w]] ^ k.table(round, 4 * w + 1)[b[4 * w + 1]] ^ k.table(round, 4 * w + 2)[b[4 * w + 2]]
            ^ k.table(round, 4 * w + 3)[b[4 * w + 3]] ^ key[w];
    }
    for (int w = 0; w < 4; ++w) {
        writeU32(b + 4 * w, x[w]);
    }
}

inline void roundB(uint8_t *b, const uint32_t *key, const Keys &k, int round)
{
    static constexpr int idx[4][4] = {{0, 7, 10, 13}, {1, 4, 11, 14}, {2, 5, 8, 15}, {3, 6, 9, 12}};
    uint32_t x[4];
    for (int w = 0; w < 4; ++w) {
        x[w] = k.table(round, idx[w][0])[b[idx[w][0]]] ^ k.table(round, idx[w][1])[b[idx[w][1]]] ^ k.table(round, idx[w][2])[b[idx[w][2]]]
            ^ k.table(round, idx[w][3])[b[idx[w][3]]] ^ key[w];
    }
    for (int w = 0; w < 4; ++w) {
        writeU32(b + 4 * w, x[w]);
    }
}
} // namespace

void KeyCrypto::decryptNgWithKey(uint8_t *data, size_t len, const uint32_t *key) const
{
    const Keys &k = *m_keys;
    for (size_t off = 0; off + 16 <= len; off += 16) {
        uint8_t *b = data + off;
        roundA(b, key + 0, k, 0);
        roundA(b, key + 4, k, 1);
        for (int r = 2; r <= 15; ++r) {
            roundB(b, key + 4 * r, k, r);
        }
        roundA(b, key + 64, k, 16);
    }
}

const uint32_t *KeyCrypto::ngKey(const std::string &name, uint32_t length) const
{
    const uint32_t idx = (gta5Hash(*m_keys, name) + length + 61u) % 101u;
    return m_keys->ngKeys[idx].data();
}

void KeyCrypto::decryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const
{
    decryptNgWithKey(data, len, ngKey(name, length));
}

void KeyCrypto::encryptNgWithKey(uint8_t *data, size_t len, const uint32_t *key) const
{
    const Keys &k = *m_keys;
    if (!k.hasEncryptTables()) {
        throw Error("NG encryption tables are not available");
    }
    auto roundA = [&](uint8_t *b, const uint32_t *rk, int tableSet) {
        const uint32_t *t = k.ngEncryptTables.data() + size_t(tableSet) * 16 * 256;
        uint8_t x[16];
        for (int i = 0; i < 16; ++i) {
            x[i] = b[i] ^ uint8_t(rk[i / 4] >> (8 * (i % 4)));
        }
        for (int w = 0; w < 4; ++w) {
            writeU32(b + 4 * w, t[(4 * w) * 256 + x[4 * w]] ^ t[(4 * w + 1) * 256 + x[4 * w + 1]] ^ t[(4 * w + 2) * 256 + x[4 * w + 2]] ^ t[(4 * w + 3) * 256 + x[4 * w + 3]]);
        }
    };
    auto roundB = [&](uint8_t *b, const uint32_t *rk, int round) {
        const NgLut *lut = k.ngEncryptLuts.data() + size_t(round - 2) * 16;
        uint8_t x[16];
        for (int i = 0; i < 16; ++i) {
            x[i] = b[i] ^ uint8_t(rk[i / 4] >> (8 * (i % 4)));
        }
        uint32_t words[4];
        for (int w = 0; w < 4; ++w) {
            words[w] = readU32(x + 4 * w);
        }
        for (int j = 0; j < 16; ++j) {
            b[j] = lut[j].lookUp(words[(j % 4 + j / 4) % 4]);
        }
    };
    for (size_t off = 0; off + 16 <= len; off += 16) {
        uint8_t *b = data + off;
        roundA(b, key + 64, 2); // round 16
        for (int r = 15; r >= 2; --r) {
            roundB(b, key + 4 * r, r);
        }
        roundA(b, key + 4, 1);
        roundA(b, key + 0, 0);
    }
}

void KeyCrypto::encryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const
{
    encryptNgWithKey(data, len, ngKey(name, length));
}

} // namespace rageark
