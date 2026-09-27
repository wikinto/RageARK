// SPDX-License-Identifier: MIT
// Port of CodeWalker AwcFile.cs (AWC container, RS-XXTEA, IMA ADPCM, WAV export).
#include "awc.h"

#include "keys.h"

#include <algorithm>
#include <cstdio>
#include <memory>

namespace rageark
{

namespace
{
constexpr uint32_t MagicLE = 0x54414441; // "ADAT"
constexpr uint32_t MagicBE = 0x41444154;
constexpr uint32_t Delta = 0x9E3779B9;

enum ChunkType : uint8_t {
    ChunkData = 0x55,
    ChunkFormat = 0xFA,
    ChunkMid = 0x68,
    ChunkStreamFormat = 0x48,
    ChunkSeekTable = 0xA3,
};

// CodeWalker DataReader over a MemoryStream: reads past the end yield zeros.
class Reader
{
public:
    Reader(const uint8_t *data, size_t len, bool bigEndian)
        : m_data(data)
        , m_len(len)
        , m_be(bigEndian)
    {
    }
    size_t pos = 0;

    Bytes bytes(size_t n)
    {
        Bytes out(n, 0);
        if (pos < m_len) {
            std::copy_n(m_data + pos, std::min(n, m_len - pos), out.begin());
        }
        pos += n;
        return out;
    }
    uint64_t uint(size_t n)
    {
        Bytes b = bytes(n);
        if (m_be) {
            std::reverse(b.begin(), b.end());
        }
        uint64_t v = 0;
        for (size_t i = 0; i < n; ++i) {
            v |= uint64_t(b[i]) << (8 * i);
        }
        return v;
    }
    uint32_t u32()
    {
        return uint32_t(uint(4));
    }
    uint16_t u16()
    {
        return uint16_t(uint(2));
    }
    uint8_t u8()
    {
        return uint8_t(uint(1));
    }
    uint64_t u64()
    {
        return uint(8);
    }

private:
    const uint8_t *m_data;
    size_t m_len;
    bool m_be;
};

struct StreamFormat {
    uint32_t id = 0;
    uint32_t samples = 0;
    uint16_t samplesPerSecond = 0;
    uint8_t codec = 0;
};

struct Format {
    uint32_t samples = 0;
    uint16_t samplesPerSecond = 0;
    uint8_t codec = 0;
};

struct ChunkInfo {
    uint8_t type = 0;
    uint32_t size = 0;
    uint32_t offset = 0;
};

struct Channel {
    int32_t blockCount = 0;
    Bytes data;
};

struct Stream {
    uint32_t id = 0;
    std::vector<ChunkInfo> chunks;
    std::optional<Bytes> data;
    std::optional<Format> format;
    bool hasMidi = false;
    // streamformat chunk
    bool hasStreamFormatChunk = false;
    uint32_t blockCount = 0, blockSize = 0, channelCount = 0;
    std::vector<StreamFormat> channels;
    std::vector<uint32_t> seekTable;
    // multichannel
    std::vector<std::vector<Channel>> blocks; // on the source stream
    const Stream *source = nullptr;
    std::optional<StreamFormat> streamFormat;
    int channelIndex = 0;

    uint8_t codec() const
    {
        return streamFormat ? streamFormat->codec : format ? format->codec : 0;
    }
    uint32_t sampleCount() const
    {
        return format ? format->samples : streamFormat ? streamFormat->samples : 0;
    }
    uint32_t samplesPerSecond() const
    {
        return format ? format->samplesPerSecond : streamFormat ? streamFormat->samplesPerSecond : 0;
    }
    bool rawAvailable() const
    {
        return data.has_value() || streamFormat.has_value();
    }
    Bytes rawData() const
    {
        if (streamFormat && !data) {
            Bytes out;
            if (source) {
                for (const auto &blk : source->blocks) {
                    if (size_t(channelIndex) < blk.size()) {
                        out.insert(out.end(), blk[size_t(channelIndex)].data.begin(), blk[size_t(channelIndex)].data.end());
                    }
                }
            }
            return out;
        }
        if (!data) {
            throw Error("stream has no audio data");
        }
        return *data;
    }
    uint64_t rawSize() const
    {
        if (streamFormat && !data) {
            uint64_t n = 0;
            if (source) {
                for (const auto &blk : source->blocks) {
                    if (size_t(channelIndex) < blk.size()) {
                        n += blk[size_t(channelIndex)].data.size();
                    }
                }
            }
            return n;
        }
        return data ? data->size() : 0;
    }
};

void xxteaDecrypt(uint32_t *blocks, int n, const std::array<uint32_t, 4> &key)
{
    if (n == 0) {
        throw Error("AWC: empty encrypted block");
    }
    uint32_t a, b = blocks[0];
    uint32_t i = uint32_t(Delta * uint32_t(6 + 52 / n));
    do {
        for (int bi = n - 1; bi >= 0; --bi) {
            a = blocks[(bi > 0 ? bi : n) - 1];
            b = blocks[bi] -= (((a >> 5) ^ (b << 2)) + ((b >> 3) ^ (a << 4))) ^ ((i ^ b) + (key[(uint32_t(bi) & 3) ^ ((i >> 2) & 3)] ^ a ^ 0x7B3A207Fu));
        }
        i -= Delta;
    } while (i != 0);
}

void xxteaEncrypt(uint32_t *blocks, int n, const std::array<uint32_t, 4> &key)
{
    if (n == 0) {
        throw Error("AWC: empty encrypted block");
    }
    int rounds = 6 + 52 / n;
    uint32_t sum = 0, y, z = blocks[n - 1];
    do {
        sum += Delta;
        const uint32_t e = (sum >> 2) & 3;
        for (int p = 0; p < n; ++p) {
            y = blocks[(p + 1) % n];
            z = blocks[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(uint32_t(p) & 3) ^ e] ^ z ^ 0x7B3A207Fu));
        }
    } while (--rounds != 0);
}

template<typename F>
void withWords(uint8_t *data, size_t len, F f)
{
    if (len % 4 != 0) {
        throw Error("AWC: encrypted data length is not a multiple of 4");
    }
    std::vector<uint32_t> w(len / 4);
    for (size_t i = 0; i < w.size(); ++i) {
        w[i] = readU32(data + 4 * i);
    }
    f(w.data(), int(w.size()));
    for (size_t i = 0; i < w.size(); ++i) {
        writeU32(data + 4 * i, w[i]);
    }
}

Bytes makeWav(const Bytes &pcm, uint32_t samplesPerSecond)
{
    Bytes w;
    w.reserve(44 + pcm.size());
    auto put = [&w](const char *s) {
        w.insert(w.end(), s, s + 4);
    };
    auto u16 = [&w](uint16_t v) {
        w.push_back(uint8_t(v));
        w.push_back(uint8_t(v >> 8));
    };
    put("RIFF");
    appendU32(w, uint32_t(36 + pcm.size()));
    put("WAVE");
    put("fmt ");
    appendU32(w, 16);
    u16(1); // PCM
    u16(1); // mono
    appendU32(w, samplesPerSecond);
    appendU32(w, samplesPerSecond * 2);
    u16(2);
    u16(16);
    put("data");
    appendU32(w, uint32_t(pcm.size()));
    w.insert(w.end(), pcm.begin(), pcm.end());
    return w;
}
} // namespace

void awcDecrypt(uint8_t *data, size_t len, const std::array<uint32_t, 4> &key)
{
    withWords(data, len, [&](uint32_t *w, int n) {
        xxteaDecrypt(w, n, key);
    });
}

void awcEncrypt(uint8_t *data, size_t len, const std::array<uint32_t, 4> &key)
{
    withWords(data, len, [&](uint32_t *w, int n) {
        xxteaEncrypt(w, n, key);
    });
}

Bytes decodeAdpcm(const Bytes &data, int sampleCount)
{
    static constexpr int indexTable[16] = {-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8};
    static constexpr int16_t stepTable[89] = {7,     8,     9,     10,    11,    12,    13,    14,    16,    17,    19,    21,    23,    25,    28,
                                              31,    34,    37,    41,    45,    50,    55,    60,    66,    73,    80,    88,    97,    107,   118,
                                              130,   143,   157,   173,   190,   209,   230,   253,   279,   307,   337,   371,   408,   449,   494,
                                              544,   598,   658,   724,   796,   876,   963,   1060,  1166,  1282,  1411,  1552,  1707,  1878,  2066,
                                              2272,  2499,  2749,  3024,  3327,  3660,  4026,  4428,  4871,  5358,  5894,  6484,  7132,  7845,  8630,
                                              9493,  10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767};
    Bytes pcm(data.size() * 4, 0);
    int predictor = 0, stepIndex = 0;
    size_t rd = 0, wr = 0;
    int bytesInBlock = 0;
    auto nibble = [&](uint8_t n) {
        const int step = stepTable[stepIndex];
        int diff = ((((n & 7) << 1) + 1) * step) >> 3;
        if (n & 8) {
            diff = -diff;
        }
        predictor += diff; // CodeWalker does not clamp the predictor itself
        stepIndex = std::clamp(stepIndex + indexTable[n], 0, 88);
        const int s = std::clamp(predictor, -32768, 32767);
        pcm[wr] = uint8_t(s & 0xFF);
        pcm[wr + 1] = uint8_t((s >> 8) & 0xFF);
        wr += 2;
    };
    while (rd < data.size() && sampleCount > 0) {
        if (bytesInBlock == 0) {
            if (rd + 4 > data.size()) {
                throw Error("ADPCM: truncated block header");
            }
            stepIndex = std::clamp(int(data[rd]), 0, 88);
            predictor = int16_t(uint16_t(data[rd + 2]) | (uint16_t(data[rd + 3]) << 8));
            bytesInBlock = 2044;
            rd += 4;
        } else {
            nibble(data[rd] & 0x0F);
            nibble((data[rd] >> 4) & 0x0F);
            --bytesInBlock;
            sampleCount -= 2;
            ++rd;
        }
    }
    return pcm;
}

struct AwcFile::Impl {
    std::vector<Stream> streams;
};

AwcFile::AwcFile(Bytes data, const std::string &entryName, const std::array<uint32_t, 4> *awcKey)
    : d(new Impl)
{
    std::unique_ptr<Impl> guard(d);
    if (data.size() < 8) {
        throw Error("AWC: data too short");
    }
    uint32_t magic = readU32(data.data());
    bool wholeFileEncrypted = false;
    if (magic != MagicLE && magic != MagicBE) {
        if (data.size() % 4 != 0) {
            throw Error("AWC: corrupted data");
        }
        if (!awcKey) {
            throw Error("AWC: encrypted container requires GTA V keys");
        }
        awcDecrypt(data.data(), data.size(), *awcKey);
        magic = readU32(data.data());
        wholeFileEncrypted = true;
    }
    if (magic != MagicLE && magic != MagicBE) {
        throw Error("AWC: unexpected magic");
    }
    Reader r(data.data(), data.size(), magic == MagicBE);

    r.u32(); // magic
    r.u16(); // version
    const uint16_t flags = r.u16();
    const int32_t streamCount = int32_t(r.u32());
    r.u32(); // data offset
    const bool chunkIndices = flags & 1;
    const bool singleEncrypt = flags & 2;
    const bool multiChannel = flags & 4;
    const bool multiEncrypt = flags & 8;
    if (streamCount < 0 || size_t(streamCount) > data.size() / 4) {
        throw Error("AWC: bad stream count");
    }
    if (chunkIndices) {
        for (int i = 0; i < streamCount; ++i) {
            r.u16();
        }
    }
    auto &streams = d->streams;
    streams.resize(size_t(streamCount));
    for (auto &s : streams) {
        const uint32_t raw = r.u32();
        s.chunks.resize(raw >> 29);
        s.id = raw & 0x1FFFFFFF;
    }
    for (auto &s : streams) {
        for (auto &c : s.chunks) {
            const uint64_t raw = r.u64();
            c.type = uint8_t(raw >> 56);
            c.size = uint32_t((raw >> 28) & 0x0FFFFFFF);
            c.offset = uint32_t(raw & 0x0FFFFFFF);
        }
    }

    Stream *multiSource = nullptr;
    for (auto &s : streams) {
        for (const auto &c : s.chunks) {
            r.pos = c.offset;
            switch (c.type) {
            case ChunkData:
                s.data = r.bytes(c.size);
                break;
            case ChunkFormat: {
                Format f;
                f.samples = r.u32();
                r.u32(); // loop point
                f.samplesPerSecond = r.u16();
                r.u16(); // headroom
                r.u16(); // loop begin
                r.u16(); // loop end
                r.u16(); // play end
                r.u8(); // play begin
                f.codec = r.u8();
                s.format = f;
                break;
            }
            case ChunkMid:
                s.hasMidi = true;
                break;
            case ChunkStreamFormat: {
                s.hasStreamFormatChunk = true;
                s.blockCount = r.u32();
                s.blockSize = r.u32();
                s.channelCount = r.u32();
                if (s.channelCount > c.size) {
                    throw Error("AWC: bad channel count");
                }
                s.channels.clear();
                for (uint32_t i = 0; i < s.channelCount; ++i) {
                    StreamFormat sf;
                    sf.id = r.u32();
                    sf.samples = r.u32();
                    r.u16(); // headroom
                    sf.samplesPerSecond = r.u16();
                    sf.codec = r.u8();
                    r.u8();
                    r.u16();
                    s.channels.push_back(sf);
                }
                break;
            }
            case ChunkSeekTable:
                s.seekTable.clear();
                for (uint32_t i = 0; i < c.size / 4; ++i) {
                    s.seekTable.push_back(r.u32());
                }
                break;
            default:
                break;
            }
        }

        // DecodeData
        if (s.data) {
            if (multiChannel) {
                const uint32_t bcount = s.hasStreamFormatChunk ? s.blockCount : 0;
                const uint32_t bsize = s.hasStreamFormatChunk ? s.blockSize : 0;
                const uint32_t ccount = s.hasStreamFormatChunk ? s.channelCount : 0;
                if (uint64_t(bcount) * bsize > uint64_t(s.data->size()) + bsize) {
                    throw Error("AWC: bad block layout");
                }
                for (uint32_t b = 0; b < bcount; ++b) {
                    const int64_t srcoff = int64_t(b) * bsize;
                    const int64_t blen = std::max<int64_t>(std::min<int64_t>(bsize, int64_t(s.data->size()) - srcoff), 0);
                    Bytes bdat(static_cast<size_t>(blen));
                    std::copy_n(s.data->begin() + srcoff, size_t(blen), bdat.begin());
                    if (multiEncrypt && !wholeFileEncrypted) {
                        if (!awcKey) {
                            throw Error("AWC: encrypted container requires GTA V keys");
                        }
                        awcDecrypt(bdat.data(), bdat.size(), *awcKey);
                    }
                    Reader br(bdat.data(), bdat.size(), magic == MagicBE);
                    std::vector<Channel> chans(ccount);
                    for (auto &ch : chans) {
                        br.u32(); // start block
                        ch.blockCount = int32_t(br.u32());
                        br.u32();
                        br.u32(); // sample count
                        br.u32();
                        br.u32();
                        if (ch.blockCount < 0 || uint64_t(ch.blockCount) * 2048 > uint64_t(bsize) + 2048) {
                            throw Error("AWC: bad channel block count");
                        }
                    }
                    for (auto &ch : chans) {
                        for (int32_t i = 0; i < ch.blockCount; ++i) {
                            br.u32(); // sample offsets
                        }
                    }
                    br.pos += (0x800 - br.pos % 0x800) % 0x800;
                    for (auto &ch : chans) {
                        ch.data = br.bytes(size_t(ch.blockCount) * 2048);
                    }
                    s.blocks.push_back(std::move(chans));
                }
            } else if (singleEncrypt && !wholeFileEncrypted) {
                if (!awcKey) {
                    throw Error("AWC: encrypted container requires GTA V keys");
                }
                awcDecrypt(s.data->data(), s.data->size(), *awcKey);
            }
            if (multiChannel) {
                multiSource = &s;
            }
        }
    }

    // AssignMultiChannelSources
    if (multiSource) {
        for (auto &s : streams) {
            if (&s == multiSource) {
                continue;
            }
            size_t srcind = 0;
            for (size_t i = 0; i < multiSource->channels.size(); ++i) {
                if (multiSource->channels[i].id == s.id) {
                    srcind = i;
                    break;
                }
            }
            s.source = multiSource;
            s.channelIndex = int(srcind);
            if (srcind < multiSource->channels.size()) {
                s.streamFormat = multiSource->channels[srcind];
            } else {
                s.streamFormat.reset();
            }
        }
    }

    // names: "<awc>_left"/"<awc>_right" like CodeWalker's JenkIndex, else the hex id
    std::string base = toLower(entryName);
    if (const auto slash = base.find_last_of('/'); slash != std::string::npos) {
        base = base.substr(slash + 1);
    }
    if (const auto dot = base.find_last_of('.'); dot != std::string::npos) {
        base = base.substr(0, dot);
    }
    auto jenk29 = [](const std::string &s) {
        return jenkHash(reinterpret_cast<const uint8_t *>(s.data()), s.size()) & 0x1FFFFFFF;
    };
    const uint32_t leftId = jenk29(base + "_left");
    const uint32_t rightId = jenk29(base + "_right");

    for (size_t i = 0; i < streams.size(); ++i) {
        const Stream &s = streams[i];
        if (s.id == 0 || s.hasMidi || !s.rawAvailable()) {
            continue; // multichannel source / MIDI / no audio: CodeWalker exports no WAV
        }
        AwcWave w;
        w.streamIndex = int(i);
        w.hash = s.id;
        if (s.id == leftId) {
            w.name = base + "_left";
        } else if (s.id == rightId) {
            w.name = base + "_right";
        } else {
            char buf[16];
            std::snprintf(buf, sizeof buf, "0x%08X", s.id);
            w.name = buf;
        }
        w.samples = s.sampleCount();
        w.samplesPerSecond = s.samplesPerSecond();
        w.codec = s.codec();
        const uint64_t raw = s.rawSize();
        if (w.codec == uint8_t(AwcCodec::Pcm) || w.codec == uint8_t(AwcCodec::Adpcm)) {
            w.extension = "wav";
            w.exportSize = 44 + (w.codec == uint8_t(AwcCodec::Adpcm) ? raw * 4 : raw);
        } else {
            w.extension = w.codec == uint8_t(AwcCodec::Mp3) ? "mp3" : "raw";
            w.exportSize = raw;
        }
        m_waves.push_back(std::move(w));
    }
    (void)guard.release();
}

AwcFile::~AwcFile()
{
    delete d;
}

int AwcFile::streamCount() const
{
    return int(d->streams.size());
}

Bytes AwcFile::wav(int streamIndex) const
{
    if (streamIndex < 0 || size_t(streamIndex) >= d->streams.size()) {
        throw Error("AWC: stream index out of range");
    }
    const Stream &s = d->streams[size_t(streamIndex)];
    Bytes pcm = s.rawData();
    if (s.codec() == uint8_t(AwcCodec::Adpcm)) {
        pcm = decodeAdpcm(pcm, int(s.sampleCount()));
    }
    return makeWav(pcm, s.samplesPerSecond());
}

Bytes AwcFile::exportStream(int streamIndex) const
{
    if (streamIndex < 0 || size_t(streamIndex) >= d->streams.size()) {
        throw Error("AWC: stream index out of range");
    }
    const uint8_t codec = d->streams[size_t(streamIndex)].codec();
    if (codec == uint8_t(AwcCodec::Pcm) || codec == uint8_t(AwcCodec::Adpcm)) {
        return wav(streamIndex);
    }
    return d->streams[size_t(streamIndex)].rawData();
}

} // namespace rageark
