// SPDX-License-Identifier: MIT
// AWC (audio wave container) parsing and WAV export.
// Port of CodeWalker AwcFile.cs (PCM + IMA ADPCM to WAV; MP3 and unknown codecs exported as raw streams).
#pragma once

#include "bytes.h"

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace rageark
{

enum class AwcCodec : uint8_t {
    Pcm = 0,
    Adpcm = 4,
    Mp3 = 7, // MPEG-1 Layer III (GTA V Enhanced dialogue); CodeWalker does not know it
};

struct AwcWave {
    int streamIndex = 0;
    uint32_t hash = 0; // 29-bit stream id
    std::string name; // file name without extension, e.g. "0x1234abcd" or "<awc>_left"
    uint32_t samples = 0;
    uint32_t samplesPerSecond = 0;
    uint8_t codec = 0;
    std::string extension; // "wav" (PCM/ADPCM), "mp3" (codec 7), "raw" (unknown codec)
    uint64_t exportSize = 0; // size of exportStream()
};

class AwcFile
{
public:
    // awcKey: GTA V PC_AWC_KEY (needed only for encrypted containers).
    // Throws Error when the container cannot be parsed (CodeWalker Load failure).
    AwcFile(Bytes data, const std::string &entryName, const std::array<uint32_t, 4> *awcKey);
    ~AwcFile();
    AwcFile(const AwcFile &) = delete;
    AwcFile &operator=(const AwcFile &) = delete;

    int streamCount() const;

    // Streams CodeWalker exports as .wav (non-zero id, not MIDI, has audio data).
    const std::vector<AwcWave> &waves() const
    {
        return m_waves;
    }

    // 16-bit PCM mono WAV of stream i, byte-identical to CodeWalker AwcStream.GetWavFile
    // (for non PCM/ADPCM codecs CodeWalker wraps the raw data, so does this). Throws on failure.
    Bytes wav(int streamIndex) const;
    // What RageARK extracts: wav() for PCM/ADPCM, the decrypted raw stream otherwise (.mp3/.raw).
    Bytes exportStream(int streamIndex) const;

    struct Impl;

private:
    Impl *d;
    std::vector<AwcWave> m_waves;
};

// Rockstar's XXTEA variant (in place, length must be a multiple of 4).
void awcDecrypt(uint8_t *data, size_t len, const std::array<uint32_t, 4> &key);
void awcEncrypt(uint8_t *data, size_t len, const std::array<uint32_t, 4> &key);

// IMA ADPCM as used by GTA V (2048-byte blocks, 4-byte header), CodeWalker ADPCMCodec.DecodeADPCM.
Bytes decodeAdpcm(const Bytes &data, int sampleCount);

} // namespace rageark
