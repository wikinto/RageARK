// SPDX-License-Identifier: GPL-2.0-or-later
// YTD (texture dictionary) parsing and DDS export.
// Port of CodeWalker TextureDictionary/Texture (Texture.cs, legacy and gen9 layouts) and
// DDSIO.GetDDSFile, so every exported .dds is byte-identical to CodeWalker's.
#pragma once

#include "bytes.h"

#include <string>
#include <vector>

namespace rageark
{

// RSC7 versions of .ytd resources
constexpr int YtdVersionLegacy = 13;
constexpr int YtdVersionGen9 = 5; // GTA V Enhanced

struct YtdTexture {
    std::string name; // texture name as stored ("" if missing)
    std::string fileName; // "<name>.dds", made unique within the dictionary
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t depth = 0;
    uint8_t levels = 0;
    uint8_t exportedLevels = 0; // mip levels in dds(); < levels when the chain reaches a 0-pixel level
    uint32_t format = 0; // legacy D3DFMT / FourCC (CodeWalker TextureFormat)
    uint32_t formatGen9 = 0; // rage::sga::BufferFormat (= DXGI_FORMAT numbering), 0 for legacy
    uint64_t dataPointer = 0; // virtual address of the pixel data
    uint32_t dataLength = 0; // bytes CodeWalker reads as TextureData.FullData
    uint64_t dataOffset = 0; // offset of the pixel data in the resource payload
    uint64_t ddsSize = 0; // size of dds(), 0 when it cannot be exported
    std::string ddsError; // why dds() fails ("" = exportable)
};

class YtdFile
{
public:
    // resource: the decompressed resource payload (system pages followed by graphics pages), or
    // just a prefix of it holding at least the system pages (enough to list the textures).
    // Throws Error when the dictionary cannot be parsed.
    YtdFile(Bytes resource, uint32_t systemFlags, uint32_t graphicsFlags);

    // Size of the system pages: YtdFile needs only this much of the payload to list the textures.
    static size_t headerSize(uint32_t systemFlags);

    // Replaces the pixel data of texture i with the image of a DDS file of the same format,
    // width, height and (at least) the same mip levels (checked; throws Error otherwise). The
    // dictionary layout stays as it is. Needs the complete payload.
    void replaceTexture(size_t index, const Bytes &ddsFile);
    // The dictionary as a complete RSC7 file (e.g. after replaceTexture).
    Bytes rsc7() const;

    bool isGen9() const
    {
        return m_gen9;
    }
    const std::vector<YtdTexture> &textures() const
    {
        return m_textures;
    }

    // DDS file of texture i, byte-identical to CodeWalker DDSIO.GetDDSFile. Where CodeWalker
    // fails because the mip chain runs into a 0-pixel level (e.g. 570x150 with 10 levels), the
    // DDS stops at the last valid level instead. Needs the complete payload; throws Error when
    // the texture cannot be exported.
    Bytes dds(size_t index) const;

private:
    Bytes readAt(uint64_t va, size_t len) const;
    std::string stringAt(uint64_t va) const;

    Bytes m_data;
    uint32_t m_systemFlags = 0;
    uint32_t m_graphicsFlags = 0;
    size_t m_systemSize = 0;
    size_t m_graphicsSize = 0;
    bool m_gen9 = false;
    std::vector<YtdTexture> m_textures;
};

// Header fields of a DDS file (the subset RageARK can import).
struct DdsInfo {
    uint32_t dxgiFormat = 0; // DXGI_FORMAT (sRGB/typeless variants folded into the UNORM format)
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t mipLevels = 0;
    size_t dataOffset = 0;
};
// Throws Error for files that are not a single 2D DDS image in a supported format.
DdsInfo parseDds(const Bytes &ddsFile);

// Human-readable format name (e.g. "DXT5", "BC7", "A8R8G8B8").
std::string textureFormatName(uint32_t legacyFormat);

} // namespace rageark
