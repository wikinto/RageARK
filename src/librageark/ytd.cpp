// SPDX-License-Identifier: GPL-2.0-or-later
#include "ytd.h"

#include "deflate.h"
#include "rpf.h"

#include <algorithm>
#include <set>

namespace rageark
{

namespace
{

// legacy TextureFormat (D3DFMT / FourCC) values
enum : uint32_t {
    FmtA8R8G8B8 = 21,
    FmtX8R8G8B8 = 22,
    FmtA1R5G5B5 = 25,
    FmtA8 = 28,
    FmtA8B8G8R8 = 32,
    FmtL8 = 50,
    FmtDXT1 = 0x31545844,
    FmtDXT3 = 0x33545844,
    FmtDXT5 = 0x35545844,
    FmtATI1 = 0x31495441,
    FmtATI2 = 0x32495441,
    FmtBC7 = 0x20374342,
};

// the DXGI formats DDSIO.GetDXGIFormat can produce
enum : uint32_t {
    DxgiUnknown = 0,
    DxgiR8G8B8A8 = 28,
    DxgiR8 = 61,
    DxgiA8 = 65,
    DxgiBC1 = 71,
    DxgiBC2 = 74,
    DxgiBC3 = 77,
    DxgiBC4 = 80,
    DxgiBC5 = 83,
    DxgiB5G5R5A1 = 86,
    DxgiB8G8R8A8 = 87,
    DxgiB8G8R8X8 = 88,
    DxgiBC7 = 98,
};

// DDSIO.GetDXGIFormat
uint32_t dxgiFormat(uint32_t f)
{
    switch (f) {
    case FmtDXT1:
        return DxgiBC1;
    case FmtDXT3:
        return DxgiBC2;
    case FmtDXT5:
        return DxgiBC3;
    case FmtATI1:
        return DxgiBC4;
    case FmtATI2:
        return DxgiBC5;
    case FmtBC7:
        return DxgiBC7;
    case FmtA1R5G5B5:
        return DxgiB5G5R5A1;
    case FmtA8:
        return DxgiA8;
    case FmtA8B8G8R8:
        return DxgiR8G8B8A8;
    case FmtL8:
        return DxgiR8;
    case FmtA8R8G8B8:
        return DxgiB8G8R8A8;
    case FmtX8R8G8B8:
        return DxgiB8G8R8X8;
    }
    return DxgiUnknown;
}

// TextureBase.GetLegacyFormat (gen9 BufferFormat -> legacy format, CodeWalker's mapping incl. its TODOs)
uint32_t legacyFormat(uint32_t g9)
{
    switch (g9) {
    case 0x00:
        return 0;
    case 0x1C: // R8G8B8A8_UNORM
        return FmtA8B8G8R8;
    case 0x57: // B8G8R8A8_UNORM
        return FmtA8R8G8B8;
    case 0x41: // A8_UNORM
        return FmtA8;
    case 0x3D: // R8_UNORM
        return FmtL8;
    case 0x56: // B5G5R5A1_UNORM
        return FmtA1R5G5B5;
    case 0x47: // BC1_UNORM
        return FmtDXT1;
    case 0x4A: // BC2_UNORM
        return FmtDXT3;
    case 0x4D: // BC3_UNORM
        return FmtDXT5;
    case 0x50: // BC4_UNORM
        return FmtATI1;
    case 0x53: // BC5_UNORM
        return FmtATI2;
    case 0x62: // BC7_UNORM
    case 0x63: // BC7_UNORM_SRGB
        return FmtBC7;
    case 0x4E: // BC3_UNORM_SRGB
        return FmtDXT5;
    case 0x38: // R16_UNORM
        return FmtA8;
    }
    return FmtA8R8G8B8;
}

bool isCompressed(uint32_t dxgi)
{
    switch (dxgi) {
    case DxgiBC1:
    case DxgiBC2:
    case DxgiBC3:
    case DxgiBC4:
    case DxgiBC5:
    case DxgiBC7:
        return true;
    }
    return false;
}

int bitsPerPixel(uint32_t dxgi)
{
    switch (dxgi) {
    case DxgiR8G8B8A8:
    case DxgiB8G8R8A8:
    case DxgiB8G8R8X8:
        return 32;
    case DxgiB5G5R5A1:
        return 16;
    case DxgiR8:
    case DxgiA8:
        return 8;
    }
    return 0;
}

// DDSIO.DXTex.ComputePitch (CP_FLAGS_NONE), restricted to the formats above
void computePitch(uint32_t dxgi, int width, int height, int &rowPitch, int &slicePitch)
{
    if (isCompressed(dxgi)) {
        const int nbw = std::max(1, (width + 3) / 4);
        const int nbh = std::max(1, (height + 3) / 4);
        rowPitch = nbw * (dxgi == DxgiBC1 || dxgi == DxgiBC4 ? 8 : 16);
        slicePitch = rowPitch * nbh;
        return;
    }
    rowPitch = (width * bitsPerPixel(dxgi) + 7) / 8;
    slicePitch = rowPitch * height;
}

struct PixelFormat {
    uint32_t size, flags, fourCC, rgbBitCount, rMask, gMask, bMask, aMask;
};

constexpr uint32_t fourCC(char a, char b, char c, char d)
{
    return uint32_t(uint8_t(a)) | (uint32_t(uint8_t(b)) << 8) | (uint32_t(uint8_t(c)) << 16) | (uint32_t(uint8_t(d)) << 24);
}

// DDS_PIXELFORMAT chosen by _EncodeDDSHeader; size 0 = DX10 extension header
PixelFormat pixelFormat(uint32_t dxgi)
{
    constexpr uint32_t FourCCFlag = 0x4, Rgb = 0x40, Rgba = 0x41, Luminance = 0x20000, Alpha = 0x2;
    switch (dxgi) {
    case DxgiR8G8B8A8:
        return {32, Rgba, 0, 32, 0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000};
    case DxgiR8:
        return {32, Luminance, 0, 8, 0xff, 0, 0, 0};
    case DxgiA8:
        return {32, Alpha, 0, 8, 0, 0, 0, 0xff};
    case DxgiBC1:
        return {32, FourCCFlag, fourCC('D', 'X', 'T', '1'), 0, 0, 0, 0, 0};
    case DxgiBC2:
        return {32, FourCCFlag, fourCC('D', 'X', 'T', '3'), 0, 0, 0, 0, 0};
    case DxgiBC3:
        return {32, FourCCFlag, fourCC('D', 'X', 'T', '5'), 0, 0, 0, 0, 0};
    case DxgiBC4:
        return {32, FourCCFlag, fourCC('B', 'C', '4', 'U'), 0, 0, 0, 0, 0};
    case DxgiBC5:
        return {32, FourCCFlag, fourCC('B', 'C', '5', 'U'), 0, 0, 0, 0, 0};
    case DxgiB5G5R5A1:
        return {32, Rgba, 0, 16, 0x00007c00, 0x000003e0, 0x0000001f, 0x00008000};
    case DxgiB8G8R8A8:
        return {32, Rgba, 0, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000};
    case DxgiB8G8R8X8:
        return {32, Rgb, 0, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0x00000000};
    }
    return {0, 0, 0, 0, 0, 0, 0, 0}; // BC7
}

// One mip level as DDSIO.GetMipmapImages lays them out.
struct MipImage {
    int width, height, rowPitch, slicePitch, offset;
};

std::vector<MipImage> mipImages(const YtdTexture &t, uint32_t dxgi, std::string *error)
{
    std::vector<MipImage> images;
    int div = 1, add = 0;
    for (int i = 0; i < t.levels; ++i) {
        if (div == 0) { // C# int overflow of div after 32 levels
            *error = "too many mip levels";
            return {};
        }
        MipImage m{};
        m.width = int(t.width) / div;
        m.height = int(t.height) / div;
        m.offset = add;
        computePitch(dxgi, m.width, m.height, m.rowPitch, m.slicePitch);
        add += m.slicePitch;
        div = int(uint32_t(div) * 2u);
        images.push_back(m);
    }
    return images;
}

uint32_t headerLength(uint32_t dxgi)
{
    return 4 + 124 + (pixelFormat(dxgi).size == 0 ? 20 : 0);
}

// Exported size, or an error (mirrors the exceptions of DDSIO.GetDDSFile).
uint64_t ddsSizeOf(const YtdTexture &t, std::string *error, uint8_t *exportedLevels)
{
    if (t.dataPointer == 0) {
        *error = "texture has no data";
        return 0;
    }
    const uint32_t dxgi = dxgiFormat(t.format);
    if (dxgi == DxgiUnknown) {
        *error = "unsupported texture format " + textureFormatName(t.format);
        return 0;
    }
    const auto images = mipImages(t, dxgi, error);
    if (!error->empty()) {
        return 0;
    }
    uint64_t size = headerLength(dxgi);
    size_t valid = 0;
    for (const auto &m : images) {
        if (m.rowPitch <= 0 || m.slicePitch <= 0) {
            break; // CodeWalker throws here; RageARK drops this and the following levels
        }
        int64_t len = m.slicePitch;
        if (int64_t(m.offset) + m.slicePitch > int64_t(t.dataLength)) {
            len = int64_t(t.dataLength) - m.offset;
        }
        size += uint64_t(std::max<int64_t>(len, 0));
        ++valid;
    }
    if (valid == 0 && !images.empty()) {
        *error = "invalid texture size";
        return 0;
    }
    *exportedLevels = uint8_t(valid);
    return size;
}

std::string uniqueFileName(std::string name, std::set<std::string> &used)
{
    if (name.empty()) {
        name = "null"; // CodeWalker: (Name ?? "null") + ".dds"
    }
    for (char &c : name) {
        if (c == '/' || c == '\\' || c == '\0') {
            c = '_';
        }
    }
    std::string candidate = name + ".dds";
    for (int n = 2; used.count(toLower(candidate)); ++n) {
        candidate = name + "_" + std::to_string(n) + ".dds";
    }
    used.insert(toLower(candidate));
    return candidate;
}

constexpr uint64_t SystemBase = 0x50000000;
constexpr uint64_t GraphicsBase = 0x60000000;
constexpr uint32_t MaxTextureData = 512u << 20;

} // namespace

std::string textureFormatName(uint32_t f)
{
    switch (f) {
    case FmtA8R8G8B8:
        return "A8R8G8B8";
    case FmtX8R8G8B8:
        return "X8R8G8B8";
    case FmtA1R5G5B5:
        return "A1R5G5B5";
    case FmtA8:
        return "A8";
    case FmtA8B8G8R8:
        return "A8B8G8R8";
    case FmtL8:
        return "L8";
    case FmtDXT1:
        return "DXT1";
    case FmtDXT3:
        return "DXT3";
    case FmtDXT5:
        return "DXT5";
    case FmtATI1:
        return "ATI1";
    case FmtATI2:
        return "ATI2";
    case FmtBC7:
        return "BC7";
    }
    return std::to_string(f); // like the C# enum ToString of an undefined value
}

size_t YtdFile::headerSize(uint32_t systemFlags)
{
    return resourceSizeFromFlags(systemFlags);
}

// ResourceDataReader: virtual address -> system/graphics stream; reads past a stream's end
// yield zero bytes (MemoryStream semantics)
Bytes YtdFile::readAt(uint64_t va, size_t len) const
{
    Bytes out(len, 0);
    size_t streamOffset = 0, streamSize = 0;
    uint64_t off = 0;
    if ((va & SystemBase) == SystemBase) {
        off = va & ~SystemBase;
        streamSize = m_systemSize;
    } else if ((va & GraphicsBase) == GraphicsBase) {
        off = va & ~GraphicsBase;
        streamOffset = m_systemSize;
        streamSize = m_graphicsSize;
    } else {
        throw Error("illegal resource pointer");
    }
    if (off < streamSize) {
        const size_t n = std::min<uint64_t>(len, streamSize - off);
        const size_t start = streamOffset + size_t(off);
        if (start < m_data.size()) {
            std::copy_n(m_data.begin() + std::ptrdiff_t(start), std::min(n, m_data.size() - start), out.begin());
        }
    }
    return out;
}

std::string YtdFile::stringAt(uint64_t va) const
{
    if (int64_t(va) <= 0) {
        return {};
    }
    std::string s;
    for (;;) {
        const Bytes chunk = readAt(va + s.size(), 64);
        const auto end = std::find(chunk.begin(), chunk.end(), uint8_t(0));
        s.append(chunk.begin(), end);
        if (end != chunk.end() || s.size() > 4096) {
            return s;
        }
    }
}

YtdFile::YtdFile(Bytes resource, uint32_t systemFlags, uint32_t graphicsFlags)
    : m_data(std::move(resource))
    , m_systemFlags(systemFlags)
    , m_graphicsFlags(graphicsFlags)
    , m_systemSize(resourceSizeFromFlags(systemFlags))
    , m_graphicsSize(resourceSizeFromFlags(graphicsFlags))
{
    const int version = int((((systemFlags >> 28) & 0xF) << 4) | ((graphicsFlags >> 28) & 0xF));
    if (version == YtdVersionGen9) {
        m_gen9 = true;
    } else if (version != YtdVersionLegacy) {
        throw Error("unsupported texture dictionary version " + std::to_string(version));
    }

    // TextureDictionary at the start of the system pages: ResourceFileBase (16), 4 x uint,
    // TextureNameHashes list (16), Textures pointer list (pointer, count, capacity)
    const Bytes dict = readAt(SystemBase, 64);
    const uint64_t listPointer = readU64(dict.data() + 0x30);
    const uint16_t count = uint16_t(dict[0x38] | (dict[0x39] << 8));
    const uint16_t capacity = uint16_t(dict[0x3A] | (dict[0x3B] << 8));
    if (count == 0) {
        return;
    }
    if (int64_t(listPointer) <= 0 || capacity < count) {
        throw Error("invalid texture list");
    }
    const Bytes pointers = readAt(listPointer, size_t(capacity) * 8);

    auto u16 = [](const Bytes &b, size_t o) {
        return uint16_t(b[o] | (b[o + 1] << 8));
    };
    std::set<std::string> used;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t tp = readU64(pointers.data() + i * 8);
        if (tp == 0) {
            continue;
        }
        const Bytes tb = readAt(tp, 144);
        YtdTexture t;
        if (m_gen9) {
            // TextureBase gen9 layout (rage::sga::ImageParams at 0x18)
            t.width = u16(tb, 0x18);
            t.height = u16(tb, 0x1A);
            t.depth = u16(tb, 0x1C);
            t.formatGen9 = tb[0x1F];
            t.levels = tb[0x22];
            t.name = stringAt(readU64(tb.data() + 0x28));
            t.dataPointer = readU64(tb.data() + 0x38);
            t.format = legacyFormat(t.formatGen9);
            // TextureBase.CalcDataSize
            int64_t len = 0;
            if (t.format != 0) {
                const uint32_t dxgi = dxgiFormat(t.format);
                int div = 1;
                for (int l = 0; l < t.levels && div != 0; ++l) {
                    int rp = 0, sp = 0;
                    computePitch(dxgi, int(t.width) / div, int(t.height) / div, rp, sp);
                    len += sp;
                    div = int(uint32_t(div) * 2u);
                }
            }
            len *= t.depth;
            if (len < 0 || len > MaxTextureData) {
                throw Error("invalid texture size");
            }
            t.dataLength = uint32_t(len);
        } else {
            t.name = stringAt(readU64(tb.data() + 0x28));
            t.width = u16(tb, 0x50);
            t.height = u16(tb, 0x52);
            t.depth = u16(tb, 0x54);
            const uint16_t stride = u16(tb, 0x56);
            t.format = readU32(tb.data() + 0x58);
            t.levels = tb[0x5D];
            t.dataPointer = readU64(tb.data() + 0x70);
            // TextureData.Read (legacy): Stride * Height, quartered per level
            int64_t full = 0, length = int64_t(stride) * t.height;
            for (int l = 0; l < t.levels; ++l) {
                full += length;
                length /= 4;
            }
            if (full > MaxTextureData) {
                throw Error("invalid texture size");
            }
            t.dataLength = uint32_t(full);
        }
        if (t.dataPointer != 0) {
            readAt(t.dataPointer, 0); // validates the pointer like ReadBlockAt does
            t.dataOffset = (t.dataPointer & SystemBase) == SystemBase ? (t.dataPointer & ~SystemBase) : m_systemSize + (t.dataPointer & ~GraphicsBase);
        }
        t.fileName = uniqueFileName(t.name, used);
        t.ddsSize = ddsSizeOf(t, &t.ddsError, &t.exportedLevels);
        m_textures.push_back(std::move(t));
    }
}

Bytes YtdFile::dds(size_t index) const
{
    const YtdTexture &t = m_textures.at(index);
    if (!t.ddsError.empty()) {
        throw Error(t.name + ": " + t.ddsError);
    }
    if (m_data.size() < m_systemSize + m_graphicsSize) {
        // header-only instance, or a truncated payload (CodeWalker's reader rejects that too)
        throw Error("texture data not loaded");
    }
    const Bytes data = readAt(t.dataPointer, t.dataLength);
    const uint32_t dxgi = dxgiFormat(t.format);
    std::string error;
    auto images = mipImages(t, dxgi, &error);
    images.resize(t.exportedLevels);
    int rowPitch = 0, slicePitch = 0;
    computePitch(dxgi, t.width, t.height, rowPitch, slicePitch);
    const PixelFormat pf = pixelFormat(dxgi);

    // DDSIO.DXTex._EncodeDDSHeader
    Bytes out;
    out.reserve(t.ddsSize);
    uint32_t flags = 0x00001007; // CAPS | HEIGHT | WIDTH | PIXELFORMAT
    uint32_t caps = 0x00001000; // DDSCAPS_TEXTURE
    if (t.exportedLevels > 0) {
        flags |= 0x00020000; // MIPMAPCOUNT
        if (t.exportedLevels > 1) {
            caps |= 0x00400008; // COMPLEX | MIPMAP
        }
    }
    flags |= isCompressed(dxgi) ? 0x00080000 : 0x00000008; // LINEARSIZE : PITCH
    appendU32(out, 0x20534444); // "DDS "
    appendU32(out, 124);
    appendU32(out, flags);
    appendU32(out, t.height);
    appendU32(out, t.width);
    appendU32(out, uint32_t(isCompressed(dxgi) ? slicePitch : rowPitch));
    appendU32(out, 1); // depth
    appendU32(out, t.exportedLevels);
    for (int i = 0; i < 11; ++i) {
        appendU32(out, 0);
    }
    const PixelFormat header = pf.size ? pf : PixelFormat{32, 0x4, fourCC('D', 'X', '1', '0'), 0, 0, 0, 0, 0};
    for (uint32_t v : {header.size, header.flags, header.fourCC, header.rgbBitCount, header.rMask, header.gMask, header.bMask, header.aMask}) {
        appendU32(out, v);
    }
    appendU32(out, caps);
    for (int i = 0; i < 4; ++i) { // caps2, caps3, caps4, reserved2
        appendU32(out, 0);
    }
    if (pf.size == 0) {
        appendU32(out, dxgi);
        appendU32(out, 3); // TEX_DIMENSION_TEXTURE2D
        appendU32(out, 0); // misc flags
        appendU32(out, 1); // array size
        appendU32(out, 0); // misc flags 2
    }

    // mip levels, clipped to the data CodeWalker read
    for (const auto &m : images) {
        int64_t len = m.slicePitch;
        if (int64_t(m.offset) + m.slicePitch > int64_t(data.size())) {
            len = int64_t(data.size()) - m.offset;
        }
        if (len > 0) {
            out.insert(out.end(), data.begin() + m.offset, data.begin() + m.offset + std::ptrdiff_t(len));
        }
    }
    return out;
}

} // namespace rageark

namespace rageark
{

namespace
{
// DXGI formats whose sRGB / typeless variants share the block layout of the UNORM format
uint32_t foldDxgi(uint32_t f)
{
    switch (f) {
    case 70:
    case 72:
        return DxgiBC1;
    case 73:
    case 75:
        return DxgiBC2;
    case 76:
    case 78:
        return DxgiBC3;
    case 79:
        return DxgiBC4;
    case 82:
        return DxgiBC5;
    case 97:
    case 99:
        return DxgiBC7;
    case 27:
    case 29:
        return DxgiR8G8B8A8;
    case 90:
    case 91:
        return DxgiB8G8R8A8;
    case 92:
    case 93:
        return DxgiB8G8R8X8;
    }
    return f;
}

// gen9 formats CodeWalker maps to a legacy format with the same pixel layout
bool faithfulGen9Format(uint32_t g9)
{
    switch (g9) {
    case 0x1C:
    case 0x57:
    case 0x41:
    case 0x3D:
    case 0x56:
    case 0x47:
    case 0x4A:
    case 0x4D:
    case 0x4E:
    case 0x50:
    case 0x53:
    case 0x62:
    case 0x63:
        return true;
    }
    return false;
}
} // namespace

DdsInfo parseDds(const Bytes &f)
{
    if (f.size() < 128 || readU32(f.data()) != 0x20534444 || readU32(f.data() + 4) != 124) {
        throw Error("not a DDS file");
    }
    DdsInfo info;
    const uint32_t flags = readU32(f.data() + 8);
    info.height = readU32(f.data() + 12);
    info.width = readU32(f.data() + 16);
    const uint32_t depth = readU32(f.data() + 24);
    const uint32_t mips = readU32(f.data() + 28);
    info.mipLevels = (flags & 0x00020000) && mips > 0 ? mips : 1;
    const uint8_t *pf = f.data() + 76;
    const uint32_t pfFlags = readU32(pf + 4), cc = readU32(pf + 8), bits = readU32(pf + 12);
    const uint32_t r = readU32(pf + 16), g = readU32(pf + 20), b = readU32(pf + 24), a = readU32(pf + 28);
    const uint32_t caps2 = readU32(f.data() + 112);
    if ((flags & 0x00800000) && depth > 1) {
        throw Error("volume DDS files are not supported");
    }
    if (caps2 & 0x200) {
        throw Error("cube map DDS files are not supported");
    }
    info.dataOffset = 128;
    if (pfFlags & 0x4) { // FourCC
        if (cc == fourCC('D', 'X', 'T', '1')) {
            info.dxgiFormat = DxgiBC1;
        } else if (cc == fourCC('D', 'X', 'T', '2') || cc == fourCC('D', 'X', 'T', '3')) {
            info.dxgiFormat = DxgiBC2;
        } else if (cc == fourCC('D', 'X', 'T', '4') || cc == fourCC('D', 'X', 'T', '5')) {
            info.dxgiFormat = DxgiBC3;
        } else if (cc == fourCC('B', 'C', '4', 'U') || cc == fourCC('A', 'T', 'I', '1')) {
            info.dxgiFormat = DxgiBC4;
        } else if (cc == fourCC('B', 'C', '5', 'U') || cc == fourCC('A', 'T', 'I', '2')) {
            info.dxgiFormat = DxgiBC5;
        } else if (cc == fourCC('D', 'X', '1', '0')) {
            if (f.size() < 148) {
                throw Error("truncated DDS file");
            }
            info.dxgiFormat = foldDxgi(readU32(f.data() + 128));
            if (readU32(f.data() + 132) != 3 || readU32(f.data() + 140) > 1 || (readU32(f.data() + 136) & 0x4)) {
                throw Error("only single 2D DDS images are supported");
            }
            info.dataOffset = 148;
        } else {
            throw Error("unsupported DDS pixel format");
        }
    } else if ((pfFlags & 0x40) && bits == 32 && r == 0x00ff0000 && g == 0x0000ff00 && b == 0x000000ff) {
        info.dxgiFormat = a ? DxgiB8G8R8A8 : DxgiB8G8R8X8;
    } else if ((pfFlags & 0x40) && bits == 32 && r == 0x000000ff && g == 0x0000ff00 && b == 0x00ff0000 && a == 0xff000000) {
        info.dxgiFormat = DxgiR8G8B8A8;
    } else if ((pfFlags & 0x40) && bits == 16 && r == 0x7c00 && g == 0x3e0 && b == 0x1f && a == 0x8000) {
        info.dxgiFormat = DxgiB5G5R5A1;
    } else if ((pfFlags & 0x20000) && bits == 8) {
        info.dxgiFormat = DxgiR8;
    } else if ((pfFlags & 0x2) && bits == 8) {
        info.dxgiFormat = DxgiA8;
    } else {
        throw Error("unsupported DDS pixel format");
    }
    return info;
}

void YtdFile::replaceTexture(size_t index, const Bytes &ddsFile)
{
    YtdTexture &t = m_textures.at(index);
    if (m_data.size() < m_systemSize + m_graphicsSize) {
        throw Error("texture data not loaded");
    }
    if (!t.ddsError.empty()) {
        throw Error(t.name + ": " + t.ddsError);
    }
    if (t.depth != 1 || (m_gen9 && !faithfulGen9Format(t.formatGen9))) {
        throw Error(t.name + ": replacing this kind of texture is not supported");
    }
    const DdsInfo dds = parseDds(ddsFile);
    const uint32_t dxgi = dxgiFormat(t.format);
    if (dds.dxgiFormat != dxgi || dds.width != t.width || dds.height != t.height) {
        throw Error(t.name + ": the new image must have the texture's format and size (" + textureFormatName(t.format) + ", " + std::to_string(t.width) + "x" +
                    std::to_string(t.height) + ")");
    }
    if (dds.mipLevels < t.exportedLevels) {
        throw Error(t.name + ": the new image must have " + std::to_string(t.exportedLevels) + " mip levels");
    }
    std::string error;
    auto images = mipImages(t, dxgi, &error);
    images.resize(t.exportedLevels);
    size_t src = dds.dataOffset;
    for (const auto &m : images) {
        // the bytes dds() exports for this level: its slice, clipped to the texture data
        int64_t len = m.slicePitch;
        if (int64_t(m.offset) + m.slicePitch > int64_t(t.dataLength)) {
            len = int64_t(t.dataLength) - m.offset;
        }
        if (len <= 0) {
            break;
        }
        if (src + size_t(len) > ddsFile.size()) {
            throw Error(t.name + ": DDS file is truncated");
        }
        const size_t dst = size_t(t.dataOffset) + size_t(m.offset);
        const size_t streamEnd = (t.dataPointer & GraphicsBase) == GraphicsBase && (t.dataPointer & SystemBase) != SystemBase ? m_systemSize + m_graphicsSize : m_systemSize;
        if (dst + size_t(len) > streamEnd || dst + size_t(len) > m_data.size()) {
            throw Error(t.name + ": texture data lies outside the resource");
        }
        std::copy_n(ddsFile.begin() + std::ptrdiff_t(src), size_t(len), m_data.begin() + std::ptrdiff_t(dst));
        src += size_t(m.slicePitch);
    }
}

Bytes YtdFile::rsc7() const
{
    Bytes out;
    appendU32(out, 0x37435352); // "RSC7"
    appendU32(out, uint32_t(m_gen9 ? YtdVersionGen9 : YtdVersionLegacy));
    appendU32(out, m_systemFlags);
    appendU32(out, m_graphicsFlags);
    const Bytes z = deflateRaw(m_data.data(), m_data.size());
    out.insert(out.end(), z.begin(), z.end());
    return out;
}

} // namespace rageark
