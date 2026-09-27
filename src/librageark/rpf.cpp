// SPDX-License-Identifier: MIT
// RPF7 reader/builder. Format knowledge from CodeWalker (RpfFile.cs).
#include "rpf.h"

#include "deflate.h"

#include <algorithm>
#include <functional>
#include <map>

namespace rageark
{

std::string encryptionName(Encryption e)
{
    switch (e) {
    case Encryption::None:
        return "NONE";
    case Encryption::Open:
        return "OPEN";
    case Encryption::Aes:
        return "AES";
    case Encryption::Ng:
        return "NG";
    }
    return "UNKNOWN";
}

uint32_t resourceSizeFromFlags(uint32_t flags)
{
    const uint32_t s0 = ((flags >> 27) & 0x1) << 0;
    const uint32_t s1 = ((flags >> 26) & 0x1) << 1;
    const uint32_t s2 = ((flags >> 25) & 0x1) << 2;
    const uint32_t s3 = ((flags >> 24) & 0x1) << 3;
    const uint32_t s4 = ((flags >> 17) & 0x7F) << 4;
    const uint32_t s5 = ((flags >> 11) & 0x3F) << 5;
    const uint32_t s6 = ((flags >> 7) & 0xF) << 6;
    const uint32_t s7 = ((flags >> 5) & 0x3) << 7;
    const uint32_t s8 = ((flags >> 4) & 0x1) << 8;
    const uint32_t ss = flags & 0xF;
    const uint64_t base = uint64_t(0x200) << ss;
    return uint32_t(base * (s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8));
}

uint64_t Entry::storedSize() const
{
    if (type == EntryType::Binary) {
        return fileSize != 0 ? fileSize : uncompressedSize;
    }
    if (type == EntryType::Resource) {
        return fileSize != 0 ? fileSize : uint64_t(resourceSizeFromFlags(systemFlags)) + resourceSizeFromFlags(graphicsFlags);
    }
    return 0;
}

uint64_t Entry::logicalSize() const
{
    if (type == EntryType::Binary) {
        return uncompressedSize;
    }
    if (type == EntryType::Resource) {
        return uint64_t(resourceSizeFromFlags(systemFlags)) + resourceSizeFromFlags(graphicsFlags);
    }
    return 0;
}

static std::string baseName(const std::string &path)
{
    const auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

Package::Package(const std::string &filePath, const Crypto *crypto)
    : m_filePath(filePath)
    , m_reader(std::make_unique<FileReader>(filePath))
    , m_crypto(crypto)
{
    Archive top;
    top.name = baseName(filePath);
    top.startPos = 0;
    top.size = m_reader->size();
    m_archives.push_back(std::move(top));
    parseArchive(0); // top-level errors propagate
    flatten();
}

void Package::decryptBlock(const Archive &a, uint8_t *data, size_t len, const std::string &name, uint32_t length) const
{
    if (a.encryption == Encryption::None || a.encryption == Encryption::Open) {
        // OpenIV-modded archives may still flag single entries; CodeWalker assumes NG then
    }
    if (!m_crypto) {
        throw KeysRequired("encrypted data requires GTA V keys");
    }
    if (a.encryption == Encryption::Aes) {
        m_crypto->decryptAes(data, len);
    } else {
        m_crypto->decryptNg(data, len, name, length);
    }
}

void Package::parseArchive(int index)
{
    // copy what we need: m_archives may reallocate while recursing
    const uint64_t start = m_archives[size_t(index)].startPos;
    const uint64_t size = m_archives[size_t(index)].size;
    const std::string archName = m_archives[size_t(index)].name;

    if (size < 16) {
        throw Error(archName + ": too small for an RPF header");
    }
    uint8_t hdr[16];
    m_reader->read(start, hdr, 16);
    if (readU32(hdr) != Rpf7Magic) {
        throw Error(archName + ": not an RPF7 archive");
    }
    const uint32_t entryCount = readU32(hdr + 4);
    const uint32_t namesLength = readU32(hdr + 8);
    const auto enc = Encryption(readU32(hdr + 12));
    if (entryCount == 0 || uint64_t(entryCount) * 16 + namesLength + 16 > size) {
        throw Error(archName + ": corrupt TOC size");
    }

    Bytes entriesData = m_reader->read(start + 16, size_t(entryCount) * 16);
    Bytes namesData = m_reader->read(start + 16 + uint64_t(entryCount) * 16, namesLength);

    Encryption effective = enc;
    switch (enc) {
    case Encryption::None:
    case Encryption::Open:
        break;
    case Encryption::Aes:
        if (!m_crypto) {
            throw KeysRequired(archName + ": AES-encrypted archive requires GTA V keys");
        }
        m_crypto->decryptAes(entriesData.data(), entriesData.size());
        m_crypto->decryptAes(namesData.data(), namesData.size());
        break;
    default: // NG, and CodeWalker treats unknown values as NG
        effective = Encryption::Ng;
        if (!m_crypto) {
            throw KeysRequired(archName + ": NG-encrypted archive requires GTA V keys");
        }
        m_crypto->decryptNg(entriesData.data(), entriesData.size(), archName, uint32_t(size));
        m_crypto->decryptNg(namesData.data(), namesData.size(), archName, uint32_t(size));
        break;
    }

    std::vector<Entry> entries(entryCount);
    for (uint32_t i = 0; i < entryCount; ++i) {
        const uint8_t *p = entriesData.data() + size_t(i) * 16;
        Entry &e = entries[i];
        const uint32_t x = readU32(p + 4);
        if (x == DirectoryIdent) {
            e.type = EntryType::Directory;
            e.nameOffset = readU32(p);
            e.entriesIndex = readU32(p + 8);
            e.entriesCount = readU32(p + 12);
        } else if ((x & 0x80000000u) == 0) {
            e.type = EntryType::Binary;
            const uint64_t buf = readU64(p);
            e.nameOffset = uint32_t(buf & 0xFFFF);
            e.fileSize = uint32_t((buf >> 16) & 0xFFFFFF);
            e.fileOffset = uint32_t((buf >> 40) & 0xFFFFFF);
            e.uncompressedSize = readU32(p + 8);
            const uint32_t encType = readU32(p + 12);
            if (encType > 1) {
                throw Error(archName + ": corrupt binary entry");
            }
            e.encrypted = encType == 1;
        } else {
            e.type = EntryType::Resource;
            e.nameOffset = uint32_t(p[0]) | (uint32_t(p[1]) << 8);
            e.fileSize = uint32_t(p[2]) | (uint32_t(p[3]) << 8) | (uint32_t(p[4]) << 16);
            e.fileOffset = (uint32_t(p[5]) | (uint32_t(p[6]) << 8) | (uint32_t(p[7]) << 16)) & 0x7FFFFF;
            e.systemFlags = readU32(p + 8);
            e.graphicsFlags = readU32(p + 12);
        }

        if (e.nameOffset >= namesData.size()) {
            throw Error(archName + ": name offset out of range");
        }
        const char *s = reinterpret_cast<const char *>(namesData.data() + e.nameOffset);
        const size_t maxLen = namesData.size() - e.nameOffset;
        e.name.assign(s, strnlen(s, maxLen));
        if (e.name.size() > 256) {
            e.name.resize(256); // same cap as CodeWalker
        }
        if (e.type == EntryType::Resource) {
            e.encrypted = endsWith(toLower(e.name), ".ysc");
            if (e.fileSize == 0xFFFFFF) {
                // huge resource: real size is smuggled into the RSC7 header bytes
                uint8_t rh[16];
                m_reader->read(start + uint64_t(e.fileOffset) * BlockSize, rh, 16);
                e.fileSize = uint32_t(rh[7]) | (uint32_t(rh[14]) << 8) | (uint32_t(rh[5]) << 16) | (uint32_t(rh[2]) << 24);
            }
        }
    }

    if (!entries[0].isDirectory()) {
        throw Error(archName + ": root entry is not a directory");
    }

    // assign parents; guard against malformed/cyclic ranges
    std::vector<uint32_t> stack{0};
    std::vector<bool> seen(entryCount, false);
    seen[0] = true;
    while (!stack.empty()) {
        const uint32_t d = stack.back();
        stack.pop_back();
        const Entry &dir = entries[d];
        if (uint64_t(dir.entriesIndex) + dir.entriesCount > entryCount) {
            throw Error(archName + ": directory range out of bounds");
        }
        for (uint32_t c = dir.entriesIndex; c < dir.entriesIndex + dir.entriesCount; ++c) {
            if (seen[c]) {
                throw Error(archName + ": directory tree is not a tree");
            }
            seen[c] = true;
            entries[c].parent = int(d);
            if (entries[c].isDirectory()) {
                stack.push_back(c);
            }
        }
    }

    m_archives[size_t(index)].encryption = effective;
    m_archives[size_t(index)].entries = std::move(entries);

    // nested archives
    const size_t count = m_archives[size_t(index)].entries.size();
    for (size_t i = 0; i < count; ++i) {
        const Entry e = m_archives[size_t(index)].entries[i];
        if (e.type != EntryType::Binary || e.parent < 0 || !endsWith(toLower(e.name), ".rpf")) {
            continue;
        }
        const uint64_t childStart = start + uint64_t(e.fileOffset) * BlockSize;
        const uint64_t childSize = e.storedSize();
        if (childStart + childSize > start + size || childSize < 16) {
            m_warnings.push_back(archName + "/" + e.name + ": nested archive out of bounds");
            continue;
        }
        uint8_t magic[4];
        m_reader->read(childStart, magic, 4);
        if (readU32(magic) != Rpf7Magic || e.fileSize != 0 || e.encrypted) {
            continue; // not a mountable RPF7 (compressed/encrypted child): keep as plain file
        }
        Archive child;
        child.name = e.name;
        child.startPos = childStart;
        child.size = childSize;
        child.parentArchive = index;
        child.parentEntry = int(i);
        const size_t before = m_archives.size();
        m_archives.push_back(std::move(child));
        const int childIndex = int(before);
        try {
            parseArchive(childIndex);
            m_archives[size_t(index)].entries[i].childArchive = childIndex;
        } catch (const Error &err) {
            if (dynamic_cast<const KeysRequired *>(&err)) {
                throw;
            }
            m_warnings.push_back(archName + "/" + e.name + ": " + err.what());
            m_archives.resize(before);
        }
    }
}

void Package::flatten()
{
    m_items.clear();
    std::function<void(int, int, const std::string &)> walk = [&](int a, int d, const std::string &prefix) {
        const Archive &arch = m_archives[size_t(a)];
        const Entry &dir = arch.entries[size_t(d)];
        for (uint32_t c = dir.entriesIndex; c < dir.entriesIndex + dir.entriesCount; ++c) {
            const Entry &e = arch.entries[c];
            const std::string path = prefix.empty() ? e.name : prefix + "/" + e.name;
            if (e.isDirectory()) {
                m_items.push_back({path, true, a, int(c)});
                walk(a, int(c), path);
            } else if (e.childArchive >= 0) {
                // nested RPF shown as a folder (like CodeWalker's explorer)
                m_items.push_back({path, true, a, int(c)});
                m_archives[size_t(e.childArchive)].pathPrefix = path;
                walk(e.childArchive, 0, path);
            } else {
                m_items.push_back({path, false, a, int(c)});
            }
        }
    };
    walk(0, 0, std::string());
}

Bytes Package::readStored(int archive, int entry) const
{
    const Archive &a = m_archives[size_t(archive)];
    const Entry &e = a.entries[size_t(entry)];
    if (e.isDirectory()) {
        throw Error("cannot read a directory");
    }
    const uint64_t off = a.startPos + uint64_t(e.fileOffset) * BlockSize;
    const uint64_t len = e.storedSize();
    if (off + len > a.startPos + a.size) {
        throw Error(e.name + ": data out of archive bounds");
    }
    return m_reader->read(off, size_t(len));
}

Bytes Package::extract(int archive, int entry, ResourceExtract mode) const
{
    const Archive &a = m_archives[size_t(archive)];
    const Entry &e = a.entries[size_t(entry)];
    Bytes data = readStored(archive, entry);

    if (e.type == EntryType::Binary) {
        if (e.encrypted) {
            decryptBlock(a, data.data(), data.size(), e.name, e.uncompressedSize);
        }
        if (e.fileSize != 0) {
            return inflateRaw(data.data(), data.size(), e.uncompressedSize);
        }
        return data;
    }

    // resource: 16-byte RSC7 header + (encrypted) deflated payload
    if (data.size() < 16) {
        throw Error(e.name + ": resource too small");
    }
    if (e.encrypted) {
        decryptBlock(a, data.data() + 16, data.size() - 16, e.name, e.fileSize);
    }
    if (mode == ResourceExtract::Rsc7) {
        return data;
    }
    auto inflated = tryInflateRaw(data.data() + 16, data.size() - 16, size_t(e.logicalSize()));
    if (inflated) {
        return std::move(*inflated);
    }
    return Bytes(data.begin() + 16, data.end());
}

Bytes Package::extractResourceHead(const Item &item, size_t maxBytes) const
{
    const Archive &a = m_archives[size_t(item.archive)];
    const Entry &e = a.entries[size_t(item.entry)];
    if (e.type != EntryType::Resource) {
        throw Error(e.name + ": not a resource");
    }
    const uint64_t stored = e.storedSize();
    if (stored < 16 || a.startPos + uint64_t(e.fileOffset) * BlockSize + stored > a.startPos + a.size) {
        throw Error(e.name + ": data out of archive bounds");
    }
    const uint64_t payloadPos = a.startPos + uint64_t(e.fileOffset) * BlockSize + 16;
    const uint64_t payloadLen = stored - 16;
    // grow the compressed window until it yields maxBytes (the NG/AES ciphers work on
    // independent 16-byte blocks, so a 16-byte aligned prefix decrypts on its own)
    for (uint64_t window = 64 * 1024;; window *= 4) {
        const uint64_t take = std::min(window, payloadLen);
        Bytes data = m_reader->read(payloadPos, size_t(take));
        if (e.encrypted) {
            const size_t aligned = take == payloadLen ? data.size() : data.size() & ~size_t(15);
            decryptBlock(a, data.data(), aligned, e.name, e.fileSize);
            data.resize(aligned);
        }
        Bytes out;
        try {
            out = inflateRawPrefix(data.data(), data.size(), maxBytes);
        } catch (const Error &) {
            // not deflated: extract() then returns the stored payload as is
            out = extract(item, ResourceExtract::Payload);
            out.resize(std::min(out.size(), maxBytes));
            return out;
        }
        if (out.size() >= maxBytes || take == payloadLen) {
            return out;
        }
    }
}

// ---------------- builder ----------------

BuildNode BuildNode::dir(std::string name, std::vector<BuildNode> children)
{
    BuildNode n;
    n.name = std::move(name);
    n.isDirectory = true;
    n.children = std::move(children);
    return n;
}

BuildNode BuildNode::file(std::string name, Bytes data, Kind kind)
{
    BuildNode n;
    n.name = std::move(name);
    n.data = std::move(data);
    n.kind = kind;
    return n;
}

namespace
{
struct FlatBuild {
    const BuildNode *node;
    Entry entry;
    Bytes payload;
};

uint64_t blocksFor(uint64_t bytes)
{
    return (bytes + BlockSize - 1) / BlockSize;
}
}

Bytes buildArchive(const BuildNode &root, Encryption encryption, const Crypto *crypto, const std::string &archiveName)
{
    if (!root.isDirectory) {
        throw Error("root must be a directory");
    }
    if ((encryption == Encryption::Aes || encryption == Encryption::Ng) && !crypto) {
        throw KeysRequired("encrypted archive creation requires GTA V keys");
    }
    if (encryption == Encryption::Ng && !crypto->canEncryptNg()) {
        throw KeysRequired("NG encryption tables are not available");
    }

    // flatten: stack DFS, each directory's children contiguous and sorted ordinally
    std::vector<FlatBuild> flat;
    flat.push_back({&root, {}, {}});
    flat[0].entry.type = EntryType::Directory;
    std::vector<size_t> stack{0};
    while (!stack.empty()) {
        const size_t di = stack.back();
        stack.pop_back();
        const BuildNode *dn = flat[di].node;
        std::vector<const BuildNode *> kids;
        for (const auto &c : dn->children) {
            kids.push_back(&c);
        }
        std::sort(kids.begin(), kids.end(), [](const BuildNode *x, const BuildNode *y) {
            return x->name < y->name;
        });
        for (size_t k = 1; k < kids.size(); ++k) {
            if (kids[k]->name == kids[k - 1]->name) {
                throw Error("duplicate entry name: " + kids[k]->name);
            }
        }
        flat[di].entry.entriesIndex = uint32_t(flat.size());
        flat[di].entry.entriesCount = uint32_t(kids.size());
        for (const BuildNode *c : kids) {
            if (c->name.empty() || c->name.find_first_of("/\\") != std::string::npos) {
                throw Error("invalid entry name: " + c->name);
            }
            FlatBuild fb{c, {}, {}};
            fb.entry.name = c->name;
            fb.entry.type = c->isDirectory ? EntryType::Directory : EntryType::Binary;
            flat.push_back(std::move(fb));
            if (c->isDirectory) {
                stack.push_back(flat.size() - 1);
            }
        }
    }

    // names blob (deduplicated, NUL-terminated, padded to 16)
    Bytes names;
    std::map<std::string, uint32_t> nameOffsets;
    for (auto &fb : flat) {
        auto it = nameOffsets.find(fb.entry.name);
        if (it == nameOffsets.end()) {
            if (names.size() > 0xFFFF) {
                throw Error("names blob too large");
            }
            it = nameOffsets.emplace(fb.entry.name, uint32_t(names.size())).first;
            names.insert(names.end(), fb.entry.name.begin(), fb.entry.name.end());
            names.push_back(0);
        }
        fb.entry.nameOffset = it->second;
    }
    names.resize((names.size() + 15) / 16 * 16, 0);

    // payloads
    for (auto &fb : flat) {
        if (fb.entry.isDirectory()) {
            continue;
        }
        const Bytes &d = fb.node->data;
        const std::string lower = toLower(fb.node->name);
        const bool isRsc = d.size() >= 16 && readU32(d.data()) == Rsc7Magic;
        BuildNode::Kind kind = fb.node->kind;
        if (kind == BuildNode::Kind::Auto) {
            if (isRsc) {
                kind = BuildNode::Kind::Resource;
            } else if (endsWith(lower, ".rpf") || endsWith(lower, ".awc")) {
                kind = BuildNode::Kind::Stored;
            } else {
                kind = BuildNode::Kind::Compressed;
            }
        }
        if (kind == BuildNode::Kind::Resource) {
            if (!isRsc) {
                throw Error(fb.node->name + ": resource data must start with RSC7");
            }
            if (d.size() > 0xFFFFFFFFu) {
                throw Error(fb.node->name + ": resource too large");
            }
            fb.entry.type = EntryType::Resource;
            fb.entry.systemFlags = readU32(d.data() + 8);
            fb.entry.graphicsFlags = readU32(d.data() + 12);
            fb.entry.fileSize = uint32_t(d.size());
            fb.payload = d;
            if (d.size() >= 0xFFFFFF) {
                const uint32_t len = uint32_t(d.size());
                fb.payload[7] = uint8_t(len);
                fb.payload[14] = uint8_t(len >> 8);
                fb.payload[5] = uint8_t(len >> 16);
                fb.payload[2] = uint8_t(len >> 24);
            }
            fb.entry.encrypted = false;
            continue;
        }
        if (d.size() > 0xFFFFFFFFu) {
            throw Error(fb.node->name + ": file too large");
        }
        fb.entry.uncompressedSize = uint32_t(d.size());
        if (kind == BuildNode::Kind::Compressed && !d.empty()) {
            Bytes c = deflateRaw(d.data(), d.size());
            if (c.size() < 0xFFFFFF) {
                fb.entry.fileSize = uint32_t(c.size());
                fb.payload = std::move(c);
                continue;
            }
        }
        fb.entry.fileSize = 0;
        fb.payload = d;
    }

    // layout
    const uint64_t headerBytes = 16 + uint64_t(flat.size()) * 16 + names.size();
    uint64_t block = blocksFor(headerBytes);
    for (auto &fb : flat) {
        if (fb.entry.isDirectory()) {
            continue;
        }
        if (block > 0x7FFFFF) {
            throw Error("archive too large");
        }
        fb.entry.fileOffset = uint32_t(block);
        block += std::max<uint64_t>(1, blocksFor(fb.payload.size()));
    }
    const uint64_t totalSize = block * BlockSize;

    // entries blob
    Bytes entries(flat.size() * 16, 0);
    for (size_t i = 0; i < flat.size(); ++i) {
        const Entry &e = flat[i].entry;
        uint8_t *p = entries.data() + i * 16;
        if (e.isDirectory()) {
            writeU32(p, e.nameOffset);
            writeU32(p + 4, DirectoryIdent);
            writeU32(p + 8, e.entriesIndex);
            writeU32(p + 12, e.entriesCount);
        } else if (e.type == EntryType::Binary) {
            p[0] = uint8_t(e.nameOffset);
            p[1] = uint8_t(e.nameOffset >> 8);
            p[2] = uint8_t(e.fileSize);
            p[3] = uint8_t(e.fileSize >> 8);
            p[4] = uint8_t(e.fileSize >> 16);
            p[5] = uint8_t(e.fileOffset);
            p[6] = uint8_t(e.fileOffset >> 8);
            p[7] = uint8_t(e.fileOffset >> 16);
            writeU32(p + 8, e.uncompressedSize);
            writeU32(p + 12, e.encrypted ? 1 : 0);
        } else {
            const uint32_t fs = std::min<uint32_t>(e.fileSize, 0xFFFFFF);
            p[0] = uint8_t(e.nameOffset);
            p[1] = uint8_t(e.nameOffset >> 8);
            p[2] = uint8_t(fs);
            p[3] = uint8_t(fs >> 8);
            p[4] = uint8_t(fs >> 16);
            p[5] = uint8_t(e.fileOffset);
            p[6] = uint8_t(e.fileOffset >> 8);
            p[7] = uint8_t(((e.fileOffset >> 16) & 0x7F) | 0x80);
            writeU32(p + 8, e.systemFlags);
            writeU32(p + 12, e.graphicsFlags);
        }
    }

    const std::string ngName = archiveName.empty() ? std::string("archive.rpf") : archiveName;
    if (encryption == Encryption::Aes) {
        crypto->encryptAes(entries.data(), entries.size());
        crypto->encryptAes(names.data(), names.size());
    } else if (encryption == Encryption::Ng) {
        crypto->encryptNg(entries.data(), entries.size(), ngName, uint32_t(totalSize));
        crypto->encryptNg(names.data(), names.size(), ngName, uint32_t(totalSize));
    }

    Bytes out(size_t(totalSize), 0);
    writeU32(out.data(), Rpf7Magic);
    writeU32(out.data() + 4, uint32_t(flat.size()));
    writeU32(out.data() + 8, uint32_t(names.size()));
    writeU32(out.data() + 12, uint32_t(encryption));
    std::copy(entries.begin(), entries.end(), out.begin() + 16);
    std::copy(names.begin(), names.end(), out.begin() + 16 + std::ptrdiff_t(entries.size()));
    for (const auto &fb : flat) {
        if (!fb.entry.isDirectory()) {
            std::copy(fb.payload.begin(), fb.payload.end(), out.begin() + std::ptrdiff_t(uint64_t(fb.entry.fileOffset) * BlockSize));
        }
    }
    return out;
}

} // namespace rageark
