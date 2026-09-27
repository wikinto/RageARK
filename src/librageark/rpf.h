// SPDX-License-Identifier: GPL-2.0-or-later
// RPF7 archive model. Format knowledge from CodeWalker (RpfFile.cs).
#pragma once

#include "bytes.h"

#include <memory>
#include <string>
#include <vector>

namespace rageark
{

constexpr uint32_t Rpf7Magic = 0x52504637; // "RPF7" read as LE u32 ("7FPR" on disk)
constexpr uint32_t Rsc7Magic = 0x37435352; // "RSC7"
constexpr uint32_t DirectoryIdent = 0x7FFFFF00;
constexpr uint64_t BlockSize = 512;

enum class Encryption : uint32_t {
    None = 0,
    Open = 0x4E45504F,
    Aes = 0x0FFFFFF9,
    Ng = 0x0FEFFFFF,
};

std::string encryptionName(Encryption e);

// Implemented by the key store (M1). Null crypto = only NONE/OPEN archives.
class Crypto
{
public:
    virtual ~Crypto() = default;
    virtual void decryptAes(uint8_t *data, size_t len) const = 0;
    virtual void encryptAes(uint8_t *data, size_t len) const = 0;
    virtual void decryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const = 0;
    virtual void encryptNg(uint8_t *data, size_t len, const std::string &name, uint32_t length) const = 0;
    virtual bool canEncryptNg() const = 0;
};

// Thrown when an encrypted archive is opened without keys.
class KeysRequired : public Error
{
public:
    using Error::Error;
};

enum class EntryType { Directory, Binary, Resource };

struct Entry {
    EntryType type = EntryType::Binary;
    std::string name;
    uint32_t nameOffset = 0;
    int parent = -1;

    // directory
    uint32_t entriesIndex = 0;
    uint32_t entriesCount = 0;

    // file
    uint32_t fileOffset = 0; // in 512-byte blocks, relative to the archive start
    uint32_t fileSize = 0; // stored size (binary: 0 = uncompressed)
    uint32_t uncompressedSize = 0; // binary only
    bool encrypted = false;
    uint32_t systemFlags = 0; // resource only
    uint32_t graphicsFlags = 0; // resource only

    int childArchive = -1; // index into Package::archives() for nested .rpf

    bool isDirectory() const
    {
        return type == EntryType::Directory;
    }
    // Bytes occupied in the archive (CodeWalker GetFileSize).
    uint64_t storedSize() const;
    // Size after extraction (best effort for resources).
    uint64_t logicalSize() const;
    uint32_t resourceVersion() const
    {
        return (((systemFlags >> 28) & 0xF) << 4) | ((graphicsFlags >> 28) & 0xF);
    }
};

uint32_t resourceSizeFromFlags(uint32_t flags);

struct Archive {
    std::string name; // name used for NG key selection (case preserved)
    uint64_t startPos = 0; // absolute offset in the physical file
    uint64_t size = 0;
    Encryption encryption = Encryption::None;
    std::vector<Entry> entries; // entries[0] = root directory
    int parentArchive = -1;
    int parentEntry = -1;
    std::string pathPrefix; // flattened path of this archive ("" for the top level)
};

enum class ResourceExtract {
    Rsc7, // RSC7 header + stored (compressed) payload, re-importable
    Payload, // decompressed payload (CodeWalker "Extract Uncompressed")
};

struct Item {
    std::string path; // forward slashes, no leading slash
    bool isDirectory = false;
    int archive = 0;
    int entry = 0;
};

class Package
{
public:
    Package(const std::string &filePath, const Crypto *crypto);

    const std::string &filePath() const
    {
        return m_filePath;
    }
    uint64_t fileSize() const
    {
        return m_reader->size();
    }
    const std::vector<Archive> &archives() const
    {
        return m_archives;
    }
    const std::vector<Item> &items() const
    {
        return m_items;
    }
    const std::vector<std::string> &warnings() const
    {
        return m_warnings;
    }
    const Entry &entry(const Item &item) const
    {
        return m_archives[size_t(item.archive)].entries[size_t(item.entry)];
    }

    // Raw bytes of a file entry exactly as stored (no decryption).
    Bytes readStored(int archive, int entry) const;
    Bytes extract(int archive, int entry, ResourceExtract mode = ResourceExtract::Rsc7) const;
    Bytes extract(const Item &item, ResourceExtract mode = ResourceExtract::Rsc7) const
    {
        return extract(item.archive, item.entry, mode);
    }

    // First maxBytes of a resource's decompressed payload (reads and decrypts only what is needed).
    Bytes extractResourceHead(const Item &item, size_t maxBytes) const;

private:
    void parseArchive(int index);
    void flatten();
    void decryptBlock(const Archive &a, uint8_t *data, size_t len, const std::string &name, uint32_t length) const;

    std::string m_filePath;
    std::unique_ptr<FileReader> m_reader;
    const Crypto *m_crypto;
    std::vector<Archive> m_archives;
    std::vector<Item> m_items;
    std::vector<std::string> m_warnings;
};

// ---- archive builder (fixtures now, new-archive creation later) ----

struct BuildNode {
    enum class Kind {
        Auto, // .rpf/.awc stored, everything else deflated when it helps
        Stored,
        Compressed,
        Resource, // data must be a complete RSC7 file
    };
    std::string name;
    bool isDirectory = false;
    Kind kind = Kind::Auto;
    Bytes data;
    std::vector<BuildNode> children;

    static BuildNode dir(std::string name, std::vector<BuildNode> children = {});
    static BuildNode file(std::string name, Bytes data, Kind kind = Kind::Auto);
};

// archiveName/crypto only matter for AES/NG (the NG key depends on name + final size).
Bytes buildArchive(const BuildNode &root, Encryption encryption = Encryption::Open, const Crypto *crypto = nullptr, const std::string &archiveName = {});

} // namespace rageark
