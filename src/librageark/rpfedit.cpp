// SPDX-License-Identifier: MIT
// In-place RPF7 editing. Allocator and TOC writer ported from CodeWalker RpfFile.cs
// (EnsureAllEntries, GetHeaderNamesData, WriteHeader, FindHole, FindEndBlock, GrowArchive,
// RelocateFile, EnsureSpace, InsertFileSpace, CreateFile, DeleteEntry, RenameEntry).
#include "rpfedit.h"

#include "deflate.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/fs.h>
#include <map>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rageark
{

std::string backupPath(const std::string &archivePath)
{
    return archivePath + ".rageark-bak";
}

std::string journalPath(const std::string &archivePath)
{
    return archivePath + ".rageark-journal";
}

bool ensureBackup(const std::string &archivePath, BackupMode mode, const std::function<void(const std::string &)> &info)
{
    const std::string bak = backupPath(archivePath);
    struct stat st {};
    if (::stat(bak.c_str(), &st) == 0) {
        return true; // one-time backup of the original: never overwritten
    }
    if (mode == BackupMode::Off) {
        return false;
    }
    const int src = ::open(archivePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        throw Error("cannot open " + archivePath + " for backup");
    }
    struct stat sst {};
    ::fstat(src, &sst);
    const std::string tmp = bak + ".tmp";
    const int dst = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, sst.st_mode & 0777);
    if (dst < 0) {
        ::close(src);
        throw Error("cannot create backup " + tmp);
    }
    bool ok = ::ioctl(dst, FICLONE, src) == 0;
    const bool reflinked = ok;
    if (!ok && mode == BackupMode::On) {
        if (info) {
            info("Creating backup " + bak + " (full copy, " + std::to_string(uint64_t(sst.st_size) >> 20) + " MiB; the filesystem has no reflink support)");
        }
        ok = true;
        off_t in = 0;
        off_t remaining = sst.st_size;
        while (remaining > 0) {
            const ssize_t n = ::copy_file_range(src, &in, dst, nullptr, size_t(std::min<off_t>(remaining, off_t(1) << 30)), 0);
            if (n <= 0) {
                ok = false;
                break;
            }
            remaining -= n;
        }
        ok = ok && ::fsync(dst) == 0;
    }
    ::close(src);
    ::close(dst);
    if (!ok) {
        ::unlink(tmp.c_str());
        if (mode == BackupMode::ReflinkOnly) {
            if (info) {
                info("No backup created: the filesystem does not support reflinks (backup = reflink-only)");
            }
            return false;
        }
        throw Error("creating the backup " + bak + " failed; the archive was not modified");
    }
    if (::rename(tmp.c_str(), bak.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw Error("cannot move backup into place: " + bak);
    }
    if (info) {
        info(std::string("Backup created: ") + bak + (reflinked ? " (reflink copy)" : ""));
    }
    return true;
}

namespace
{
uint64_t blocksFor(uint64_t bytes)
{
    return (bytes + BlockSize - 1) / BlockSize;
}

bool iequals(const std::string &a, const std::string &b)
{
    return toLower(a) == toLower(b);
}

std::vector<std::string> splitPath(const std::string &path)
{
    std::vector<std::string> out;
    std::string cur;
    for (char c : path) {
        if (c == '/' || c == '\\') {
            if (!cur.empty()) {
                out.push_back(cur);
            }
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) {
        out.push_back(cur);
    }
    return out;
}

bool storedPlainByExtension(const std::string &name)
{
    // retail NG archives keep these unencrypted (census of update.rpf)
    const std::string l = toLower(name);
    return endsWith(l, ".rpf") || endsWith(l, ".awc") || endsWith(l, ".bik");
}
} // namespace

struct ENode;

struct EArchive {
    std::string name; // NG key name
    uint64_t startPos = 0;
    uint64_t size = 0;
    Encryption encryption = Encryption::None;
    std::unique_ptr<ENode> root;
    EArchive *parent = nullptr;
    ENode *parentEntry = nullptr;
    int depth = 0;
    bool dirty = false;
};

struct ENode {
    std::string name;
    EntryType type = EntryType::Binary;
    uint32_t fileOffset = 0;
    uint32_t fileSize = 0;
    uint32_t uncompressedSize = 0;
    bool encrypted = false;
    uint32_t systemFlags = 0;
    uint32_t graphicsFlags = 0;
    // TOC bookkeeping
    uint32_t nameOffset = 0;
    uint32_t entriesIndex = 0;
    uint32_t entriesCount = 0;

    std::vector<std::unique_ptr<ENode>> children;
    ENode *parent = nullptr;
    EArchive *archive = nullptr;
    EArchive *child = nullptr; // mounted nested archive

    bool isDir() const
    {
        return type == EntryType::Directory;
    }
    uint64_t storedSize() const
    {
        if (type == EntryType::Binary) {
            return fileSize != 0 ? fileSize : uncompressedSize;
        }
        if (type == EntryType::Resource) {
            return fileSize != 0 ? fileSize : uint64_t(resourceSizeFromFlags(systemFlags)) + resourceSizeFromFlags(graphicsFlags);
        }
        return 0;
    }
};

struct ArchiveEditor::Impl {
    std::string path;
    const Crypto *crypto = nullptr;
    EditOptions options;
    int fd = -1;
    bool writable = false;
    bool changed = false;
    std::vector<std::unique_ptr<EArchive>> archives;

    ~Impl()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    void say(const std::string &s) const
    {
        if (options.info) {
            options.info(s);
        }
    }

    // ---- raw I/O ----
    void readAt(uint64_t off, uint8_t *dst, size_t len) const
    {
        size_t done = 0;
        while (done < len) {
            const ssize_t n = ::pread(fd, dst + done, len - done, off_t(off + done));
            if (n <= 0) {
                throw Error("read error in " + path);
            }
            done += size_t(n);
        }
    }
    Bytes readAt(uint64_t off, size_t len) const
    {
        Bytes b(len);
        readAt(off, b.data(), len);
        return b;
    }
    void writeAt(uint64_t off, const uint8_t *src, size_t len)
    {
        beginWrite();
        size_t done = 0;
        while (done < len) {
            const ssize_t n = ::pwrite(fd, src + done, len - done, off_t(off + done));
            if (n <= 0) {
                throw Error("write error in " + path + ": " + std::strerror(errno));
            }
            done += size_t(n);
        }
    }

    // Backup + journal before the first byte is changed (ANALYSIS 3.3).
    void beginWrite()
    {
        if (writable) {
            return;
        }
        ensureBackup(path, options.backup, options.info);
        const int wfd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (wfd < 0) {
            throw Error("cannot open " + path + " for writing: " + std::strerror(errno));
        }
        const int jfd = ::open(journalPath(path).c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (jfd >= 0) {
            const std::string msg = "RageARK edit in progress. If this file survives, the edit was interrupted: restore "
                + backupPath(path) + "\n";
            (void)!::write(jfd, msg.data(), msg.size());
            ::fsync(jfd);
            ::close(jfd);
        }
        ::close(fd);
        fd = wfd;
        writable = true;
    }

    // ---- parsing (same rules as Package) ----
    void decryptToc(const EArchive &a, Bytes &b) const
    {
        switch (a.encryption) {
        case Encryption::None:
        case Encryption::Open:
            return;
        case Encryption::Aes:
            if (!crypto) {
                throw KeysRequired(a.name + ": AES-encrypted archive requires GTA V keys");
            }
            crypto->decryptAes(b.data(), b.size());
            return;
        case Encryption::Ng:
            if (!crypto) {
                throw KeysRequired(a.name + ": NG-encrypted archive requires GTA V keys");
            }
            crypto->decryptNg(b.data(), b.size(), a.name, uint32_t(a.size));
            return;
        }
    }

    void parseArchive(EArchive *a)
    {
        uint8_t hdr[16];
        readAt(a->startPos, hdr, 16);
        if (readU32(hdr) != Rpf7Magic) {
            throw Error(a->name + ": not an RPF7 archive");
        }
        const uint32_t entryCount = readU32(hdr + 4);
        const uint32_t namesLength = readU32(hdr + 8);
        const uint32_t enc = readU32(hdr + 12);
        a->encryption = (enc == uint32_t(Encryption::None) || enc == uint32_t(Encryption::Open) || enc == uint32_t(Encryption::Aes)) ? Encryption(enc) : Encryption::Ng;
        if (entryCount == 0 || uint64_t(entryCount) * 16 + namesLength + 16 > a->size) {
            throw Error(a->name + ": corrupt TOC size");
        }
        Bytes entries = readAt(a->startPos + 16, size_t(entryCount) * 16);
        Bytes names = readAt(a->startPos + 16 + uint64_t(entryCount) * 16, namesLength);
        decryptToc(*a, entries);
        decryptToc(*a, names);

        std::vector<std::unique_ptr<ENode>> nodes(entryCount);
        for (uint32_t i = 0; i < entryCount; ++i) {
            const uint8_t *p = entries.data() + size_t(i) * 16;
            auto n = std::make_unique<ENode>();
            n->archive = a;
            const uint32_t x = readU32(p + 4);
            uint32_t nameOffset;
            if (x == DirectoryIdent) {
                n->type = EntryType::Directory;
                nameOffset = readU32(p);
                n->entriesIndex = readU32(p + 8);
                n->entriesCount = readU32(p + 12);
            } else if ((x & 0x80000000u) == 0) {
                n->type = EntryType::Binary;
                const uint64_t buf = readU64(p);
                nameOffset = uint32_t(buf & 0xFFFF);
                n->fileSize = uint32_t((buf >> 16) & 0xFFFFFF);
                n->fileOffset = uint32_t((buf >> 40) & 0xFFFFFF);
                n->uncompressedSize = readU32(p + 8);
                const uint32_t et = readU32(p + 12);
                if (et > 1) {
                    throw Error(a->name + ": corrupt binary entry");
                }
                n->encrypted = et == 1;
            } else {
                n->type = EntryType::Resource;
                nameOffset = uint32_t(p[0]) | (uint32_t(p[1]) << 8);
                n->fileSize = uint32_t(p[2]) | (uint32_t(p[3]) << 8) | (uint32_t(p[4]) << 16);
                n->fileOffset = (uint32_t(p[5]) | (uint32_t(p[6]) << 8) | (uint32_t(p[7]) << 16)) & 0x7FFFFF;
                n->systemFlags = readU32(p + 8);
                n->graphicsFlags = readU32(p + 12);
            }
            if (nameOffset >= names.size()) {
                throw Error(a->name + ": name offset out of range");
            }
            const char *s = reinterpret_cast<const char *>(names.data() + nameOffset);
            n->name.assign(s, strnlen(s, names.size() - nameOffset));
            if (n->type == EntryType::Resource) {
                n->encrypted = endsWith(toLower(n->name), ".ysc");
                if (n->fileSize == 0xFFFFFF) {
                    uint8_t rh[16];
                    readAt(a->startPos + uint64_t(n->fileOffset) * BlockSize, rh, 16);
                    n->fileSize = uint32_t(rh[7]) | (uint32_t(rh[14]) << 8) | (uint32_t(rh[5]) << 16) | (uint32_t(rh[2]) << 24);
                }
            }
            nodes[i] = std::move(n);
        }
        if (!nodes[0]->isDir()) {
            throw Error(a->name + ": root entry is not a directory");
        }
        // build the tree (same traversal/guards as Package)
        std::vector<bool> seen(entryCount, false);
        seen[0] = true;
        std::vector<ENode *> raw(entryCount);
        for (uint32_t i = 0; i < entryCount; ++i) {
            raw[i] = nodes[i].get();
        }
        std::vector<uint32_t> stack{0};
        std::vector<std::pair<uint32_t, uint32_t>> links; // (parent, child)
        while (!stack.empty()) {
            const uint32_t d = stack.back();
            stack.pop_back();
            const ENode *dir = raw[d];
            if (uint64_t(dir->entriesIndex) + dir->entriesCount > entryCount) {
                throw Error(a->name + ": directory range out of bounds");
            }
            for (uint32_t c = dir->entriesIndex; c < dir->entriesIndex + dir->entriesCount; ++c) {
                if (seen[c]) {
                    throw Error(a->name + ": directory tree is not a tree");
                }
                seen[c] = true;
                links.emplace_back(d, c);
                if (raw[c]->isDir()) {
                    stack.push_back(c);
                }
            }
        }
        for (const auto &[p, c] : links) {
            raw[c]->parent = raw[p];
        }
        for (const auto &[p, c] : links) {
            raw[p]->children.push_back(std::move(nodes[c]));
        }
        a->root = std::move(nodes[0]);

        // nested archives
        std::vector<ENode *> files;
        collectFiles(a->root.get(), files);
        for (ENode *e : files) {
            if (e->type != EntryType::Binary || !endsWith(toLower(e->name), ".rpf") || e->fileSize != 0 || e->encrypted) {
                continue;
            }
            const uint64_t childStart = a->startPos + uint64_t(e->fileOffset) * BlockSize;
            const uint64_t childSize = e->storedSize();
            if (childSize < 16 || childStart + childSize > a->startPos + a->size) {
                continue;
            }
            uint8_t magic[4];
            readAt(childStart, magic, 4);
            if (readU32(magic) != Rpf7Magic) {
                continue;
            }
            mountChild(a, e, e->name);
        }
    }

    // Parse the archive stored in entry e; keyName = name its TOC is currently encrypted with.
    void mountChild(EArchive *parentArchive, ENode *e, const std::string &keyName)
    {
        auto child = std::make_unique<EArchive>();
        child->name = keyName;
        child->startPos = parentArchive->startPos + uint64_t(e->fileOffset) * BlockSize;
        child->size = e->storedSize();
        child->parent = parentArchive;
        child->parentEntry = e;
        child->depth = parentArchive->depth + 1;
        EArchive *raw = child.get();
        const size_t before = archives.size();
        archives.push_back(std::move(child));
        try {
            parseArchive(raw);
            e->child = raw;
        } catch (const KeysRequired &) {
            throw;
        } catch (const Error &) {
            // not mountable: stays a plain file, like Package; drop anything added below it
            archives.resize(before);
        }
    }

    static void collectFiles(ENode *n, std::vector<ENode *> &out)
    {
        for (auto &c : n->children) {
            if (c->isDir()) {
                collectFiles(c.get(), out);
            } else {
                out.push_back(c.get());
            }
        }
    }

    std::vector<ENode *> filesOf(EArchive *a) const
    {
        std::vector<ENode *> out;
        collectFiles(a->root.get(), out);
        return out;
    }

    // ---- TOC layout (CodeWalker EnsureAllEntries / GetHeaderNamesData) ----
    std::vector<ENode *> allEntries(EArchive *a) const
    {
        std::vector<ENode *> all{a->root.get()};
        std::vector<ENode *> stack{a->root.get()};
        std::vector<ENode *> temp;
        while (!stack.empty()) {
            ENode *item = stack.back();
            stack.pop_back();
            item->entriesCount = uint32_t(item->children.size());
            item->entriesIndex = uint32_t(all.size());
            temp.clear();
            for (auto &c : item->children) {
                temp.push_back(c.get());
            }
            std::sort(temp.begin(), temp.end(), [](const ENode *x, const ENode *y) {
                return x->name < y->name; // String.CompareOrdinal
            });
            for (ENode *e : temp) {
                all.push_back(e);
                if (e->isDir()) {
                    stack.push_back(e);
                }
            }
        }
        return all;
    }

    Bytes namesBlob(const std::vector<ENode *> &all) const
    {
        Bytes names;
        std::map<std::string, uint32_t> offsets;
        for (ENode *e : all) {
            auto it = offsets.find(e->name);
            if (it == offsets.end()) {
                it = offsets.emplace(e->name, uint32_t(names.size())).first;
                names.insert(names.end(), e->name.begin(), e->name.end());
                names.push_back(0);
            }
            e->nameOffset = it->second;
        }
        names.resize((names.size() + 15) / 16 * 16, 0);
        return names;
    }

    uint64_t headerBytes(EArchive *a) const
    {
        const auto all = allEntries(a);
        return 16 + uint64_t(all.size()) * 16 + namesBlob(all).size();
    }

    // ---- allocator (CodeWalker RpfFile.cs:1230-1373, hardened) ----
    ENode *findFirstFileAfter(EArchive *a, uint32_t block) const
    {
        ENode *next = nullptr;
        for (ENode *f : filesOf(a)) {
            if (f->storedSize() == 0) {
                continue; // occupies no blocks
            }
            if (f->fileOffset > block && (!next || f->fileOffset < next->fileOffset)) {
                next = f;
            }
        }
        return next;
    }

    uint32_t findHole(EArchive *a, uint64_t reqBlocks, uint32_t ignoreStart, uint32_t ignoreEnd) const
    {
        std::vector<ENode *> files;
        for (ENode *f : filesOf(a)) {
            if (f->storedSize() != 0) {
                files.push_back(f);
            }
        }
        std::sort(files.begin(), files.end(), [](const ENode *x, const ENode *y) {
            return x->fileOffset < y->fileOffset;
        });
        uint32_t found = 0;
        uint64_t foundSize = UINT64_MAX;
        uint64_t e1next = blocksFor(headerBytes(a));
        for (ENode *f : files) {
            const uint64_t e2beg = f->fileOffset;
            const uint64_t e1end = e1next;
            e1next = std::max<uint64_t>(e1next, e2beg + blocksFor(f->storedSize()));
            if (e2beg > ignoreStart && e1end < ignoreEnd) {
                continue; // inside the area being made room for
            }
            if (e1end < e2beg) {
                const uint64_t space = e2beg - e1end;
                if (space >= reqBlocks && space < foundSize) {
                    found = uint32_t(e1end);
                    foundSize = space;
                }
            }
        }
        return found;
    }

    uint32_t findEndBlock(EArchive *a) const
    {
        uint64_t end = blocksFor(headerBytes(a));
        for (ENode *f : filesOf(a)) {
            if (f->storedSize() != 0) {
                end = std::max<uint64_t>(end, f->fileOffset + blocksFor(f->storedSize()));
            }
        }
        if (end > 0xFFFFFF) {
            throw Error(a->name + ": archive would exceed the RPF7 size limit");
        }
        return uint32_t(end);
    }

    void markDirty(EArchive *a)
    {
        a->dirty = true;
        changed = true;
    }

    void growArchive(EArchive *a, uint64_t newBlockCount)
    {
        const uint64_t newSize = newBlockCount * BlockSize;
        if (newSize <= a->size) {
            return;
        }
        a->size = newSize;
        markDirty(a); // the NG TOC key depends on the archive size
        if (a->parent) {
            ENode *pe = a->parentEntry;
            if (newSize > 0xFFFFFFFFull) {
                throw Error(a->name + ": nested archive would exceed 4 GiB");
            }
            pe->uncompressedSize = uint32_t(newSize);
            pe->fileSize = 0; // archives are stored uncompressed
            ensureSpace(a->parent, pe, newSize);
        }
    }

    void updateStartPos(EArchive *a, uint64_t newStart)
    {
        a->startPos = newStart;
        for (ENode *f : filesOf(a)) {
            if (f->child) {
                updateStartPos(f->child, newStart + uint64_t(f->fileOffset) * BlockSize);
            }
        }
    }

    void relocateFile(EArchive *a, ENode *f, uint32_t newBlock)
    {
        const uint64_t flen = blocksFor(f->storedSize());
        const uint64_t fbeg = f->fileOffset;
        if (newBlock + flen > fbeg && newBlock < fbeg + flen) {
            throw Error("cannot relocate " + f->name + ": new position overlaps the old one");
        }
        uint64_t src = a->startPos + fbeg * BlockSize;
        uint64_t dst = a->startPos + uint64_t(newBlock) * BlockSize;
        const uint64_t newStart = dst;
        uint64_t remaining = flen * BlockSize;
        Bytes buf(std::min<uint64_t>(remaining, 8u << 20));
        while (remaining > 0) {
            const size_t n = size_t(std::min<uint64_t>(remaining, buf.size()));
            readAt(src, buf.data(), n);
            writeAt(dst, buf.data(), n);
            src += n;
            dst += n;
            remaining -= n;
        }
        f->fileOffset = newBlock;
        if (f->child) {
            updateStartPos(f->child, newStart);
        }
        markDirty(a);
    }

    // Make room for `bytecount` bytes at entry e (e == nullptr: the header at block 0).
    void ensureSpace(EArchive *a, ENode *e, uint64_t bytecount)
    {
        const uint64_t blockCount = blocksFor(bytecount);
        const uint32_t startBlock = e ? e->fileOffset : 0;
        const uint64_t endBlock = startBlock + blockCount;
        ENode *next = findFirstFileAfter(a, startBlock);
        while (next) {
            if (next->fileOffset >= endBlock) {
                break;
            }
            const uint64_t entryBlocks = blocksFor(next->storedSize());
            uint32_t newBlock = findHole(a, entryBlocks, startBlock, uint32_t(std::min<uint64_t>(endBlock, 0xFFFFFFFF)));
            if (newBlock == 0) {
                newBlock = std::max<uint32_t>(findEndBlock(a), uint32_t(endBlock));
                growArchive(a, newBlock + entryBlocks);
            }
            relocateFile(a, next, newBlock);
            next = findFirstFileAfter(a, startBlock);
        }
        if (!next) {
            growArchive(a, std::max<uint64_t>(findEndBlock(a), endBlock));
        }
        markDirty(a);
    }

    void insertFileSpace(EArchive *a, ENode *entry)
    {
        const uint64_t blocks = blocksFor(entry->storedSize());
        // blocks inside the (possibly grown) header are not free
        const uint64_t header = blocksFor(headerBytes(a));
        uint32_t off = findHole(a, blocks, 0, 0);
        if (off == 0 || off < header) {
            off = findEndBlock(a);
            growArchive(a, uint64_t(off) + blocks);
        }
        entry->fileOffset = off;
        markDirty(a);
    }

    void writeEntryData(EArchive *a, ENode *e, const Bytes &data)
    {
        const uint64_t beg = a->startPos + uint64_t(e->fileOffset) * BlockSize;
        const uint64_t end = beg + blocksFor(e->storedSize()) * BlockSize;
        writeAt(beg, data.data(), data.size());
        if (beg + data.size() < end) {
            const Bytes pad(size_t(end - beg - data.size()), 0);
            writeAt(beg + data.size(), pad.data(), pad.size());
        }
    }

    // ---- TOC writer (CodeWalker WriteHeader, re-encrypting with the archive's encryption) ----
    void writeHeader(EArchive *a)
    {
        const auto all = allEntries(a);
        Bytes names = namesBlob(all);
        if (names.size() > 0xFFFF + 1) {
            throw Error(a->name + ": too many names for an RPF7 TOC");
        }
        Bytes entries(all.size() * 16, 0);
        for (size_t i = 0; i < all.size(); ++i) {
            const ENode *e = all[i];
            uint8_t *p = entries.data() + i * 16;
            if (e->isDir()) {
                writeU32(p, e->nameOffset);
                writeU32(p + 4, DirectoryIdent);
                writeU32(p + 8, e->entriesIndex);
                writeU32(p + 12, e->entriesCount);
                continue;
            }
            if (e->nameOffset > 0xFFFF) {
                throw Error(a->name + ": name table overflow");
            }
            p[0] = uint8_t(e->nameOffset);
            p[1] = uint8_t(e->nameOffset >> 8);
            const uint32_t fs = std::min<uint32_t>(e->fileSize, 0xFFFFFF);
            p[2] = uint8_t(fs);
            p[3] = uint8_t(fs >> 8);
            p[4] = uint8_t(fs >> 16);
            p[5] = uint8_t(e->fileOffset);
            p[6] = uint8_t(e->fileOffset >> 8);
            if (e->type == EntryType::Binary) {
                p[7] = uint8_t(e->fileOffset >> 16);
                writeU32(p + 8, e->uncompressedSize);
                writeU32(p + 12, e->encrypted ? 1 : 0);
            } else {
                p[7] = uint8_t(((e->fileOffset >> 16) & 0x7F) | 0x80);
                writeU32(p + 8, e->systemFlags);
                writeU32(p + 12, e->graphicsFlags);
            }
        }
        switch (a->encryption) {
        case Encryption::None:
        case Encryption::Open:
            break;
        case Encryption::Aes:
            crypto->encryptAes(entries.data(), entries.size());
            crypto->encryptAes(names.data(), names.size());
            break;
        case Encryption::Ng:
            if (!crypto || !crypto->canEncryptNg()) {
                throw KeysRequired(a->name + ": NG encryption tables are required to write this archive");
            }
            crypto->encryptNg(entries.data(), entries.size(), a->name, uint32_t(a->size));
            crypto->encryptNg(names.data(), names.size(), a->name, uint32_t(a->size));
            break;
        }
        const uint64_t headerBlocks = blocksFor(16 + entries.size() + names.size());
        Bytes out(size_t(headerBlocks * BlockSize), 0);
        writeU32(out.data(), Rpf7Magic);
        writeU32(out.data() + 4, uint32_t(all.size()));
        writeU32(out.data() + 8, uint32_t(names.size()));
        writeU32(out.data() + 12, uint32_t(a->encryption));
        std::copy(entries.begin(), entries.end(), out.begin() + 16);
        std::copy(names.begin(), names.end(), out.begin() + 16 + std::ptrdiff_t(entries.size()));
        writeAt(a->startPos, out.data(), out.size()); // one write: the header commit
    }

    // ---- entry crypto ----
    void cryptEntry(const EArchive *a, const ENode *e, Bytes &data, bool encrypt) const
    {
        if (e->type == EntryType::Binary && !e->encrypted) {
            return;
        }
        if (e->type == EntryType::Resource && !e->encrypted) {
            return;
        }
        if (!crypto) {
            throw KeysRequired(e->name + ": encrypted entry requires GTA V keys");
        }
        uint8_t *p = data.data();
        size_t len = data.size();
        uint32_t length = e->uncompressedSize;
        if (e->type == EntryType::Resource) {
            if (len < 16) {
                return;
            }
            p += 16;
            len -= 16;
            length = e->fileSize;
        }
        if (a->encryption == Encryption::Aes) {
            encrypt ? crypto->encryptAes(p, len) : crypto->decryptAes(p, len);
        } else {
            if (encrypt && !crypto->canEncryptNg()) {
                throw KeysRequired(e->name + ": NG encryption tables are required");
            }
            encrypt ? crypto->encryptNg(p, len, e->name, length) : crypto->decryptNg(p, len, e->name, length);
        }
    }

    bool shouldEncryptNewBinary(const EArchive *a, const std::string &name) const
    {
        return a->encryption == Encryption::Ng && !storedPlainByExtension(name);
    }

    // ---- path resolution ----
    struct Loc {
        EArchive *archive = nullptr;
        ENode *node = nullptr; // entry (for a nested archive: its entry in the parent)
    };

    static ENode *findChild(ENode *dir, const std::string &name)
    {
        for (auto &c : dir->children) {
            if (iequals(c->name, name)) {
                return c.get();
            }
        }
        return nullptr;
    }

    // Directory node to put children into: a folder, or the root of a nested archive.
    static ENode *containerOf(ENode *n)
    {
        if (n->isDir()) {
            return n;
        }
        if (n->child) {
            return n->child->root.get();
        }
        return nullptr;
    }

    Loc resolve(const std::string &path) const
    {
        const auto parts = splitPath(path);
        EArchive *a = archives[0].get();
        ENode *cur = a->root.get();
        for (size_t i = 0; i < parts.size(); ++i) {
            ENode *dir = containerOf(cur);
            if (!dir) {
                return {};
            }
            a = dir->archive;
            ENode *next = findChild(dir, parts[i]);
            if (!next) {
                return {};
            }
            cur = next;
        }
        return {cur->archive, cur};
    }

    ENode *makeDirs(const std::vector<std::string> &parts, size_t count)
    {
        ENode *cur = archives[0]->root.get();
        for (size_t i = 0; i < count; ++i) {
            ENode *dir = containerOf(cur);
            if (!dir) {
                throw Error(cur->name + " is a file, not a folder");
            }
            ENode *next = findChild(dir, parts[i]);
            if (!next) {
                validateName(parts[i]);
                auto n = std::make_unique<ENode>();
                n->name = parts[i];
                n->type = EntryType::Directory;
                n->archive = dir->archive;
                n->parent = dir;
                next = n.get();
                dir->children.push_back(std::move(n));
                markDirty(dir->archive);
            }
            cur = next;
        }
        ENode *dir = containerOf(cur);
        if (!dir) {
            throw Error(cur->name + " is a file, not a folder");
        }
        return dir;
    }

    static void validateName(const std::string &name)
    {
        if (name.empty() || name.size() > 255 || name.find_first_of("/\\") != std::string::npos || name == "." || name == "..") {
            throw Error("invalid entry name: " + name);
        }
    }

    // CodeWalker DeleteEntry: drop the entry (space becomes a hole) and any nested archive.
    void removeNode(ENode *n)
    {
        if (!n->parent) {
            throw Error("cannot delete the archive root");
        }
        dropArchivesUnder(n);
        EArchive *a = n->archive;
        auto &siblings = n->parent->children;
        siblings.erase(std::remove_if(siblings.begin(), siblings.end(),
                                      [n](const std::unique_ptr<ENode> &c) {
                                          return c.get() == n;
                                      }),
                       siblings.end());
        markDirty(a);
    }

    void dropArchivesUnder(ENode *n)
    {
        std::vector<EArchive *> doomed;
        std::function<void(ENode *)> walk = [&](ENode *x) {
            if (x->child) {
                doomed.push_back(x->child);
                walk(x->child->root.get());
            }
            for (auto &c : x->children) {
                walk(c.get());
            }
        };
        walk(n);
        archives.erase(std::remove_if(archives.begin(), archives.end(),
                                      [&](const std::unique_ptr<EArchive> &a) {
                                          return std::find(doomed.begin(), doomed.end(), a.get()) != doomed.end();
                                      }),
                       archives.end());
    }

    // Insert a new file entry with final stored bytes (already compressed/encrypted).
    ENode *insertFile(ENode *dir, std::unique_ptr<ENode> node, const Bytes &stored)
    {
        EArchive *a = dir->archive;
        if (ENode *existing = findChild(dir, node->name)) {
            if (existing->isDir()) {
                throw Error(node->name + " already exists as a folder");
            }
            removeNode(existing); // CreateFile(overwrite = true)
        }
        node->archive = a;
        node->parent = dir;
        ENode *raw = node.get();
        dir->children.push_back(std::move(node));
        insertFileSpace(a, raw);
        writeEntryData(a, raw, stored);
        return raw;
    }

    // CodeWalker CreateFile conversion rules.
    ENode *createFile(ENode *dir, const std::string &name, Bytes data)
    {
        validateName(name);
        EArchive *a = dir->archive;
        const std::string lower = toLower(name);
        auto e = std::make_unique<ENode>();
        e->name = name;
        const uint32_t hdr = data.size() >= 16 ? readU32(data.data()) : 0;
        bool isRpf = false;
        if (data.size() > 0xFFFFFFFFull) {
            throw Error(name + ": file too large for an RPF entry");
        }
        const uint32_t len = uint32_t(data.size());
        if (hdr == Rsc7Magic) {
            e->type = EntryType::Resource;
            e->systemFlags = readU32(data.data() + 8);
            e->graphicsFlags = readU32(data.data() + 12);
            e->fileSize = len;
            if (len >= 0xFFFFFF) {
                data[7] = uint8_t(len);
                data[14] = uint8_t(len >> 8);
                data[5] = uint8_t(len >> 16);
                data[2] = uint8_t(len >> 24);
            }
            e->encrypted = endsWith(lower, ".ysc");
            cryptEntry(a, e.get(), data, true);
            return insertFile(dir, std::move(e), data);
        }
        isRpf = endsWith(lower, ".rpf") && hdr == Rpf7Magic;
        const bool stored = isRpf || endsWith(lower, ".awc");
        e->type = EntryType::Binary;
        e->uncompressedSize = len;
        Bytes payload;
        if (stored) {
            e->fileSize = 0;
            payload = std::move(data);
        } else {
            payload = deflateRaw(data.data(), data.size());
            if (payload.size() > 0xFFFFFF) {
                e->fileSize = 0;
                payload = std::move(data);
            } else {
                e->fileSize = uint32_t(payload.size());
            }
        }
        e->encrypted = shouldEncryptNewBinary(a, name) && !payload.empty();
        cryptEntry(a, e.get(), payload, true);
        ENode *node = insertFile(dir, std::move(e), payload);
        if (isRpf) {
            mountChild(a, node, name);
        }
        return node;
    }

    // Stored bytes of a file entry, decrypted (still compressed).
    Bytes readPlainStored(ENode *e)
    {
        Bytes data = readAt(e->archive->startPos + uint64_t(e->fileOffset) * BlockSize, size_t(e->storedSize()));
        cryptEntry(e->archive, e, data, false);
        return data;
    }

    ENode *copyNode(ENode *src, ENode *dstDir, const std::string &newName)
    {
        validateName(newName);
        if (src->isDir()) {
            ENode *d = findChild(dstDir, newName);
            if (d && !d->isDir()) {
                throw Error(newName + " already exists as a file");
            }
            if (!d) {
                auto n = std::make_unique<ENode>();
                n->name = newName;
                n->type = EntryType::Directory;
                n->archive = dstDir->archive;
                n->parent = dstDir;
                d = n.get();
                dstDir->children.push_back(std::move(n));
                markDirty(dstDir->archive);
            }
            // snapshot: copying a folder into itself must not recurse forever
            std::vector<ENode *> kids;
            for (auto &c : src->children) {
                kids.push_back(c.get());
            }
            for (ENode *c : kids) {
                copyNode(c, d, c->name);
            }
            return d;
        }
        EArchive *da = dstDir->archive;
        auto e = std::make_unique<ENode>();
        e->name = newName;
        e->type = src->type;
        e->fileSize = src->fileSize;
        e->uncompressedSize = src->uncompressedSize;
        e->systemFlags = src->systemFlags;
        e->graphicsFlags = src->graphicsFlags;
        Bytes data;
        if (src->child) {
            // nested archive: copied verbatim, its TOC re-keyed below if the name changes
            data = readAt(src->archive->startPos + uint64_t(src->fileOffset) * BlockSize, size_t(src->storedSize()));
            e->encrypted = false;
        } else {
            data = readPlainStored(src);
            if (src->type == EntryType::Resource) {
                e->encrypted = endsWith(toLower(newName), ".ysc");
            } else {
                e->encrypted = src->encrypted ? (da->encryption == Encryption::Ng || da->encryption == Encryption::Aes)
                                              : false;
            }
            cryptEntry(da, e.get(), data, true);
        }
        const std::string keyName = src->child ? src->child->name : std::string();
        ENode *node = insertFile(dstDir, std::move(e), data);
        if (!keyName.empty()) {
            mountChild(da, node, keyName);
            if (node->child && node->child->name != newName) {
                node->child->name = newName; // re-encrypt its TOC for the new name
                markDirty(node->child);
            }
        }
        return node;
    }

    bool renameNeedsReencrypt(const ENode *n, const std::string &newName) const
    {
        if (n->isDir() || n->child) {
            return false;
        }
        if (n->type == EntryType::Resource && endsWith(toLower(n->name), ".ysc") != endsWith(toLower(newName), ".ysc")) {
            return true; // resource encryption is implied by the .ysc name
        }
        if (!n->encrypted) {
            return false;
        }
        // NG keys depend on the entry name (AES does not)
        return n->archive->encryption != Encryption::Aes;
    }

    void commit()
    {
        if (!changed) {
            return;
        }
        // deepest archives first; the top-level header is written last
        for (;;) {
            EArchive *next = nullptr;
            for (auto &a : archives) {
                if (a->dirty && (!next || a->depth > next->depth)) {
                    next = a.get();
                }
            }
            if (!next) {
                break;
            }
            ensureSpace(next, nullptr, headerBytes(next)); // may relocate files / grow ancestors
            if (next->parent == nullptr) {
                // top level: the NG key uses the real file size
                struct stat st {};
                ::fstat(fd, &st);
                if (uint64_t(st.st_size) < next->size) {
                    if (::ftruncate(fd, off_t(next->size)) != 0) {
                        throw Error("cannot extend " + path);
                    }
                } else if (uint64_t(st.st_size) > next->size) {
                    next->size = uint64_t(st.st_size);
                }
                if (::fdatasync(fd) != 0) {
                    throw Error("sync failed for " + path);
                }
            }
            writeHeader(next);
            next->dirty = false;
        }
        if (::fdatasync(fd) != 0) {
            throw Error("sync failed for " + path);
        }
        ::unlink(journalPath(path).c_str());
        changed = false;
    }
};

ArchiveEditor::ArchiveEditor(const std::string &path, const Crypto *crypto, EditOptions options)
    : d(std::make_unique<Impl>())
{
    d->path = path;
    d->crypto = crypto;
    d->options = std::move(options);
    d->fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (d->fd < 0) {
        throw Error("cannot open " + path);
    }
    struct stat st {};
    ::fstat(d->fd, &st);
    auto top = std::make_unique<EArchive>();
    const auto slash = path.find_last_of('/');
    top->name = slash == std::string::npos ? path : path.substr(slash + 1);
    top->size = uint64_t(st.st_size);
    EArchive *raw = top.get();
    d->archives.push_back(std::move(top));
    d->parseArchive(raw);
}

ArchiveEditor::~ArchiveEditor() = default;

bool ArchiveEditor::exists(const std::string &path) const
{
    return d->resolve(path).node != nullptr;
}

bool ArchiveEditor::isDirectory(const std::string &path) const
{
    const auto loc = d->resolve(path);
    return loc.node && Impl::containerOf(loc.node) != nullptr;
}

void ArchiveEditor::addFile(const std::string &path, const Bytes &data)
{
    const auto parts = splitPath(path);
    if (parts.empty()) {
        throw Error("empty path");
    }
    ENode *dir = d->makeDirs(parts, parts.size() - 1);
    d->createFile(dir, parts.back(), data);
}

void ArchiveEditor::addDirectory(const std::string &path)
{
    const auto parts = splitPath(path);
    d->makeDirs(parts, parts.size());
}

void ArchiveEditor::remove(const std::string &path)
{
    const auto loc = d->resolve(path);
    if (!loc.node) {
        throw Error("not found in archive: " + path);
    }
    d->removeNode(loc.node);
}

void ArchiveEditor::move(const std::string &from, const std::string &to)
{
    const auto src = d->resolve(from);
    if (!src.node || !src.node->parent) {
        throw Error("not found in archive: " + from);
    }
    const auto parts = splitPath(to);
    if (parts.empty()) {
        throw Error("empty destination path");
    }
    Impl::validateName(parts.back());
    ENode *dstDir = d->makeDirs(parts, parts.size() - 1);
    // moving a folder into itself is impossible
    for (const ENode *p = dstDir; p; p = p->parent ? p->parent : p->archive->parentEntry) {
        if (p == src.node) {
            throw Error("cannot move " + from + " into itself");
        }
    }
    ENode *existing = Impl::findChild(dstDir, parts.back());
    if (existing == src.node) {
        existing = nullptr; // case-only rename
    }
    if (existing) {
        if (existing->isDir() || src.node->isDir()) {
            throw Error(to + " already exists");
        }
        d->removeNode(existing);
    }
    if (dstDir->archive == src.archive && !d->renameNeedsReencrypt(src.node, parts.back())) {
        // TOC-only rename/move (CodeWalker RenameEntry)
        ENode *n = src.node;
        auto &siblings = n->parent->children;
        auto it = std::find_if(siblings.begin(), siblings.end(), [n](const std::unique_ptr<ENode> &c) {
            return c.get() == n;
        });
        std::unique_ptr<ENode> owned = std::move(*it);
        siblings.erase(it);
        owned->name = parts.back();
        owned->parent = dstDir;
        if (owned->child) {
            owned->child->name = parts.back(); // nested TOC key follows the entry name
            d->markDirty(owned->child);
        }
        dstDir->children.push_back(std::move(owned));
        d->markDirty(src.archive);
        return;
    }
    d->copyNode(src.node, dstDir, parts.back());
    d->removeNode(src.node);
}

void ArchiveEditor::copy(const std::string &from, const std::string &to)
{
    const auto src = d->resolve(from);
    if (!src.node || !src.node->parent) {
        throw Error("not found in archive: " + from);
    }
    const auto parts = splitPath(to);
    if (parts.empty()) {
        throw Error("empty destination path");
    }
    ENode *dstDir = d->makeDirs(parts, parts.size() - 1);
    if (Impl::findChild(dstDir, parts.back()) == src.node) {
        throw Error("cannot copy " + from + " onto itself");
    }
    d->copyNode(src.node, dstDir, parts.back());
}

void ArchiveEditor::commit()
{
    d->commit();
}

bool ArchiveEditor::hasChanges() const
{
    return d->changed;
}

} // namespace rageark
