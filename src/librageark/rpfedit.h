// SPDX-License-Identifier: GPL-2.0-or-later
// In-place RPF7 editing (CodeWalker RPF Explorer edit mode, ANALYSIS part 3).
// Block allocator / WriteHeader / CreateFile / DeleteEntry ported from CodeWalker RpfFile.cs,
// with RageARK's safety model: backup first, data written before any TOC, TOCs re-encrypted
// with the archive's own encryption (NG by default), top-level header committed last.
#pragma once

#include "rpf.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace rageark
{

enum class BackupMode {
    On, // reflink when the filesystem supports it, full copy otherwise
    ReflinkOnly, // back up only when a reflink (COW clone) is possible
    Off,
};

struct EditOptions {
    BackupMode backup = BackupMode::On;
    std::function<void(const std::string &)> info; // progress / safety messages
};

std::string backupPath(const std::string &archivePath);
std::string journalPath(const std::string &archivePath);

// Creates archivePath.rageark-bak unless it exists. Returns true when a backup exists afterwards.
// Throws when mode == On and the copy fails.
bool ensureBackup(const std::string &archivePath, BackupMode mode, const std::function<void(const std::string &)> &info = {});

class ArchiveEditor
{
public:
    // crypto may be null for archives without AES/NG parts; NG writes need crypto->canEncryptNg().
    ArchiveEditor(const std::string &path, const Crypto *crypto, EditOptions options = {});
    ~ArchiveEditor();
    ArchiveEditor(const ArchiveEditor &) = delete;
    ArchiveEditor &operator=(const ArchiveEditor &) = delete;

    // Paths are the flattened paths of Package::items() ("a/b/dlc.rpf/c.xml"), '/' separated,
    // matched case-insensitively like the game. Nested .rpf entries act as folders.
    bool exists(const std::string &path) const;
    bool isDirectory(const std::string &path) const;

    // CodeWalker CreateFile: RSC7 data -> resource entry; .rpf/.awc stored; else raw-deflated.
    // Replaces an existing file. Missing parent folders are created.
    void addFile(const std::string &path, const Bytes &data);
    void addDirectory(const std::string &path); // no-op when it exists
    void remove(const std::string &path); // file, folder (recursive) or nested archive
    void move(const std::string &from, const std::string &to); // rename / move, also across archives
    void copy(const std::string &from, const std::string &to);

    // Writes all changed TOCs (deepest archive first, top-level header last) and syncs.
    void commit();
    bool hasChanges() const;

    struct Impl;

private:
    std::unique_ptr<Impl> d;
};

} // namespace rageark
