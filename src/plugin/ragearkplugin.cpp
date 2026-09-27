// SPDX-License-Identifier: GPL-2.0-or-later
#include "ragearkplugin.h"

#include "archiveentry.h"
#include "awc.h"
#include "exepickerquery.h"
#include "keys.h"
#include "keystore.h"
#include "rpf.h"
#include "rpfedit.h"
#include "ytd.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KPluginFactory>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QThread>

K_PLUGIN_CLASS_WITH_JSON(RageArkPlugin, "ragearkplugin.json")

RageArkPlugin::RageArkPlugin(QObject *parent, const QVariantList &args)
    : ReadWriteArchiveInterface(parent, args)
{
}

static QString configuredExe()
{
    const KConfigGroup group = KSharedConfig::openConfig(QStringLiteral("ragearkrc"))->group(QStringLiteral("Keys"));
    return group.readEntry("gta_exe", QString());
}

static void storeConfiguredExe(const QString &path)
{
    KConfigGroup group = KSharedConfig::openConfig(QStringLiteral("ragearkrc"))->group(QStringLiteral("Keys"));
    group.writeEntry("gta_exe", path);
    group.sync();
}

// cache -> $RAGEARK_GTA_EXE -> ragearkrc [Keys] gta_exe -> exe-picker popup
bool RageArkPlugin::ensureKeys()
{
    if (m_crypto) {
        return true;
    }
    auto progressInfo = [this](const std::string &s) {
        Q_EMIT info(QString::fromStdString(s));
    };
    QString failure;
    try {
        if (auto keys = rageark::KeyStore::resolve(configuredExe().toStdString(), progressInfo)) {
            m_crypto = std::make_shared<rageark::KeyCrypto>(keys);
            return true;
        }
    } catch (const std::exception &e) {
        failure = QString::fromUtf8(e.what()); // stale config path etc.: fall through to the popup
    }
    for (int attempt = 0; attempt < 3; ++attempt) {
        ExePickerQuery query(QFileInfo(filename()).fileName(), failure);
        Q_EMIT userQuery(&query);
        query.waitForResponse();
        if (query.cancelled()) {
            return false;
        }
        try {
            auto keys = rageark::KeyStore::fromExe(query.exePath().toStdString(), progressInfo);
            storeConfiguredExe(query.exePath());
            m_crypto = std::make_shared<rageark::KeyCrypto>(keys);
            return true;
        } catch (const std::exception &e) {
            failure = QString::fromUtf8(e.what());
        }
    }
    return false;
}

bool RageArkPlugin::openPackage(QString *errorOut)
{
    if (m_package) {
        return true;
    }
    try {
        try {
            m_package = std::make_shared<rageark::Package>(filename().toStdString(), m_crypto.get());
        } catch (const rageark::KeysRequired &) {
            if (!ensureKeys()) {
                throw;
            }
            m_package = std::make_shared<rageark::Package>(filename().toStdString(), m_crypto.get());
        }
        return true;
    } catch (const rageark::KeysRequired &e) {
        if (errorOut) {
            *errorOut = QString::fromUtf8(e.what());
        }
        Q_EMIT error(i18nc("error message",
                           "GTA V keys are required to open this archive. Select your GTA5.exe or GTA5_Enhanced.exe, "
                           "or set RAGEARK_GTA_EXE, or add gta_exe=... under [Keys] in ~/.config/ragearkrc. (%1)",
                           QString::fromUtf8(e.what())));
        return false;
    } catch (const std::exception &e) {
        if (errorOut) {
            *errorOut = QString::fromUtf8(e.what());
        }
        Q_EMIT error(i18nc("error message", "Failed to open RPF archive: %1", QString::fromUtf8(e.what())));
        return false;
    }
}

// [Awc] decode / [Ytd] decode in ragearkrc
static bool decodeEnabled(const QString &group)
{
    return KSharedConfig::openConfig(QStringLiteral("ragearkrc"))->group(group).readEntry("decode", true);
}

void RageArkPlugin::buildListing()
{
    m_listed.clear();
    m_listedIndex.clear();
    m_ytdItem = -1;
    m_ytd.reset();
    const bool decodeAwc = decodeEnabled(QStringLiteral("Awc"));
    const bool decodeYtd = decodeEnabled(QStringLiteral("Ytd"));
    const auto *awcKey = m_crypto ? &m_crypto->keys().awcKey : nullptr;
    const auto &items = m_package->items();
    auto add = [this](Listed l) {
        m_listedIndex.insert(l.path, int(m_listed.size()));
        m_listed.push_back(std::move(l));
    };
    for (size_t i = 0; i < items.size(); ++i) {
        const auto &item = items[i];
        const rageark::Entry &re = m_package->entry(item);
        Listed l;
        l.path = QString::fromStdString(item.path);
        l.item = int(i);
        l.isDirectory = item.isDirectory;
        if (!item.isDirectory) {
            // resources are extracted as RSC7 files (header + stored payload)
            l.size = re.type == rageark::EntryType::Resource ? re.storedSize() : re.logicalSize();
            l.compressedSize = re.storedSize();
        }
        if (decodeAwc && !item.isDirectory && re.type == rageark::EntryType::Binary && rageark::endsWith(rageark::toLower(re.name), ".awc")) {
            // decoded view (ANALYSIS 2.5): foo.awc/ folder with one file per audio stream
            try {
                const rageark::AwcFile awc(m_package->extract(item), re.name, awcKey);
                l.isDirectory = true;
                const QString dir = l.path;
                add(l);
                for (const auto &w : awc.waves()) {
                    Listed s;
                    s.path = dir + QLatin1Char('/') + QString::fromStdString(w.name + "." + w.extension);
                    s.item = int(i);
                    s.awcStream = w.streamIndex;
                    s.size = w.exportSize;
                    s.compressedSize = w.exportSize;
                    add(s);
                }
                continue;
            } catch (const std::exception &e) {
                Q_EMIT info(i18nc("info", "%1: AWC not decoded (%2), listed as raw file", l.path, QString::fromUtf8(e.what())));
            }
        }
        if (decodeYtd && !item.isDirectory && re.type == rageark::EntryType::Resource && rageark::endsWith(rageark::toLower(re.name), ".ytd")) {
            // decoded view: foo.ytd/ folder with one .dds per texture (CodeWalker's DDS export).
            // Listing needs only the system pages, the pixel data is read on extraction.
            try {
                const rageark::YtdFile ytd(m_package->extractResourceHead(item, rageark::YtdFile::headerSize(re.systemFlags)), re.systemFlags,
                                           re.graphicsFlags);
                l.isDirectory = true;
                const QString dir = l.path;
                add(l);
                const auto &textures = ytd.textures();
                for (size_t t = 0; t < textures.size(); ++t) {
                    if (!textures[t].ddsError.empty()) {
                        Q_EMIT info(i18nc("info", "%1: texture %2 cannot be exported (%3)", l.path, QString::fromStdString(textures[t].name),
                                          QString::fromStdString(textures[t].ddsError)));
                        continue;
                    }
                    Listed s;
                    s.path = dir + QLatin1Char('/') + QString::fromStdString(textures[t].fileName);
                    s.item = int(i);
                    s.ytdTexture = int(t);
                    s.size = textures[t].ddsSize;
                    s.compressedSize = textures[t].ddsSize;
                    add(s);
                }
                continue;
            } catch (const std::exception &e) {
                Q_EMIT info(i18nc("info", "%1: texture dictionary not decoded (%2), listed as raw file", l.path, QString::fromUtf8(e.what())));
            }
        }
        add(l);
    }
}

rageark::Bytes RageArkPlugin::readListed(const Listed &l) const
{
    const auto &item = m_package->items()[size_t(l.item)];
    if (l.awcStream >= 0) {
        const rageark::Entry &re = m_package->entry(item);
        const rageark::AwcFile awc(m_package->extract(item), re.name, m_crypto ? &m_crypto->keys().awcKey : nullptr);
        return awc.exportStream(l.awcStream);
    }
    if (l.ytdTexture >= 0) {
        if (m_ytdItem != l.item || !m_ytd) {
            const rageark::Entry &re = m_package->entry(item);
            m_ytd = std::make_shared<rageark::YtdFile>(m_package->extract(item, rageark::ResourceExtract::Payload), re.systemFlags, re.graphicsFlags);
            m_ytdItem = l.item;
        }
        return m_ytd->dds(size_t(l.ytdTexture));
    }
    // Ark extract = CodeWalker "Extract Raw": resources keep their RSC7 header (re-importable)
    return m_package->extract(item, rageark::ResourceExtract::Rsc7);
}

bool RageArkPlugin::list()
{
    if (!openPackage()) {
        return false;
    }
    buildListing();
    quint64 done = 0;
    for (const auto &l : m_listed) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        auto *e = new Kerfuffle::Archive::Entry(); // ownership passes to Ark's model
        e->setProperty("fullPath", l.isDirectory ? l.path + QLatin1Char('/') : l.path);
        e->setProperty("isDirectory", l.isDirectory);
        if (!l.isDirectory) {
            e->setProperty("size", qulonglong(l.size));
            e->setProperty("compressedSize", qulonglong(l.compressedSize));
            e->compressedSizeIsSet = true;
        }
        Q_EMIT entry(e);
        Q_EMIT progress(double(++done) / double(m_listed.size() + 1));
    }
    for (const auto &w : m_package->warnings()) {
        Q_EMIT info(QString::fromStdString(w));
    }
    if (QFile::exists(QString::fromStdString(rageark::journalPath(filename().toStdString())))) {
        Q_EMIT info(i18nc("warning", "A previous RageARK edit of this archive was interrupted. If the archive is damaged, restore %1.",
                          QString::fromStdString(rageark::backupPath(filename().toStdString()))));
    }
    return true;
}

bool RageArkPlugin::testArchive()
{
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    quint64 done = 0;
    for (const auto &l : m_listed) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        if (!l.isDirectory) {
            try {
                if (l.isVirtual()) {
                    readListed(l);
                } else {
                    // decrypt + inflate everything, resources included
                    m_package->extract(m_package->items()[size_t(l.item)], rageark::ResourceExtract::Payload);
                }
            } catch (const std::exception &e) {
                Q_EMIT error(i18nc("error message", "Testing failed for %1: %2", l.path, QString::fromUtf8(e.what())));
                return false;
            }
        }
        Q_EMIT progress(double(++done) / double(m_listed.size() + 1));
    }
    Q_EMIT testSuccess();
    return true;
}

bool RageArkPlugin::extractFiles(const QList<Kerfuffle::Archive::Entry *> &files, const QString &destinationDirectory, const Kerfuffle::ExtractionOptions &options)
{
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    const bool preservePaths = options.preservePaths();
    const bool dragAndDrop = options.isDragAndDropEnabled();

    // (listed index, root node to strip)
    std::vector<std::pair<int, QString>> todo;
    if (files.isEmpty()) {
        for (size_t i = 0; i < m_listed.size(); ++i) {
            todo.emplace_back(int(i), QString());
        }
    } else {
        for (const auto *f : files) {
            const auto it = m_listedIndex.constFind(f->fullPath(Kerfuffle::NoTrailingSlash));
            if (it == m_listedIndex.constEnd()) {
                Q_EMIT error(i18nc("error message", "Entry not found in archive: %1", f->fullPath(Kerfuffle::NoTrailingSlash)));
                return false;
            }
            todo.emplace_back(it.value(), dragAndDrop ? f->rootNode : QString());
        }
    }

    quint64 done = 0;
    for (const auto &[index, rootNode] : todo) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        const Listed &l = m_listed[size_t(index)];
        QString rel = l.path;
        if (!rootNode.isEmpty() && rel.startsWith(rootNode)) {
            rel.remove(0, rootNode.size());
            while (rel.startsWith(QLatin1Char('/'))) {
                rel.remove(0, 1);
            }
        }
        if (!preservePaths) {
            rel = QFileInfo(rel).fileName();
        }
        const QString outPath = destinationDirectory + QLatin1Char('/') + rel;
        if (l.isDirectory) {
            if (preservePaths) {
                QDir().mkpath(outPath);
            }
        } else {
            QDir().mkpath(QFileInfo(outPath).absolutePath());
            try {
                rageark::writeWholeFile(outPath.toStdString(), readListed(l));
            } catch (const std::exception &e) {
                Q_EMIT error(i18nc("error message", "Extraction of %1 failed: %2", l.path, QString::fromUtf8(e.what())));
                return false;
            }
        }
        Q_EMIT progress(double(++done) / double(todo.size() + 1));
    }
    return true;
}

static rageark::BackupMode backupMode()
{
    const KConfigGroup group = KSharedConfig::openConfig(QStringLiteral("ragearkrc"))->group(QStringLiteral("Backup"));
    const QString mode = group.readEntry("mode", QStringLiteral("on")).toLower();
    if (mode == QLatin1String("off")) {
        return rageark::BackupMode::Off;
    }
    if (mode == QLatin1String("reflink-only")) {
        return rageark::BackupMode::ReflinkOnly;
    }
    return rageark::BackupMode::On;
}

std::string RageArkPlugin::editablePath(const QString &listedPath, QString *errorOut) const
{
    QString p = listedPath;
    while (p.endsWith(QLatin1Char('/'))) {
        p.chop(1);
    }
    const auto it = m_listedIndex.constFind(p);
    if (it != m_listedIndex.constEnd() && m_listed[size_t(it.value())].ytdTexture >= 0) {
        if (errorOut) {
            *errorOut = i18nc("error message",
                              "%1 is a texture decoded from its .ytd file and cannot be changed here. Replace the whole .ytd file "
                              "(set decode=false under [Ytd] in ~/.config/ragearkrc to show raw .ytd files).",
                              p);
        }
        return {};
    }
    if (it != m_listedIndex.constEnd() && m_listed[size_t(it.value())].awcStream >= 0) {
        if (errorOut) {
            *errorOut = i18nc("error message",
                              "%1 is a decoded audio stream and cannot be changed. Edit the .awc file itself "
                              "(set decode=false under [Awc] in ~/.config/ragearkrc to show raw .awc files).",
                              p);
        }
        return {};
    }
    return p.toStdString();
}

bool RageArkPlugin::editArchive(const std::function<void(rageark::ArchiveEditor &)> &ops)
{
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    // NG archives are re-encrypted on write (no ASI needed): make sure the encrypt tables exist
    bool needsNg = false;
    for (const auto &a : m_package->archives()) {
        needsNg = needsNg || a.encryption == rageark::Encryption::Ng;
    }
    auto infoFn = [this](const std::string &s) {
        Q_EMIT info(QString::fromStdString(s));
    };
    if (needsNg && !m_crypto->canEncryptNg()) {
        Q_EMIT info(i18nc("info", "Generating NG encryption tables (one-time, may take a minute)..."));
        try {
            auto keys = rageark::KeyStore::withEncryptTables(std::shared_ptr<const rageark::Keys>(m_crypto, &m_crypto->keys()), infoFn);
            m_crypto = std::make_shared<rageark::KeyCrypto>(keys);
        } catch (const std::exception &e) {
            Q_EMIT error(i18nc("error message", "Could not generate NG encryption tables: %1", QString::fromUtf8(e.what())));
            return false;
        }
    }

    QSet<QString> before;
    for (const auto &l : m_listed) {
        before.insert(l.path);
    }

    QString failure;
    try {
        rageark::EditOptions options;
        options.backup = backupMode();
        options.info = infoFn;
        rageark::ArchiveEditor editor(filename().toStdString(), m_crypto.get(), options);
        try {
            ops(editor);
        } catch (const std::exception &e) {
            failure = QString::fromUtf8(e.what());
        }
        editor.commit(); // keep everything that succeeded consistent on disk
    } catch (const std::exception &e) {
        failure = failure.isEmpty() ? QString::fromUtf8(e.what()) : failure + QLatin1String("; ") + QString::fromUtf8(e.what());
    }

    // reload and tell Ark's model what changed
    m_package.reset();
    m_ytd.reset();
    m_ytdItem = -1;
    m_listed.clear();
    m_listedIndex.clear();
    if (openPackage()) {
        buildListing();
        QSet<QString> after;
        for (const auto &l : m_listed) {
            after.insert(l.path);
            if (!before.contains(l.path)) {
                auto *e = new Kerfuffle::Archive::Entry();
                e->setProperty("fullPath", l.isDirectory ? l.path + QLatin1Char('/') : l.path);
                e->setProperty("isDirectory", l.isDirectory);
                if (!l.isDirectory) {
                    e->setProperty("size", qulonglong(l.size));
                    e->setProperty("compressedSize", qulonglong(l.compressedSize));
                    e->compressedSizeIsSet = true;
                }
                Q_EMIT entry(e);
            }
        }
        for (const auto &p : std::as_const(before)) {
            if (!after.contains(p)) {
                Q_EMIT entryRemoved(p);
            }
        }
    }
    if (!failure.isEmpty()) {
        Q_EMIT error(i18nc("error message", "Editing the RPF archive failed: %1", failure));
        return false;
    }
    return true;
}

bool RageArkPlugin::addFiles(const QList<Kerfuffle::Archive::Entry *> &files, const Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options, uint numberOfEntriesToAdd)
{
    Q_UNUSED(options)
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    QString prefix;
    if (destination) {
        const QString destPath = destination->fullPath(Kerfuffle::NoTrailingSlash);
        QString err;
        const std::string dest = editablePath(destPath, &err);
        if (!err.isEmpty()) {
            Q_EMIT error(err);
            return false;
        }
        if (m_listedIndex.contains(destPath)) {
            const auto &l = m_listed[size_t(m_listedIndex.value(destPath))];
            if (l.item >= 0 && !l.isVirtual() && l.isDirectory && !m_package->items()[size_t(l.item)].isDirectory) {
                // a decoded file shown as a folder
                if (m_package->entry(m_package->items()[size_t(l.item)]).type == rageark::EntryType::Resource) {
                    return replaceTextures(l, files);
                }
                Q_EMIT error(i18nc("error message", "Files cannot be added into a decoded .awc folder."));
                return false;
            }
        }
        prefix = QString::fromStdString(dest) + QLatin1Char('/');
    }
    const double total = numberOfEntriesToAdd ? double(numberOfEntriesToAdd) : double(files.size());
    return editArchive([&](rageark::ArchiveEditor &ed) {
        quint64 done = 0;
        auto addOne = [&](const QString &rel) {
            const QFileInfo fi(rel);
            QString inArchive = rel;
            while (inArchive.startsWith(QLatin1String("./"))) {
                inArchive.remove(0, 2);
            }
            while (inArchive.endsWith(QLatin1Char('/'))) {
                inArchive.chop(1);
            }
            inArchive = prefix + inArchive;
            if (fi.isDir()) {
                ed.addDirectory(inArchive.toStdString());
            } else {
                if (fi.size() > 0x3FFFFFFF) { // CodeWalker's import limit (ExploreForm.cs:3088)
                    throw rageark::Error(rel.toStdString() + ": files larger than 1 GiB cannot be imported");
                }
                ed.addFile(inArchive.toStdString(), rageark::readWholeFile(fi.filePath().toStdString()));
            }
            Q_EMIT progress(double(++done) / (total + 1));
        };
        for (const auto *f : files) {
            if (QThread::currentThread()->isInterruptionRequested()) {
                break;
            }
            const QString rel = f->fullPath();
            addOne(rel);
            if (QFileInfo(rel).isDir()) {
                QDirIterator it(rel, QDir::AllEntries | QDir::Readable | QDir::Hidden | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
                while (it.hasNext() && !QThread::currentThread()->isInterruptionRequested()) {
                    addOne(it.next());
                }
            }
        }
    });
}

bool RageArkPlugin::replaceTextures(const Listed &ytdFolder, const QList<Kerfuffle::Archive::Entry *> &files)
{
    const rageark::Item &item = m_package->items()[size_t(ytdFolder.item)];
    const rageark::Entry &re = m_package->entry(item);
    std::unique_ptr<rageark::YtdFile> ytd;
    try {
        ytd = std::make_unique<rageark::YtdFile>(m_package->extract(item, rageark::ResourceExtract::Payload), re.systemFlags, re.graphicsFlags);
    } catch (const std::exception &e) {
        Q_EMIT error(i18nc("error message", "%1 cannot be read: %2", ytdFolder.path, QString::fromUtf8(e.what())));
        return false;
    }
    for (const auto *f : files) {
        const QFileInfo fi(f->fullPath());
        if (fi.isDir()) {
            Q_EMIT error(i18nc("error message", "Folders cannot be added into a .ytd texture dictionary."));
            return false;
        }
        int index = -1;
        const auto &textures = ytd->textures();
        for (size_t t = 0; t < textures.size(); ++t) {
            if (QString::fromStdString(textures[t].fileName).compare(fi.fileName(), Qt::CaseInsensitive) == 0) {
                index = int(t);
            }
        }
        if (index < 0) {
            Q_EMIT error(i18nc("error message",
                               "%1 has no texture %2. Textures can only be replaced: add a DDS file named like an existing texture, "
                               "with the same format, size and mip levels.",
                               ytdFolder.path, fi.fileName()));
            return false;
        }
        try {
            ytd->replaceTexture(size_t(index), rageark::readWholeFile(fi.filePath().toStdString()));
        } catch (const std::exception &e) {
            Q_EMIT error(i18nc("error message", "Cannot replace texture %1: %2", fi.fileName(), QString::fromUtf8(e.what())));
            return false;
        }
    }
    const rageark::Bytes rsc7 = ytd->rsc7();
    const std::string path = item.path;
    return editArchive([&](rageark::ArchiveEditor &ed) {
        ed.addFile(path, rsc7);
    });
}

bool RageArkPlugin::moveFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options)
{
    Q_UNUSED(options)
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    const auto tops = entriesWithoutChildren(files);
    QStringList paths = entryFullPaths(files);
    paths.sort();
    const QStringList dests = entryPathsFromDestination(paths, destination, tops.count());
    std::vector<std::pair<std::string, std::string>> moves;
    for (const auto *t : tops) {
        const int i = paths.indexOf(t->fullPath());
        QString err;
        const std::string from = editablePath(t->fullPath(), &err);
        const std::string to = i >= 0 ? editablePath(dests.at(i), &err) : std::string();
        if (!err.isEmpty() || i < 0) {
            Q_EMIT error(err.isEmpty() ? i18nc("error message", "Cannot move %1", t->fullPath()) : err);
            return false;
        }
        moves.emplace_back(from, to);
    }
    return editArchive([&](rageark::ArchiveEditor &ed) {
        size_t done = 0;
        for (const auto &[from, to] : moves) {
            ed.move(from, to);
            Q_EMIT progress(double(++done) / double(moves.size() + 1));
        }
    });
}

bool RageArkPlugin::copyFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options)
{
    Q_UNUSED(options)
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    const auto tops = entriesWithoutChildren(files);
    QStringList paths = entryFullPaths(files);
    const QStringList dests = entryPathsFromDestination(paths, destination, 0);
    std::vector<std::pair<std::string, std::string>> copies;
    for (const auto *t : tops) {
        const int i = paths.indexOf(t->fullPath());
        QString err;
        const std::string from = editablePath(t->fullPath(), &err);
        const std::string to = i >= 0 ? editablePath(dests.at(i), &err) : std::string();
        if (!err.isEmpty() || i < 0) {
            Q_EMIT error(err.isEmpty() ? i18nc("error message", "Cannot copy %1", t->fullPath()) : err);
            return false;
        }
        copies.emplace_back(from, to);
    }
    return editArchive([&](rageark::ArchiveEditor &ed) {
        size_t done = 0;
        for (const auto &[from, to] : copies) {
            ed.copy(from, to);
            Q_EMIT progress(double(++done) / double(copies.size() + 1));
        }
    });
}

bool RageArkPlugin::deleteFiles(const QList<Kerfuffle::Archive::Entry *> &files)
{
    if (!openPackage()) {
        return false;
    }
    if (m_listed.empty()) {
        buildListing();
    }
    std::vector<std::string> doomed;
    for (const auto *t : entriesWithoutChildren(files)) {
        QString err;
        const std::string p = editablePath(t->fullPath(), &err);
        if (!err.isEmpty()) {
            Q_EMIT error(err);
            return false;
        }
        doomed.push_back(p);
    }
    return editArchive([&](rageark::ArchiveEditor &ed) {
        size_t done = 0;
        for (const auto &p : doomed) {
            ed.remove(p);
            Q_EMIT progress(double(++done) / double(doomed.size() + 1));
        }
    });
}

bool RageArkPlugin::addComment(const QString &comment)
{
    Q_UNUSED(comment)
    Q_EMIT error(i18nc("error message", "RPF archives do not support comments."));
    return false;
}

#include "ragearkplugin.moc"
