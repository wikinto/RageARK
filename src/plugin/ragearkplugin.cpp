// SPDX-License-Identifier: GPL-2.0-or-later
#include "ragearkplugin.h"

#include "archiveentry.h"
#include "awc.h"
#include "exepickerquery.h"
#include "keys.h"
#include "keystore.h"
#include "rpf.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KPluginFactory>
#include <QDir>
#include <QFile>
#include <QFileInfo>
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

static bool awcDecodeEnabled()
{
    const KConfigGroup group = KSharedConfig::openConfig(QStringLiteral("ragearkrc"))->group(QStringLiteral("Awc"));
    return group.readEntry("decode", true);
}

void RageArkPlugin::buildListing()
{
    m_listed.clear();
    m_listedIndex.clear();
    const bool decodeAwc = awcDecodeEnabled();
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
            l.size = re.logicalSize();
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
        }
        Q_EMIT entry(e);
        Q_EMIT progress(double(++done) / double(m_listed.size() + 1));
    }
    for (const auto &w : m_package->warnings()) {
        Q_EMIT info(QString::fromStdString(w));
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
                if (l.awcStream >= 0) {
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

bool RageArkPlugin::writeSupported(QString *errorOut) const
{
    if (errorOut) {
        *errorOut = QStringLiteral("writing RPF archives is not implemented yet (M3)");
    }
    return false;
}

bool RageArkPlugin::addFiles(const QList<Kerfuffle::Archive::Entry *> &files, const Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options, uint numberOfEntriesToAdd)
{
    Q_UNUSED(files)
    Q_UNUSED(destination)
    Q_UNUSED(options)
    Q_UNUSED(numberOfEntriesToAdd)
    QString e;
    writeSupported(&e);
    Q_EMIT error(e);
    return false;
}

bool RageArkPlugin::moveFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options)
{
    Q_UNUSED(files)
    Q_UNUSED(destination)
    Q_UNUSED(options)
    QString e;
    writeSupported(&e);
    Q_EMIT error(e);
    return false;
}

bool RageArkPlugin::copyFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options)
{
    Q_UNUSED(files)
    Q_UNUSED(destination)
    Q_UNUSED(options)
    QString e;
    writeSupported(&e);
    Q_EMIT error(e);
    return false;
}

bool RageArkPlugin::deleteFiles(const QList<Kerfuffle::Archive::Entry *> &files)
{
    Q_UNUSED(files)
    QString e;
    writeSupported(&e);
    Q_EMIT error(e);
    return false;
}

bool RageArkPlugin::addComment(const QString &comment)
{
    Q_UNUSED(comment)
    Q_EMIT error(i18nc("error message", "RPF archives do not support comments."));
    return false;
}

#include "ragearkplugin.moc"
