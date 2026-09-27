// SPDX-License-Identifier: GPL-2.0-or-later
#include "ragearkplugin.h"

#include "archiveentry.h"
#include "exepickerquery.h"
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

bool RageArkPlugin::list()
{
    if (!openPackage()) {
        return false;
    }
    const auto &items = m_package->items();
    quint64 done = 0;
    for (const auto &item : items) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        auto *e = new Kerfuffle::Archive::Entry(); // ownership passes to Ark's model
        if (item.isDirectory) {
            e->setProperty("fullPath", QString::fromStdString(item.path) + QLatin1Char('/'));
            e->setProperty("isDirectory", true);
        } else {
            e->setProperty("fullPath", QString::fromStdString(item.path));
            e->setProperty("isDirectory", false);
            const rageark::Entry &re = m_package->entry(item);
            e->setProperty("size", qulonglong(re.logicalSize()));
            e->setProperty("compressedSize", qulonglong(re.storedSize()));
        }
        Q_EMIT entry(e);
        Q_EMIT progress(double(++done) / double(items.size() + 1));
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
    quint64 done = 0;
    const auto &items = m_package->items();
    for (const auto &item : items) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        if (!item.isDirectory) {
            try {
                m_package->extract(item, rageark::ResourceExtract::Payload);
            } catch (const std::exception &e) {
                Q_EMIT error(i18nc("error message", "Testing failed for %1: %2", QString::fromStdString(item.path), QString::fromUtf8(e.what())));
                return false;
            }
        }
        Q_EMIT progress(double(++done) / double(items.size() + 1));
    }
    Q_EMIT testSuccess();
    return true;
}

bool RageArkPlugin::extractFiles(const QList<Kerfuffle::Archive::Entry *> &files, const QString &destinationDirectory, const Kerfuffle::ExtractionOptions &options)
{
    if (!openPackage()) {
        return false;
    }
    const bool extractAll = files.isEmpty();
    const bool preservePaths = options.preservePaths();
    QStringList wanted;
    for (const auto *f : files) {
        wanted << f->fullPath(Kerfuffle::NoTrailingSlash);
    }
    // when drag&dropping, the dragged folder becomes the root and is stripped
    std::vector<QString> rootNodes;
    if (options.isDragAndDropEnabled()) {
        for (const auto *f : files) {
            if (!f->rootNode.isEmpty()) {
                rootNodes.push_back(f->rootNode);
            }
        }
    }

    quint64 done = 0;
    int extracted = 0;
    for (const auto &item : m_package->items()) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            return false;
        }
        if (item.isDirectory) {
            continue;
        }
        const QString path = QString::fromStdString(item.path);
        QString rel = path;
        if (!extractAll) {
            const int idx = wanted.indexOf(path);
            if (idx < 0) {
                continue;
            }
            if (options.isDragAndDropEnabled() && !rootNodes.empty() && !rootNodes.at(idx).isEmpty()) {
                rel.remove(rel.indexOf(rootNodes.at(idx)), rootNodes.at(idx).size());
            }
        }
        QString target = preservePaths ? rel : QFileInfo(rel).fileName();
        const QString outPath = destinationDirectory + QLatin1Char('/') + target;
        if (!preservePaths) {
            QDir().mkpath(destinationDirectory);
        } else {
            QDir().mkpath(QFileInfo(outPath).absolutePath());
        }
        try {
            const auto mode = rageark::ResourceExtract::Rsc7; // re-importable extract
            rageark::writeWholeFile(outPath.toStdString(), m_package->extract(item, mode));
        } catch (const std::exception &e) {
            Q_EMIT error(i18nc("error message", "Extraction of %1 failed: %2", path, QString::fromUtf8(e.what())));
            return false;
        }
        ++extracted;
        Q_EMIT progress(double(++done) / double(m_package->items().size() + 1));
    }
    Q_UNUSED(extracted)
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
