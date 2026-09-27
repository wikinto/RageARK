// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "archiveinterface.h"
#include "bytes.h"

#include <QHash>
#include <QString>

#include <memory>
#include <vector>

namespace rageark
{
class KeyCrypto;
class Package;
}

class RageArkPlugin : public Kerfuffle::ReadWriteArchiveInterface
{
    Q_OBJECT
public:
    explicit RageArkPlugin(QObject *parent, const QVariantList &args);

    bool list() override;
    bool testArchive() override;
    bool extractFiles(const QList<Kerfuffle::Archive::Entry *> &files, const QString &destinationDirectory, const Kerfuffle::ExtractionOptions &options) override;

    bool addFiles(const QList<Kerfuffle::Archive::Entry *> &files, const Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options, uint numberOfEntriesToAdd = 0) override;
    bool moveFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options) override;
    bool copyFiles(const QList<Kerfuffle::Archive::Entry *> &files, Kerfuffle::Archive::Entry *destination, const Kerfuffle::CompressionOptions &options) override;
    bool deleteFiles(const QList<Kerfuffle::Archive::Entry *> &files) override;
    bool addComment(const QString &comment) override;

private:
    // What list() showed to Ark: a package item, or one decoded AWC stream (virtual file).
    struct Listed {
        QString path; // no trailing slash
        bool isDirectory = false;
        int item = -1; // index into Package::items()
        int awcStream = -1; // >= 0: virtual AWC stream export of item
        quint64 size = 0;
        quint64 compressedSize = 0;
    };

    bool openPackage(QString *errorOut = nullptr);
    void buildListing();
    rageark::Bytes readListed(const Listed &l) const;
    bool ensureKeys();
    bool writeSupported(QString *errorOut = nullptr) const;

    std::shared_ptr<rageark::KeyCrypto> m_crypto;
    std::shared_ptr<rageark::Package> m_package;
    std::vector<Listed> m_listed;
    QHash<QString, int> m_listedIndex; // path -> index in m_listed
};
