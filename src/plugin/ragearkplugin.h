// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "archiveinterface.h"

#include <memory>

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
    bool openPackage(QString *errorOut = nullptr);
    bool ensureKeys();
    bool writeSupported(QString *errorOut = nullptr) const;

    std::shared_ptr<rageark::KeyCrypto> m_crypto;
    std::shared_ptr<rageark::Package> m_package;
};
