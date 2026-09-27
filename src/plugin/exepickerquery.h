// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "queries.h"

// First-run prompt for GTA5.exe / GTA5_Enhanced.exe (like CodeWalker's GTA folder prompt).
// Emitted from the worker thread via userQuery(); execute() runs on the GUI thread.
// response(): selected exe path, or empty when cancelled.
class ExePickerQuery : public Kerfuffle::Query
{
public:
    explicit ExePickerQuery(const QString &archiveName, const QString &reason = {});
    void execute() override;

    QString exePath() const;
    bool cancelled() const;
};
