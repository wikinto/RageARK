// SPDX-License-Identifier: GPL-2.0-or-later
#include "exepickerquery.h"

#include <KLocalizedString>
#include <QApplication>
#include <QCursor>
#include <QFileDialog>
#include <QMessageBox>

ExePickerQuery::ExePickerQuery(const QString &archiveName, const QString &reason)
{
    m_data[QStringLiteral("archive")] = archiveName;
    m_data[QStringLiteral("reason")] = reason;
}

void ExePickerQuery::execute()
{
    QApplication::setOverrideCursor(QCursor(Qt::ArrowCursor));
    QWidget *parent = QApplication::activeWindow();

    QString text = xi18nc("@info",
                          "<para><filename>%1</filename> is encrypted.</para>"
                          "<para>RageARK needs the keys from your own copy of GTA V. "
                          "Please select <filename>GTA5.exe</filename> or <filename>GTA5_Enhanced.exe</filename>. "
                          "This is only needed once; the derived keys are cached.</para>",
                          m_data.value(QStringLiteral("archive")).toString());
    const QString reason = m_data.value(QStringLiteral("reason")).toString();
    if (!reason.isEmpty()) {
        text += xi18nc("@info", "<para>Previous attempt failed: %1</para>", reason);
    }

    QString path;
    if (QMessageBox::information(parent, i18nc("@title:window", "GTA V Keys Required"), text, QMessageBox::Open | QMessageBox::Cancel, QMessageBox::Open)
        == QMessageBox::Open) {
        path = QFileDialog::getOpenFileName(parent,
                                            i18nc("@title:window", "Select GTA V Executable"),
                                            QString(),
                                            i18nc("file filter", "GTA V executable (GTA5.exe GTA5_Enhanced.exe gta5.exe gta5_enhanced.exe);;All files (*)"));
    }
    QApplication::restoreOverrideCursor();
    setResponse(path);
}

QString ExePickerQuery::exePath() const
{
    return response().toString();
}

bool ExePickerQuery::cancelled() const
{
    return response().toString().isEmpty();
}
