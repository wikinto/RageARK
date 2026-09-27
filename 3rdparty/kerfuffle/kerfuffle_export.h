/*
    Minimal stand-in for the kerfuffle_export.h that Ark generates with
    generate_export_header(kerfuffle). RageARK only *imports* these symbols
    from the installed libkerfuffle.so, so default visibility is sufficient.

    SPDX-License-Identifier: BSD-2-Clause
*/

#ifndef KERFUFFLE_EXPORT_H
#define KERFUFFLE_EXPORT_H

#define KERFUFFLE_EXPORT __attribute__((visibility("default")))
#define KERFUFFLE_NO_EXPORT __attribute__((visibility("hidden")))

#endif
