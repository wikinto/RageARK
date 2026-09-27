// SPDX-License-Identifier: MIT
#pragma once

#include "bytes.h"

#include <optional>

namespace rageark
{

// Raw DEFLATE (no zlib/gzip header), matching .NET DeflateStream.
Bytes inflateRaw(const uint8_t *data, size_t len, size_t sizeHint = 0);
std::optional<Bytes> tryInflateRaw(const uint8_t *data, size_t len, size_t sizeHint = 0);
// Inflates only until maxOut bytes are produced (or the input ends); corrupt data throws.
Bytes inflateRawPrefix(const uint8_t *data, size_t len, size_t maxOut);
Bytes deflateRaw(const uint8_t *data, size_t len, int level = 9);

} // namespace rageark
