// SPDX-License-Identifier: GPL-2.0-or-later
#include "deflate.h"

#include <zlib.h>

namespace rageark
{

std::optional<Bytes> tryInflateRaw(const uint8_t *data, size_t len, size_t sizeHint)
{
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK) {
        return std::nullopt;
    }
    Bytes out(sizeHint > 0 ? sizeHint : std::max<size_t>(len * 4, 4096));
    zs.next_in = const_cast<Bytef *>(data);
    zs.avail_in = uInt(len);
    size_t produced = 0;
    int ret = Z_OK;
    while (true) {
        if (produced == out.size()) {
            out.resize(out.size() * 2);
        }
        zs.next_out = out.data() + produced;
        zs.avail_out = uInt(out.size() - produced);
        ret = inflate(&zs, Z_NO_FLUSH);
        produced = out.size() - zs.avail_out;
        if (ret == Z_STREAM_END) {
            break;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            inflateEnd(&zs);
            return std::nullopt;
        }
        if (ret == Z_BUF_ERROR && zs.avail_in == 0) {
            // input exhausted without stream end: .NET tolerates truncated
            // trailing data, so accept what was produced
            break;
        }
    }
    inflateEnd(&zs);
    out.resize(produced);
    return out;
}

Bytes inflateRaw(const uint8_t *data, size_t len, size_t sizeHint)
{
    auto r = tryInflateRaw(data, len, sizeHint);
    if (!r) {
        throw Error("inflate failed (corrupt data or wrong key)");
    }
    return std::move(*r);
}

Bytes deflateRaw(const uint8_t *data, size_t len, int level)
{
    z_stream zs{};
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw Error("deflateInit failed");
    }
    Bytes out(deflateBound(&zs, uLong(len)));
    zs.next_in = const_cast<Bytef *>(data);
    zs.avail_in = uInt(len);
    zs.next_out = out.data();
    zs.avail_out = uInt(out.size());
    const int ret = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    if (ret != Z_STREAM_END) {
        throw Error("deflate failed");
    }
    out.resize(zs.total_out);
    return out;
}

} // namespace rageark
