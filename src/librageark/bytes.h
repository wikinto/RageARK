// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace rageark
{

using Bytes = std::vector<uint8_t>;

class Error : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

inline uint32_t readU32(const uint8_t *p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline uint64_t readU64(const uint8_t *p)
{
    return uint64_t(readU32(p)) | (uint64_t(readU32(p + 4)) << 32);
}

inline void writeU32(uint8_t *p, uint32_t v)
{
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

inline void appendU32(Bytes &b, uint32_t v)
{
    const size_t o = b.size();
    b.resize(o + 4);
    writeU32(b.data() + o, v);
}

inline std::string toLower(std::string s)
{
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = char(c - 'A' + 'a');
        }
    }
    return s;
}

inline bool endsWith(const std::string &s, const std::string &suffix)
{
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Random-access reader over a file descriptor (pread based, thread-safe).
class FileReader
{
public:
    explicit FileReader(const std::string &path);
    ~FileReader();
    FileReader(const FileReader &) = delete;
    FileReader &operator=(const FileReader &) = delete;

    uint64_t size() const
    {
        return m_size;
    }
    void read(uint64_t offset, void *dst, size_t len) const;
    Bytes read(uint64_t offset, size_t len) const;

private:
    int m_fd = -1;
    uint64_t m_size = 0;
};

Bytes readWholeFile(const std::string &path);
void writeWholeFile(const std::string &path, const Bytes &data);

} // namespace rageark
