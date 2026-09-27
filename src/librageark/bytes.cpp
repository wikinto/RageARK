// SPDX-License-Identifier: GPL-2.0-or-later
#include "bytes.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rageark
{

FileReader::FileReader(const std::string &path)
{
    m_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (m_fd < 0) {
        throw Error("cannot open " + path + ": " + std::strerror(errno));
    }
    struct stat st {};
    if (::fstat(m_fd, &st) != 0) {
        ::close(m_fd);
        throw Error("cannot stat " + path);
    }
    m_size = uint64_t(st.st_size);
}

FileReader::~FileReader()
{
    if (m_fd >= 0) {
        ::close(m_fd);
    }
}

void FileReader::read(uint64_t offset, void *dst, size_t len) const
{
    if (offset > m_size || len > m_size - offset) {
        throw Error("read past end of file");
    }
    auto *out = static_cast<uint8_t *>(dst);
    while (len > 0) {
        const ssize_t n = ::pread(m_fd, out, len, off_t(offset));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error(std::string("read error: ") + std::strerror(errno));
        }
        if (n == 0) {
            throw Error("unexpected end of file");
        }
        out += n;
        offset += uint64_t(n);
        len -= size_t(n);
    }
}

Bytes FileReader::read(uint64_t offset, size_t len) const
{
    Bytes b(len);
    if (len > 0) {
        read(offset, b.data(), len);
    }
    return b;
}

Bytes readWholeFile(const std::string &path)
{
    FileReader r(path);
    return r.read(0, size_t(r.size()));
}

void writeWholeFile(const std::string &path, const Bytes &data)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        throw Error("cannot create " + path + ": " + std::strerror(errno));
    }
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            throw Error("write error on " + path);
        }
        off += size_t(n);
    }
    ::close(fd);
}

} // namespace rageark
