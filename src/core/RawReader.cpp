#include "RawReader.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>

namespace dd {

RawReader::~RawReader() { close(); }

bool RawReader::open(const std::string &path, std::string *error) {
    close();
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        if (error) *error = std::string("Cannot open '") + path + "': " + strerror(errno);
        return false;
    }
    struct stat st{};
    if (fstat(fd_, &st) != 0) {
        if (error) *error = std::string("Cannot stat '") + path + "': " + strerror(errno);
        close();
        return false;
    }
    isBlock_ = S_ISBLK(st.st_mode);
    if (isBlock_) {
        uint64_t bytes = 0;
        if (ioctl(fd_, BLKGETSIZE64, &bytes) == 0) size_ = bytes;
        else size_ = static_cast<uint64_t>(st.st_size);
    } else if (S_ISREG(st.st_mode)) {
        size_ = static_cast<uint64_t>(st.st_size);
    } else {
        if (error) *error = "Not a regular file or block device";
        close();
        return false;
    }
    path_ = path;
    return true;
}

void RawReader::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    size_ = 0;
    path_.clear();
    isBlock_ = false;
}

int64_t RawReader::readAt(uint64_t offset, void *buffer, size_t length) const {
    if (fd_ < 0 || length == 0) return -1;
    if (offset >= size_) return 0;
    if (length > size_ - offset) length = static_cast<size_t>(size_ - offset);
    uint8_t *out = static_cast<uint8_t *>(buffer);
    size_t done = 0;
    while (done < length) {
        ssize_t n = ::pread(fd_, out + done, length - done, static_cast<off_t>(offset + done));
        if (n > 0) { done += static_cast<size_t>(n); continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return done ? static_cast<int64_t>(done) : -1;
    }
    return static_cast<int64_t>(done);
}

bool RawReader::readExact(uint64_t offset, void *buffer, size_t length) const {
    return readAt(offset, buffer, length) == static_cast<int64_t>(length);
}

uint8_t RawReader::u8(uint64_t off, bool *ok) const {
    uint8_t v = 0;
    bool r = read(off, &v);
    if (ok) *ok = r;
    return v;
}
uint16_t RawReader::u16(uint64_t off, bool *ok) const {
    uint8_t b[2]{};
    bool r = readExact(off, b, 2);
    if (ok) *ok = r;
    return static_cast<uint16_t>(b[0] | (b[1] << 8));
}
uint32_t RawReader::u32(uint64_t off, bool *ok) const {
    uint8_t b[4]{};
    bool r = readExact(off, b, 4);
    if (ok) *ok = r;
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}
uint64_t RawReader::u64(uint64_t off, bool *ok) const {
    uint64_t lo = u32(off, ok);
    uint64_t hi = u32(off + 4, ok);
    return lo | (hi << 32);
}

} // namespace dd
