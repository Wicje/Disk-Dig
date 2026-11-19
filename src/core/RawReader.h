#pragma once
#include <cstdint>
#include <string>

namespace dd {

// Read-only access to a block device or a raw image file.
class RawReader {
public:
    ~RawReader();
    bool open(const std::string &path, std::string *error = nullptr);
    void close();
    bool isOpen() const { return fd_ >= 0; }
    uint64_t size() const { return size_; }
    const std::string &path() const { return path_; }
    bool isBlockDevice() const { return isBlock_; }

    // Returns number of bytes read, or -1 on error. Safe for devices and files.
    int64_t readAt(uint64_t offset, void *buffer, size_t length) const;
    bool readExact(uint64_t offset, void *buffer, size_t length) const;

    template <typename T> bool read(uint64_t offset, T *out) const {
        return readExact(offset, out, sizeof(T));
    }
    uint8_t u8(uint64_t off, bool *ok = nullptr) const;
    uint16_t u16(uint64_t off, bool *ok = nullptr) const;
    uint32_t u32(uint64_t off, bool *ok = nullptr) const;
    uint64_t u64(uint64_t off, bool *ok = nullptr) const;

private:
    int fd_ = -1;
    uint64_t size_ = 0;
    bool isBlock_ = false;
    std::string path_;
};

} // namespace dd
