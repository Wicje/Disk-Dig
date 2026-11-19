#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace dd {

enum class Chance { High, Medium, Low };
enum class Status { Existing, Deleted, Carved };
enum class FsKind { Ext, Fat, ExFat, Ntfs, Unknown, WholeDisk };
enum class Category { All, Pictures, Videos, Audio, Documents, Archives, Other };

struct ByteRange {
    uint64_t offset = 0;  // absolute offset in source bytes
    uint64_t length = 0;
};

struct FileRecord {
    uint64_t id = 0;
    std::string name;
    std::string path;      // logical path inside the filesystem, may be empty
    uint64_t size = 0;
    Status status = Status::Deleted;
    Chance chance = Chance::Low;
    FsKind fs = FsKind::Unknown;
    std::string type;      // inferred extension / description
    std::vector<ByteRange> ranges;  // segments to concatenate for recovery
    std::string why;       // human-readable explanation of the chance estimate
    uint64_t modified = 0; // unix seconds, 0 if unknown
    uint64_t deleted = 0;
    uint64_t inode = 0;    // inode / MFT record / dir entry offset, diagnostic
};

struct DeviceInfo {
    std::string path;      // /dev/sdX or image file
    std::string model;
    uint64_t bytes = 0;
    bool removable = false;
    bool mounted = false;
    std::string mounts;
    bool isImage = false;
    bool readable = false;
    std::string error;
};

struct Partition {
    uint64_t start = 0;    // absolute byte offset in the source
    uint64_t length = 0;
    uint32_t number = 0;
    uint8_t type = 0;      // MBR partition type
    FsKind fs = FsKind::Unknown;
    std::string fsLabel;
    std::string description;
};

struct ScanOptions {
    bool includeExisting = true;
    bool includeDeleted = true;
    bool carveFreeSpace = true;
    uint64_t maxCarveBytes = 0; // 0 = no limit
    uint32_t maxCarveFiles = 5000;
};

struct ScanStats {
    uint64_t scanned = 0;
    uint64_t total = 0;
    uint32_t extFound = 0;
    uint32_t fatFound = 0;
    uint32_t exfatFound = 0;
    uint32_t ntfsFound = 0;
    uint32_t carvedFound = 0;
    uint32_t existingFound = 0;
};

using ProgressFn = std::function<void(int percent, const std::string &phase)>;
using ResultFn = std::function<void(const FileRecord &record)>;

const char *chanceName(Chance c);
const char *statusName(Status s);
const char *fsName(FsKind f);
const char *categoryName(Category c);
Category categoryFromName(const std::string &name);
Category categoryFromType(const std::string &type);
std::string formatBytes(uint64_t n);
std::string typeFromName(const std::string &name);

} // namespace dd
