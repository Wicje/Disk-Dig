#include "core/FsScanner.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_set>
#include <vector>

namespace dd {
namespace {

constexpr size_t DIR_ENTRY_SIZE = 32;
constexpr uint32_t FAT_FREE = 0x00000000u;
constexpr uint32_t FAT_BAD = 0x0FFFFFF7u;
constexpr uint32_t FAT_MAX_VALID = 0x0FFFFFEFu;

struct ExfatInfo {
    uint64_t fatOffset = 0;
    uint64_t heapOffset = 0;
    uint64_t clusterBytes = 0;
    uint32_t clusterCount = 0;
    uint32_t rootCluster = 0;
    uint64_t bitmapFirstCluster = 0;
    uint64_t bitmapLength = 0;
    std::vector<uint8_t> bitmap;
    bool bitmapValid = false;
};

struct ExfatState {
    uint64_t nextId = 1;
    uint32_t entriesSeen = 0;
    uint32_t recordsEmitted = 0;
    std::unordered_set<uint32_t> visitedDirs;
};

uint16_t rd16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t rd32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t rd64(const uint8_t *p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

bool isPow2(uint64_t v) { return v && ((v & (v - 1)) == 0); }

uint64_t exfatDateTimeToUnix(uint16_t date, uint16_t time) {
    if (date == 0) return 0;
    int day = date & 0x1F;
    int month = (date >> 5) & 0x0F;
    int year = ((date >> 9) & 0x7F) + 1980;
    int sec2 = time & 0x1F;
    int min = (time >> 5) & 0x3F;
    int hour = (time >> 11) & 0x1F;
    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec2 * 2;
    tm.tm_isdst = -1;
#if defined(__linux__)
    time_t t = timegm(&tm);
#else
    time_t t = std::mktime(&tm);
#endif
    return t == static_cast<time_t>(-1) ? 0 : static_cast<uint64_t>(t);
}

void appendUtf8(std::string &out, uint16_t ch) {
    if (ch == 0) return;
    if (ch < 0x80) {
        out.push_back(static_cast<char>(ch));
    } else if (ch < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (ch >> 6)));
        out.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xE0 | (ch >> 12)));
        out.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
    }
}

bool validCluster(const ScanContext &ctx, const ExfatInfo &fi, uint32_t cluster) {
    if (cluster < 2 || cluster > fi.clusterCount + 1) return false;
    uint64_t end = fi.heapOffset + static_cast<uint64_t>(cluster - 1) * fi.clusterBytes;
    return end <= ctx.partitionStart + ctx.partitionLength;
}

uint64_t clusterOffset(const ExfatInfo &fi, uint32_t cluster) {
    return fi.heapOffset + static_cast<uint64_t>(cluster - 2) * fi.clusterBytes;
}

uint32_t readFatEntry(const ScanContext &ctx, const ExfatInfo &fi, uint32_t cluster) {
    bool ok = false;
    uint32_t v = ctx.reader.u32(fi.fatOffset + static_cast<uint64_t>(cluster) * 4, &ok);
    return ok ? (v & 0x0FFFFFFFu) : FAT_BAD;
}

bool chainEnd(uint32_t entry) {
    return entry == FAT_FREE || entry == FAT_BAD || entry >= 0x0FFFFFF8u;
}

// True when the exFAT allocation bitmap marks the cluster as allocated.
// Without bitmap info we assume free (don't block recovery on missing data).
bool clusterAllocated(const ExfatInfo &fi, uint32_t cluster) {
    if (cluster < 2 || cluster > fi.clusterCount + 1) return true;
    if (!fi.bitmapValid) return false;
    uint64_t i = static_cast<uint64_t>(cluster) - 2;
    if (i >= static_cast<uint64_t>(fi.bitmap.size()) * 8u) return false;
    return (fi.bitmap[i / 8] >> (i % 8)) & 1u;
}

// Loads the exFAT allocation bitmap (root directory entry type 0x81) so deleted
// entries can be checked against real cluster allocation instead of stale hints.
bool readDirectoryData(const ScanContext &ctx, const ExfatInfo &fi, uint32_t startCluster,
                       std::vector<uint8_t> &out);

bool loadBitmap(ScanContext &ctx, ExfatInfo &fi) {
    std::vector<uint8_t> data;
    if (!readDirectoryData(ctx, fi, fi.rootCluster, data)) return false;
    size_t count = data.size() / DIR_ENTRY_SIZE;
    for (size_t i = 0; i < count; ++i) {
        const uint8_t *e = data.data() + i * DIR_ENTRY_SIZE;
        if (e[0] == 0x00) break;
        if ((e[0] & 0x1F) == 0x01 && (e[0] & 0x40) == 0) {  // Allocation Bitmap, primary
            fi.bitmapFirstCluster = rd32(e + 20);
            fi.bitmapLength = rd64(e + 24);
            fi.bitmapValid = true;
            break;
        }
    }
    if (!fi.bitmapValid || fi.bitmapLength == 0) return false;

    fi.bitmap.clear();
    fi.bitmap.reserve(static_cast<size_t>(fi.bitmapLength));
    uint32_t c = static_cast<uint32_t>(fi.bitmapFirstCluster);
    std::unordered_set<uint32_t> seen;
    while (fi.bitmap.size() < fi.bitmapLength) {
        if (c < 2 || c > fi.clusterCount + 1) break;
        if (!seen.insert(c).second) break;
        uint64_t off = clusterOffset(fi, c);
        if (off + fi.clusterBytes > ctx.partitionStart + ctx.partitionLength) break;
        std::vector<uint8_t> buf(fi.clusterBytes);
        if (!ctx.reader.readExact(off, buf.data(), buf.size())) break;
        fi.bitmap.insert(fi.bitmap.end(), buf.begin(), buf.end());
        uint32_t next = readFatEntry(ctx, fi, c);
        if (chainEnd(next) || next < 2 || next > FAT_MAX_VALID) break;
        c = next;
    }
    return fi.bitmap.size() >= fi.bitmapLength;
}

// Sanity check: does the data at the start cluster look like the claimed file type?
// Prevents restoring garbage for stale deleted directory entries whose clusters
// have been reallocated or overwritten.
bool headerMatchesExt(const char *ext, const ScanContext &ctx, const ExfatInfo &fi, uint32_t cluster) {
    uint8_t hdr[16];
    uint64_t off = clusterOffset(fi, cluster);
    if (!ctx.reader.readExact(off, hdr, sizeof(hdr))) return false;
    std::string e = ext;
    for (char &c : e) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    if (e == "jpg" || e == "jpeg") return hdr[0] == 0xFF && hdr[1] == 0xD8 && hdr[2] == 0xFF;
    if (e == "png") return memcmp(hdr, "\x89PNG\r\n\x1a\n", 8) == 0;
    if (e == "mp4" || e == "mov" || e == "3gp" || e == "m4v") return memcmp(hdr + 4, "ftyp", 4) == 0;
    if (e == "mkv" || e == "webm") return hdr[0] == 0x1A && hdr[1] == 0x45 && hdr[2] == 0xDF && hdr[3] == 0xA3;
    if (e == "avi") return memcmp(hdr, "RIFF", 4) == 0 && memcmp(hdr + 8, "AVI ", 4) == 0;
    if (e == "mpg" || e == "mpeg" || e == "vob") return hdr[0] == 0 && hdr[1] == 0 && hdr[2] == 1 && hdr[3] == 0xBA;
    if (e == "ts" || e == "m2ts" || e == "mts") return hdr[0] == 0x47;
    if (e == "flv") return memcmp(hdr, "FLV\x01", 4) == 0;
    if (e == "tif" || e == "tiff") {
        return (hdr[0] == 'I' && hdr[1] == 'I' && hdr[2] == '*' && hdr[3] == 0) ||
               (hdr[0] == 'M' && hdr[1] == 'M' && hdr[2] == 0 && hdr[3] == '*');
    }
    if (e == "bmp") return hdr[0] == 'B' && hdr[1] == 'M';
    if (e == "gif") return memcmp(hdr, "GIF8", 4) == 0;
    if (e == "webp") return memcmp(hdr, "RIFF", 4) == 0 && memcmp(hdr + 8, "WEBP", 4) == 0;
    if (e == "pdf") return memcmp(hdr, "%PDF", 4) == 0;
    if (e == "zip") return memcmp(hdr, "PK\x03\x04", 4) == 0;
    return true;  // unknown extension: do not block recovery
}

std::vector<ByteRange> chainRanges(const ScanContext &ctx, const ExfatInfo &fi,
                                   uint32_t startCluster, uint64_t size, bool noFatChain) {
    std::vector<ByteRange> ranges;
    if (startCluster < 2 || size == 0 || !validCluster(ctx, fi, startCluster)) return ranges;

    uint64_t remaining = size;
    uint32_t cluster = startCluster;
    std::unordered_set<uint32_t> seen;
    uint32_t maxSteps = std::min<uint32_t>(fi.clusterCount ? fi.clusterCount : 1u, 100000u);

    for (uint32_t step = 0; step < maxSteps && remaining > 0; ++step) {
        if (!validCluster(ctx, fi, cluster)) break;
        if (!seen.insert(cluster).second) break;
        uint64_t off = clusterOffset(fi, cluster);
        uint64_t len = std::min<uint64_t>(fi.clusterBytes, remaining);
        if (!ranges.empty() && ranges.back().offset + ranges.back().length == off)
            ranges.back().length += len;
        else
            ranges.push_back(ByteRange{off, len});
        remaining -= len;
        if (remaining == 0) break;
        if (noFatChain) ++cluster;
        else {
            uint32_t next = readFatEntry(ctx, fi, cluster);
            if (chainEnd(next) || next < 2 || next > FAT_MAX_VALID) break;
            cluster = next;
        }
    }
    return ranges;
}

bool readDirectoryData(const ScanContext &ctx, const ExfatInfo &fi, uint32_t startCluster,
                       std::vector<uint8_t> &out) {
    if (!validCluster(ctx, fi, startCluster)) return false;
    uint32_t cluster = startCluster;
    std::unordered_set<uint32_t> seen;
    uint32_t maxSteps = std::min<uint32_t>(fi.clusterCount ? fi.clusterCount : 1u, 100000u);
    size_t toRead = static_cast<size_t>(std::min<uint64_t>(fi.clusterBytes, 16u * 1024u * 1024u));

    for (uint32_t step = 0; step < maxSteps; ++step) {
        if (!validCluster(ctx, fi, cluster)) break;
        if (!seen.insert(cluster).second) break;
        std::vector<uint8_t> buf(toRead);
        if (!ctx.reader.readExact(clusterOffset(fi, cluster), buf.data(), buf.size())) break;
        out.insert(out.end(), buf.begin(), buf.end());
        if (out.size() >= 64u * 1024u * 1024u) break;
        uint32_t next = readFatEntry(ctx, fi, cluster);
        if (chainEnd(next) || next < 2 || next > FAT_MAX_VALID) break;
        cluster = next;
    }
    return !out.empty();
}

void emitRecord(ScanContext &ctx, ExfatState &st, const FileRecord &rec) {
    if (st.recordsEmitted >= 200000) return;
    FileRecord copy = rec;
    copy.id = st.nextId++;
    ctx.result(copy);
    ++st.recordsEmitted;
    ++ctx.stats.fatFound;
    if (rec.status == Status::Existing) ++ctx.stats.existingFound;
}

void scanDirectory(ScanContext &ctx, const ExfatInfo &fi, ExfatState &st,
                   uint32_t startCluster, const std::string &dirPath, int depth);

void processEntrySet(ScanContext &ctx, const ExfatInfo &fi, ExfatState &st,
                     const std::vector<uint8_t> &data, size_t index, size_t secondaryCount,
                     const std::string &dirPath, int depth) {
    const uint8_t *file = data.data() + index * DIR_ENTRY_SIZE;
    uint8_t type = file[0];
    bool deleted = (type & 0x80) == 0;
    if ((type & 0x1F) != 0x05 || (type & 0x40) != 0 || secondaryCount < 2 || secondaryCount > 18)
        return;
    const bool want = deleted ? ctx.options.includeDeleted : ctx.options.includeExisting;

    const uint8_t *stream = nullptr;
    std::vector<uint16_t> nameChars;
    for (size_t j = 1; j <= secondaryCount; ++j) {
        size_t idx = index + j;
        if (idx * DIR_ENTRY_SIZE + DIR_ENTRY_SIZE > data.size()) break;
        const uint8_t *e = data.data() + idx * DIR_ENTRY_SIZE;
        uint8_t et = e[0];
        int code = et & 0x1F;
        bool secondary = (et & 0x40) != 0;
        if (secondary && code == 0 && !stream) stream = e;
        else if (secondary && code == 1) {
            for (int k = 0; k < 15; ++k) nameChars.push_back(rd16(e + 2 + k * 2));
        }
    }
    if (!stream) return;

    uint8_t nameLength = stream[3];
    uint16_t flags = static_cast<uint16_t>(stream[1]);
    bool noFatChain = (flags & 0x02) != 0;
    uint32_t firstCluster = rd32(stream + 20);
    uint64_t dataLength = rd64(stream + 24);
    uint64_t validLength = rd64(stream + 8);
    uint64_t logicalSize = dataLength ? dataLength : validLength;
    uint16_t attrs = rd16(file + 4);
    bool isDir = (attrs & 0x10) != 0;
    uint64_t modified = exfatDateTimeToUnix(rd16(file + 18), rd16(file + 16));

    std::string name;
    for (size_t i = 0; i < nameChars.size() && i < nameLength; ++i) {
        if (nameChars[i] == 0x0000 || nameChars[i] == 0xFFFF) break;
        appendUtf8(name, nameChars[i]);
    }
    if (name.empty() || name == "." || name == "..") return;

    FileRecord rec;
    rec.name = name;
    rec.path = dirPath.empty() || dirPath == "/" ? "/" + name : dirPath + "/" + name;
    rec.fs = FsKind::ExFat;
    rec.size = isDir ? 0 : logicalSize;
    rec.type = isDir ? "Directory" : typeFromName(name);
    rec.modified = modified;
    rec.inode = firstCluster;

    if (!deleted) {
        rec.status = Status::Existing;
        rec.chance = Chance::High;
        rec.why = "exFAT chain intact and file still allocated";
        if (!isDir && firstCluster >= 2 && logicalSize > 0)
            rec.ranges = chainRanges(ctx, fi, firstCluster, logicalSize, noFatChain);
    } else {
        rec.status = Status::Deleted;
        if (firstCluster >= 2 && validCluster(ctx, fi, firstCluster) && logicalSize > 0) {
            // Trust the allocation bitmap over stale directory hints: a deleted
            // entry whose first cluster is already reallocated holds garbage.
            if (clusterAllocated(fi, firstCluster)) {
                rec.chance = Chance::Low;
                rec.why = "Deleted exFAT entry; starting cluster allocated (data overwritten)";
            } else if (!headerMatchesExt(extensionOf(name).c_str(), ctx, fi, firstCluster)) {
                rec.chance = Chance::Low;
                rec.why = "Deleted exFAT entry; data does not match file type (may be overwritten)";
            } else {
                // Deletion does not always free the FAT chain (format tools and some
                // cameras only clear the InUse bit), so follow whatever the entry
                // still describes instead of requiring a free starting cluster.
                rec.ranges = chainRanges(ctx, fi, firstCluster, logicalSize, noFatChain);
                uint64_t got = 0;
                for (const ByteRange &b : rec.ranges) got += b.length;
                if (got >= logicalSize) {
                    rec.chance = noFatChain ? Chance::High : Chance::Medium;
                    rec.why = noFatChain
                        ? "Deleted exFAT entry; contiguous data appears intact"
                        : "Deleted exFAT entry; FAT chain still intact";
                } else if (got > 0) {
                    rec.chance = Chance::Medium;
                    rec.why = "Deleted exFAT entry; partial data chain recovered (" +
                              formatBytes(got) + " of " + formatBytes(logicalSize) + ")";
                } else {
                    rec.chance = Chance::Low;
                    rec.why = "Deleted exFAT entry; data may be overwritten";
                }
            }
        } else {
            rec.chance = Chance::Low;
            rec.why = "Deleted exFAT entry; invalid starting cluster";
        }
    }
    if (want) emitRecord(ctx, st, rec);

    if (isDir && firstCluster >= 2 && !ctx.cancelledNow() && depth <= 12)
        scanDirectory(ctx, fi, st, firstCluster, rec.path, depth + 1);
}

void scanDirectory(ScanContext &ctx, const ExfatInfo &fi, ExfatState &st,
                   uint32_t startCluster, const std::string &dirPath, int depth) {
    if (ctx.cancelledNow() || depth > 12) return;
    if (st.entriesSeen >= 200000 || st.recordsEmitted >= 200000) return;
    if (!st.visitedDirs.insert(startCluster).second) return;

    std::vector<uint8_t> data;
    if (!readDirectoryData(ctx, fi, startCluster, data)) return;

    size_t count = data.size() / DIR_ENTRY_SIZE;
    for (size_t i = 0; i < count;) {
        if (ctx.cancelledNow()) return;
        if (st.entriesSeen >= 200000 || st.recordsEmitted >= 200000) return;
        const uint8_t *e = data.data() + i * DIR_ENTRY_SIZE;
        uint8_t type = e[0];
        if (type == 0x00) { ++i; continue; }
        int code = type & 0x1F;
        bool primary = (type & 0x40) == 0;
        if (primary && (code == 0x05 || code == 0x03)) {
            size_t secondaryCount = code == 0x05 ? e[1] : 0;
            ++st.entriesSeen;
            if (code == 0x05) processEntrySet(ctx, fi, st, data, i, secondaryCount, dirPath, depth);
            i += 1 + std::min<size_t>(secondaryCount, 18);
        } else {
            ++i;
        }
    }
}

} // namespace

void scanExfat(ScanContext &ctx) {
    if (ctx.cancelledNow()) return;
    ctx.progress(0, "Reading exFAT boot sector");

    const uint64_t boot = ctx.partitionStart;
    if (ctx.partitionLength < 512) return;

    char sig[8]{};
    if (!ctx.reader.readExact(boot + 3, sig, 8) || std::memcmp(sig, "EXFAT   ", 8) != 0) return;

    bool ok = false;
    uint8_t sectorShift = ctx.reader.u8(boot + 0x6C, &ok); if (!ok) return;
    uint8_t clusterShift = ctx.reader.u8(boot + 0x6D, &ok); if (!ok) return;
    uint32_t fatOffsetSectors = ctx.reader.u32(boot + 0x50, &ok); if (!ok) return;
    uint32_t heapOffsetSectors = ctx.reader.u32(boot + 0x58, &ok); if (!ok) return;
    uint32_t clusterCount = ctx.reader.u32(boot + 0x5C, &ok); if (!ok) return;
    uint32_t rootCluster = ctx.reader.u32(boot + 0x60, &ok); if (!ok) return;
    if (sectorShift < 9 || sectorShift > 12 || clusterShift > 25) return;
    if (clusterCount == 0 || rootCluster < 2 || rootCluster > clusterCount + 1) return;

    uint64_t bytesPerSector = uint64_t{1} << sectorShift;
    uint64_t clusterBytes = bytesPerSector << clusterShift;
    if (!isPow2(clusterBytes) || clusterBytes == 0) return;

    ExfatInfo fi;
    fi.fatOffset = boot + static_cast<uint64_t>(fatOffsetSectors) * bytesPerSector;
    fi.heapOffset = boot + static_cast<uint64_t>(heapOffsetSectors) * bytesPerSector;
    fi.clusterBytes = clusterBytes;
    fi.clusterCount = clusterCount;
    fi.rootCluster = rootCluster;
    loadBitmap(ctx, fi);
    if (fi.heapOffset < boot || !validCluster(ctx, fi, rootCluster)) return;

    ExfatState st;
    ctx.progress(5, "Scanning exFAT directory tree");
    scanDirectory(ctx, fi, st, rootCluster, "/", 0);
    ctx.progress(100, "exFAT scan complete");
}

} // namespace dd
