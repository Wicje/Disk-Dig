#include "core/FsScanner.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dd {
namespace {

constexpr uint32_t FAT_ENTRY_FREE = 0x00000000u;
constexpr uint32_t FAT_ENTRY_BAD = 0x0FFFFFF7u;
constexpr uint32_t FAT_ENTRY_EOC_MIN = 0x0FFFFFF8u;
constexpr uint32_t FAT_ENTRY_MASK = 0x0FFFFFFFu;
constexpr uint32_t FAT_MAX_VALID = 0x0FFFFFEFu;
constexpr size_t DIR_ENTRY_SIZE = 32;
constexpr uint8_t ATTR_READ_ONLY = 0x01;
constexpr uint8_t ATTR_HIDDEN = 0x02;
constexpr uint8_t ATTR_SYSTEM = 0x04;
constexpr uint8_t ATTR_VOLUME_ID = 0x08;
constexpr uint8_t ATTR_DIRECTORY = 0x10;
constexpr uint8_t ATTR_ARCHIVE = 0x20;
constexpr uint8_t ATTR_LFN = 0x0F;

struct FatInfo {
    uint16_t bytesPerSector = 0;
    uint8_t sectorsPerCluster = 0;
    uint16_t reservedSectors = 0;
    uint8_t numFATs = 0;
    uint32_t fatSectors = 0;
    uint32_t totalSectors = 0;
    uint32_t dataStart = 0;
    uint32_t dataSectors = 0;
    uint32_t clusterCount = 0;
    uint32_t rootCluster = 0;
    uint64_t fatOffset = 0;
    uint64_t clusterBytes = 0;
};

struct ScanState {
    uint64_t nextId = 1;
    uint32_t clustersWalked = 0;
    uint32_t entriesSeen = 0;
    uint32_t recordsEmitted = 0;
    std::unordered_set<uint32_t> visitedDirChains;
};

bool isPow2(uint32_t v) { return v && ((v & (v - 1)) == 0); }

uint64_t clusterOffset(const FatInfo &fi, uint64_t partitionStart, uint32_t cluster) {
    return partitionStart + (static_cast<uint64_t>(fi.dataStart) +
                             static_cast<uint64_t>(cluster - 2) * fi.sectorsPerCluster) *
                                fi.bytesPerSector;
}

bool clusterInRange(const ScanContext &ctx, const FatInfo &fi, uint32_t cluster) {
    if (cluster < 2 || cluster > fi.clusterCount + 1) return false;
    uint64_t off = clusterOffset(fi, ctx.partitionStart, cluster);
    uint64_t end = off + fi.clusterBytes;
    return off >= ctx.partitionStart && end <= ctx.partitionStart + ctx.partitionLength &&
           end >= off;
}

uint32_t readFatEntry(const ScanContext &ctx, const FatInfo &fi, uint32_t cluster) {
    uint64_t off = fi.fatOffset + static_cast<uint64_t>(cluster) * 4u;
    bool ok = false;
    uint32_t v = ctx.reader.u32(off, &ok);
    if (!ok) return FAT_ENTRY_BAD;
    return v & FAT_ENTRY_MASK;
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

struct LfnPart {
    int seq = 0;
    bool hasSeq = false;
    std::array<uint16_t, 13> chars{};
};

std::string lfnToUtf8(const std::vector<LfnPart> &partsIn) {
    if (partsIn.empty()) return {};
    std::vector<LfnPart> parts = partsIn;
    bool allSeq = true;
    for (const auto &p : parts) if (!p.hasSeq) { allSeq = false; break; }
    if (allSeq) {
        std::sort(parts.begin(), parts.end(), [](const LfnPart &a, const LfnPart &b) {
            return a.seq < b.seq;
        });
    } else {
        std::reverse(parts.begin(), parts.end());
    }
    std::string out;
    bool done = false;
    for (const auto &p : parts) {
        for (uint16_t ch : p.chars) {
            if (ch == 0x0000 || ch == 0xFFFF) { done = true; break; }
            appendUtf8(out, ch);
        }
        if (done) break;
    }
    return out;
}

std::string trimTrailingSpaces(const std::string &s) {
    size_t end = s.size();
    while (end > 0 && s[end - 1] == ' ') --end;
    return s.substr(0, end);
}

std::string shortNameFromEntry(const uint8_t *e, bool deleted) {
    char base[9];
    char ext[4];
    std::memcpy(base, e + 0, 8);
    std::memcpy(ext, e + 8, 3);
    base[8] = '\0';
    ext[3] = '\0';
    if (deleted && static_cast<uint8_t>(base[0]) == 0xE5) base[0] = '_';
    else if (static_cast<uint8_t>(base[0]) == 0x05) base[0] = static_cast<char>(0xE5);
    std::string b = trimTrailingSpaces(std::string(base, 8));
    std::string x = trimTrailingSpaces(std::string(ext, 3));
    if (x.empty()) return b;
    if (b.empty()) return "." + x;
    return b + "." + x;
}

uint16_t rd16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
uint32_t rd32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

LfnPart parseLfnPart(const uint8_t *e, bool deletedEntry) {
    LfnPart p;
    uint8_t ord = e[0];
    if (!deletedEntry) {
        p.seq = ord & 0x1F;
        p.hasSeq = (p.seq >= 1 && p.seq <= 20);
    } else {
        p.hasSeq = false;
    }
    int idx = 0;
    for (int i = 0; i < 5; ++i) p.chars[idx++] = rd16(e + 1 + i * 2);
    for (int i = 0; i < 6; ++i) p.chars[idx++] = rd16(e + 14 + i * 2);
    for (int i = 0; i < 2; ++i) p.chars[idx++] = rd16(e + 28 + i * 2);
    return p;
}

uint64_t fatDateTimeToUnix(uint16_t date, uint16_t time) {
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
    // timegm is not standard C++, but widely available on Linux; fallback to mktime-like manual calc not necessary.
    // Use timegm if available.
#if defined(_GNU_SOURCE) || defined(__USE_MISC) || defined(__linux__)
    time_t t = timegm(&tm);
#else
    // Portable-ish fallback: treat as UTC by adjusting with timezone if possible is complex; use mktime as approximation.
    time_t t = std::mktime(&tm);
#endif
    if (t == static_cast<time_t>(-1)) return 0;
    return static_cast<uint64_t>(t);
}

bool readCluster(const ScanContext &ctx, const FatInfo &fi, uint32_t cluster,
                 std::vector<uint8_t> &out) {
    if (!clusterInRange(ctx, fi, cluster)) return false;
    size_t toRead = static_cast<size_t>(std::min<uint64_t>(fi.clusterBytes, 65536u));
    out.resize(toRead);
    uint64_t off = clusterOffset(fi, ctx.partitionStart, cluster);
    return ctx.reader.readExact(off, out.data(), toRead);
}

std::vector<ByteRange> coalesceChain(const ScanContext &ctx, const FatInfo &fi, uint32_t startCluster,
                                     uint64_t fileSize, bool existing) {
    std::vector<ByteRange> ranges;
    if (startCluster < 2) return ranges;
    uint32_t cluster = startCluster;
    uint64_t remaining = fileSize;
    std::unordered_set<uint32_t> seen;
    uint32_t steps = 0;
    uint32_t maxSteps = std::min<uint32_t>(fi.clusterCount ? fi.clusterCount : 1u, 100000u);
    while (steps++ < maxSteps) {
        if (cluster < 2 || cluster > fi.clusterCount + 1) break;
        if (!clusterInRange(ctx, fi, cluster)) break;
        if (!seen.insert(cluster).second) break;
        uint64_t off = clusterOffset(fi, ctx.partitionStart, cluster);
        uint64_t len = fi.clusterBytes;
        if (!existing && remaining > 0) len = std::min<uint64_t>(len, remaining);
        else if (existing && remaining > 0) len = std::min<uint64_t>(len, remaining);
        else if (existing && remaining == 0) {
            // existing file with unknown/zero size in chain context shouldn't happen, but keep safe
            len = fi.clusterBytes;
        }
        if (!ranges.empty() && ranges.back().offset + ranges.back().length == off) {
            ranges.back().length += len;
        } else {
            ranges.push_back(ByteRange{off, len});
        }
        if (remaining > 0) {
            if (remaining <= len) remaining = 0;
            else remaining -= len;
        }
        uint32_t entry = readFatEntry(ctx, fi, cluster);
        if (entry >= FAT_ENTRY_EOC_MIN || entry == FAT_ENTRY_BAD || entry == FAT_ENTRY_FREE) break;
        if (entry < 2 || entry > FAT_MAX_VALID) break;
        if (existing && remaining == 0) break;
        cluster = entry;
    }
    return ranges;
}

std::vector<ByteRange> contiguousRun(const ScanContext &ctx, const FatInfo &fi, uint32_t startCluster,
                                     uint64_t fileSize, bool &fits) {
    fits = false;
    std::vector<ByteRange> ranges;
    if (startCluster < 2 || fileSize == 0) return ranges;
    uint64_t clusterBytes = fi.clusterBytes;
    uint64_t clustersNeeded = (fileSize + clusterBytes - 1) / clusterBytes;
    if (clustersNeeded == 0) clustersNeeded = 1;
    uint64_t cur = startCluster;
    uint64_t remainingBytes = fileSize;
    for (uint64_t i = 0; i < clustersNeeded; ++i) {
        uint32_t c = static_cast<uint32_t>(cur + i);
        if (c < 2 || c > fi.clusterCount + 1) return ranges; // not fully fitting
        if (!clusterInRange(ctx, fi, c)) return ranges;
        uint64_t off = clusterOffset(fi, ctx.partitionStart, c);
        uint64_t len = std::min<uint64_t>(clusterBytes, remainingBytes);
        if (!ranges.empty() && ranges.back().offset + ranges.back().length == off) {
            ranges.back().length += len;
        } else {
            ranges.push_back(ByteRange{off, len});
        }
        if (remainingBytes > len) remainingBytes -= len; else remainingBytes = 0;
    }
    fits = true;
    return ranges;
}

void emitRecord(ScanContext &ctx, ScanState &st, const FileRecord &rec) {
    if (st.recordsEmitted >= 200000) return;
    ctx.result(rec);
    st.recordsEmitted++;
    ctx.stats.fatFound++;
    if (rec.status == Status::Existing) ctx.stats.existingFound++;
}

void processEntry(ScanContext &ctx, const FatInfo &fi, ScanState &st,
                  const uint8_t *e, const std::string &dirPath,
                  const std::string &lfnName, std::vector<uint32_t> &subdirsToVisit);

void walkDirectory(ScanContext &ctx, const FatInfo &fi, ScanState &st, uint32_t startCluster,
                   const std::string &dirPath, int depth) {
    if (ctx.cancelledNow()) return;
    if (depth > 12) return;
    if (st.entriesSeen >= 200000 || st.recordsEmitted >= 200000) return;
    if (startCluster < 2 || startCluster > fi.clusterCount + 1) return;
    if (!st.visitedDirChains.insert(startCluster).second) return;

    uint32_t cluster = startCluster;
    uint32_t chainSteps = 0;
    uint32_t maxChain = std::min<uint32_t>(fi.clusterCount ? fi.clusterCount : 1u, 100000u);
    std::unordered_set<uint32_t> seenInChain;

    while (!ctx.cancelledNow() && chainSteps < maxChain && st.clustersWalked < 100000) {
        if (cluster < 2 || cluster > fi.clusterCount + 1) break;
        if (!seenInChain.insert(cluster).second) break;
        st.clustersWalked++;
        chainSteps++;

        std::vector<uint8_t> buf;
        if (!readCluster(ctx, fi, cluster, buf)) break;

        std::vector<LfnPart> lfnParts;
        bool lfnActive = false;
        bool endOfDir = false;

        for (size_t off = 0; off + DIR_ENTRY_SIZE <= buf.size(); off += DIR_ENTRY_SIZE) {
            if (ctx.cancelledNow()) return;
            if (st.entriesSeen >= 200000 || st.recordsEmitted >= 200000) return;
            const uint8_t *e = buf.data() + off;
            uint8_t first = e[0];
            if (first == 0x00) { endOfDir = true; break; }

            uint8_t attr = e[11];
            bool deletedEntry = (first == 0xE5);

            if (attr == ATTR_LFN) {
                if ((first & 0x40) || !lfnActive) {
                    lfnParts.clear();
                    lfnActive = true;
                }
                lfnParts.push_back(parseLfnPart(e, deletedEntry));
                continue;
            }

            if (attr & ATTR_VOLUME_ID) {
                lfnParts.clear();
                lfnActive = false;
                continue;
            }

            // short entry (file/dir, existing or deleted)
            std::string lfnName;
            if (!lfnParts.empty()) {
                lfnName = lfnToUtf8(lfnParts);
            }
            lfnParts.clear();
            lfnActive = false;

            st.entriesSeen++;

            std::vector<uint32_t> subdirs;
            processEntry(ctx, fi, st, e, dirPath, lfnName, subdirs);
            for (uint32_t sd : subdirs) {
                // recurse into existing subdirectory
                std::string subName = shortNameFromEntry(e, deletedEntry);
                if (!lfnName.empty()) subName = lfnName;
                std::string subPath = dirPath;
                if (!subPath.empty() && subPath.back() != '/') subPath += '/';
                subPath += subName;
                if (subPath.empty()) subPath = "/" + subName;
                walkDirectory(ctx, fi, st, sd, subPath, depth + 1);
                if (ctx.cancelledNow() || st.entriesSeen >= 200000 || st.recordsEmitted >= 200000) return;
            }
        }

        if (endOfDir) break;

        uint32_t entry = readFatEntry(ctx, fi, cluster);
        if (entry >= FAT_ENTRY_EOC_MIN || entry == FAT_ENTRY_BAD || entry == FAT_ENTRY_FREE) break;
        if (entry < 2 || entry > FAT_MAX_VALID) break;
        cluster = entry;
    }
}

void processEntry(ScanContext &ctx, const FatInfo &fi, ScanState &st,
                  const uint8_t *e, const std::string &dirPath,
                  const std::string &lfnName, std::vector<uint32_t> &subdirsToVisit) {
    uint8_t first = e[0];
    bool deleted = (first == 0xE5);
    uint8_t attr = e[11];
    bool isDir = (attr & ATTR_DIRECTORY) != 0;

    std::string shortName = shortNameFromEntry(e, deleted);
    std::string name = lfnName.empty() ? shortName : lfnName;

    // Skip . and ..
    if (shortName == "." || shortName == "..") return;

    uint32_t firstCluster = (static_cast<uint32_t>(rd16(e + 20)) << 16) | rd16(e + 26);
    uint32_t size32 = rd32(e + 28);
    uint64_t logicalSize = isDir ? 0 : static_cast<uint64_t>(size32);

    uint16_t wDate = rd16(e + 16); // spec says +0x10 date, +0x12 time for write time
    uint16_t wTime = rd16(e + 18);
    // follow spec literally:
    wDate = rd16(e + 0x10);
    wTime = rd16(e + 0x12);
    uint64_t modified = fatDateTimeToUnix(wDate, wTime);

    FileRecord rec;
    rec.id = st.nextId++;
    rec.name = name;
    std::string path = dirPath;
    if (!path.empty() && path.back() != '/') path += '/';
    path += name;
    if (dirPath.empty() || dirPath == "/") {
        if (dirPath == "/") path = "/" + name; else path = "/" + name;
    }
    rec.path = path;
    rec.size = logicalSize;
    rec.fs = FsKind::Fat;
    rec.type = isDir ? "Directory" : typeFromName(name);
    rec.modified = modified;
    rec.deleted = 0;
    // diagnostic inode: use absolute offset not directly known here cheaply; store firstCluster
    rec.inode = firstCluster;

    if (!deleted) {
        // existing
        if (!ctx.options.includeExisting) {
            // but we may still need to recurse into existing directories
            if (isDir && firstCluster >= 2) subdirsToVisit.push_back(firstCluster);
            return;
        }
        rec.status = Status::Existing;
        rec.chance = Chance::High;
        rec.why = "FAT chain intact and file still allocated";
        if (isDir) {
            rec.size = 0;
            rec.ranges.clear();
        } else {
            if (logicalSize == 0 || firstCluster < 2) {
                rec.ranges.clear();
            } else {
                rec.ranges = coalesceChain(ctx, fi, firstCluster, logicalSize, true);
            }
        }
        emitRecord(ctx, st, rec);
        if (isDir && firstCluster >= 2) subdirsToVisit.push_back(firstCluster);
        return;
    }

    // deleted
    if (!ctx.options.includeDeleted) return;
    if (isDir) {
        // include deleted directories only as records, do not recurse into them
        rec.status = Status::Deleted;
        rec.size = 0;
        bool firstValid = (firstCluster >= 2 && firstCluster <= fi.clusterCount + 1);
        if (!firstValid) {
            rec.chance = Chance::Low;
            rec.why = "Deleted directory entry has invalid starting cluster";
        } else {
            uint32_t fe = readFatEntry(ctx, fi, firstCluster);
            if (fe == FAT_ENTRY_FREE) {
                bool fits = clusterInRange(ctx, fi, firstCluster);
                rec.chance = fits ? Chance::High : Chance::Low;
                rec.why = fits ? "Deleted directory entry intact; data area not reallocated"
                               : "Deleted directory entry outside partition bounds";
                if (fits) {
                    uint64_t off = clusterOffset(fi, ctx.partitionStart, firstCluster);
                    rec.ranges.push_back(ByteRange{off, std::min<uint64_t>(fi.clusterBytes, 65536u)});
                }
            } else if (fe == FAT_ENTRY_EOC_MIN || (fe >= 2 && fe <= FAT_MAX_VALID)) {
                rec.chance = Chance::Medium;
                rec.why = "Partial FAT chain still present; directory data may be recoverable";
                rec.ranges = coalesceChain(ctx, fi, firstCluster, fi.clusterBytes, false);
            } else {
                rec.chance = Chance::Low;
                rec.why = "Starting cluster FAT entry invalid or data may be overwritten";
            }
        }
        emitRecord(ctx, st, rec);
        return;
    }

    // deleted file
    // Never emit zero-size deleted file records unless name known and note "size unknown"
    if (logicalSize == 0) {
        if (name.empty()) return;
        rec.status = Status::Deleted;
        rec.chance = Chance::Low;
        rec.ranges.clear();
        rec.why = "size unknown";
        emitRecord(ctx, st, rec);
        return;
    }

    bool firstValid = (firstCluster >= 2 && firstCluster <= fi.clusterCount + 1);
    bool startInPartition = firstValid && clusterInRange(ctx, fi, firstCluster);
    if (!firstValid || !startInPartition) {
        rec.status = Status::Deleted;
        rec.chance = Chance::Low;
        rec.ranges.clear();
        rec.why = !firstValid ? "Invalid starting cluster; data location unknown"
                               : "Data area outside partition bounds";
        emitRecord(ctx, st, rec);
        return;
    }

    uint32_t firstFat = readFatEntry(ctx, fi, firstCluster);
    bool partialChain = (firstFat == FAT_ENTRY_EOC_MIN || (firstFat >= 2 && firstFat <= FAT_MAX_VALID));

    if (partialChain) {
        rec.ranges = coalesceChain(ctx, fi, firstCluster, logicalSize, false);
        if (rec.ranges.empty()) {
            rec.chance = Chance::Low;
            rec.why = "Partial FAT chain present but data blocks could not be read";
        } else {
            rec.chance = Chance::Medium;
            rec.why = "Partial FAT chain still present; data may be fragmented or partially overwritten";
        }
    } else {
        bool fits = false;
        rec.ranges = contiguousRun(ctx, fi, firstCluster, logicalSize, fits);
        if (fits && firstFat == FAT_ENTRY_FREE) {
            rec.chance = Chance::High;
            rec.why = "Deleted directory entry intact; data area not reallocated";
        } else if (fits && firstFat != FAT_ENTRY_FREE) {
            rec.chance = Chance::Medium;
            rec.why = "Data area may be reallocated";
        } else {
            // contiguous run doesn't fit in partition/cluster range
            rec.chance = Chance::Low;
            rec.why = "Data outside partition or cluster range; recovery unlikely";
            // try to keep whatever contiguous portion was built? contiguousRun returns empty on first failure in our impl
            // rebuild partial contiguous that fits
            rec.ranges.clear();
            uint64_t clusterBytes = fi.clusterBytes;
            uint64_t clustersNeeded = (logicalSize + clusterBytes - 1) / clusterBytes;
            uint64_t remainingBytes = logicalSize;
            for (uint64_t i = 0; i < clustersNeeded; ++i) {
                uint32_t c = static_cast<uint32_t>(firstCluster + i);
                if (c < 2 || c > fi.clusterCount + 1) break;
                if (!clusterInRange(ctx, fi, c)) break;
                uint64_t off = clusterOffset(fi, ctx.partitionStart, c);
                uint64_t len = std::min<uint64_t>(clusterBytes, remainingBytes);
                if (!rec.ranges.empty() && rec.ranges.back().offset + rec.ranges.back().length == off)
                    rec.ranges.back().length += len;
                else
                    rec.ranges.push_back(ByteRange{off, len});
                if (remainingBytes > len) remainingBytes -= len; else remainingBytes = 0;
            }
            if (rec.ranges.empty()) {
                rec.why = "Data outside partition or cluster range; recovery unlikely";
            }
        }
    }

    // if we somehow got no ranges and not low-for-outside reason, adjust
    if (rec.ranges.empty() && rec.chance != Chance::Low) {
        rec.chance = Chance::Low;
        rec.why = "No recoverable data ranges could be determined";
    }

    rec.status = Status::Deleted;
    emitRecord(ctx, st, rec);
}

} // namespace

void scanFat32(ScanContext &ctx) {
    if (ctx.cancelledNow()) return;
    ctx.progress(0, "Reading FAT32 boot sector");

    const uint64_t bpb = ctx.partitionStart;
    if (ctx.partitionLength < 512) return;

    bool ok = false;
    uint8_t sig[8]{};
    if (!ctx.reader.readExact(bpb + 82, sig, 8)) return;
    if (std::memcmp(sig, "FAT32   ", 8) != 0) return;

    FatInfo fi;
    fi.bytesPerSector = ctx.reader.u16(bpb + 11, &ok); if (!ok) return;
    fi.sectorsPerCluster = ctx.reader.u8(bpb + 13, &ok); if (!ok) return;
    fi.reservedSectors = ctx.reader.u16(bpb + 14, &ok); if (!ok) return;
    fi.numFATs = ctx.reader.u8(bpb + 16, &ok); if (!ok) return;
    uint16_t rootEntries = ctx.reader.u16(bpb + 17, &ok); if (!ok) return; (void)rootEntries;
    uint16_t fatSize16 = ctx.reader.u16(bpb + 22, &ok); if (!ok) return;
    uint16_t totalSec16 = ctx.reader.u16(bpb + 19, &ok); if (!ok) return;
    uint32_t totalSec32 = ctx.reader.u32(bpb + 32, &ok); if (!ok) return;
    uint32_t fatSize32 = ctx.reader.u32(bpb + 36, &ok); if (!ok) return;
    fi.rootCluster = ctx.reader.u32(bpb + 44, &ok); if (!ok) return;
    uint32_t fsInfo = ctx.reader.u32(bpb + 48, &ok); if (!ok) return; (void)fsInfo;

    if (fi.bytesPerSector < 512 || fi.bytesPerSector > 4096 || !isPow2(fi.bytesPerSector)) return;
    if (fi.sectorsPerCluster == 0 || fi.sectorsPerCluster > 128) return;
    if (fi.numFATs == 0) return;

    fi.fatSectors = fatSize32 ? fatSize32 : fatSize16;
    fi.totalSectors = totalSec16 ? totalSec16 : totalSec32;
    if (fi.totalSectors == 0 || fi.fatSectors == 0) return;

    uint64_t dataStart64 = static_cast<uint64_t>(fi.reservedSectors) +
                           static_cast<uint64_t>(fi.numFATs) * fi.fatSectors;
    if (dataStart64 >= fi.totalSectors) return;
    fi.dataStart = static_cast<uint32_t>(dataStart64);
    fi.dataSectors = fi.totalSectors - fi.dataStart;
    if (fi.sectorsPerCluster == 0) return;
    fi.clusterCount = fi.dataSectors / fi.sectorsPerCluster;
    if (fi.clusterCount < 1) return;

    fi.fatOffset = ctx.partitionStart + static_cast<uint64_t>(fi.reservedSectors) * fi.bytesPerSector;
    fi.clusterBytes = static_cast<uint64_t>(fi.sectorsPerCluster) * fi.bytesPerSector;
    if (fi.clusterBytes == 0) return;

    // Basic bounds sanity check against partition length / reader
    uint64_t fatRegionEnd = fi.fatOffset + static_cast<uint64_t>(fi.numFATs) * fi.fatSectors * fi.bytesPerSector;
    if (fatRegionEnd < fi.fatOffset) return;
    uint64_t dataRegionStart = clusterOffset(fi, ctx.partitionStart, 2);
    if (dataRegionStart < ctx.partitionStart) return;

    if (fi.rootCluster < 2) fi.rootCluster = 2;

    ScanState st;
    ctx.progress(5, "Scanning FAT32 directory tree");
    walkDirectory(ctx, fi, st, fi.rootCluster, "/", 0);
    ctx.progress(100, "FAT32 scan complete");
}

} // namespace dd
