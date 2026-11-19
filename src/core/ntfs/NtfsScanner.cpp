#include "core/FsScanner.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace dd {
namespace {

uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t le64(const uint8_t *p) {
    return static_cast<uint64_t>(le32(p)) |
           (static_cast<uint64_t>(le32(p + 4)) << 32);
}

uint64_t readUnsignedLE(const uint8_t *p, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

int64_t readSignedLE(const uint8_t *p, int n) {
    if (n <= 0) return 0;
    uint64_t v = readUnsignedLE(p, n);
    const int bits = n * 8;
    if (bits < 64 && (v & (uint64_t(1) << (bits - 1))))
        v |= ~uint64_t(0) << bits;
    return static_cast<int64_t>(v);
}

bool addOverflow(uint64_t a, uint64_t b, uint64_t &out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) return true;
    out = a + b;
    return false;
}

bool mulOverflow(uint64_t a, uint64_t b, uint64_t &out) {
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return true;
    out = a * b;
    return false;
}

uint64_t ticksToUnix(uint64_t ticks) {
    const uint64_t epoch = 11644473600ULL;
    if (ticks == 0 || ticks == std::numeric_limits<uint64_t>::max()) return 0;
    uint64_t secs = ticks / 10000000ULL;
    if (secs <= epoch) return 0;
    return secs - epoch;
}

void appendUtf8(std::string &s, uint32_t cp) {
    if (cp <= 0x7F) {
        s.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        s.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        s.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string utf16LeToUtf8(const uint8_t *p, uint64_t units) {
    std::string s;
    for (uint64_t i = 0; i < units; ++i) {
        uint32_t cp = le16(p + i * 2);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units) {
            uint32_t lo = le16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        appendUtf8(s, cp);
    }
    return s;
}

struct NameInfo {
    uint64_t parent = 0;
    std::string name;
};

struct ParsedRecord {
    uint16_t sequence = 0;
    uint16_t linkCount = 0;
    uint16_t flags = 0;
    bool usaIntact = true;
    uint64_t parent = 0;
    std::string name;
    uint8_t nameNs = 4;
    bool hasSi = false;
    uint64_t created = 0;
    uint64_t modified = 0;
    uint64_t mftChanged = 0;
    uint64_t accessed = 0;
    bool hasData = false;
    bool dataResident = false;
    uint64_t dataSize = 0;
    uint64_t dataAllocated = 0;
    uint64_t dataInitialized = 0;
    std::vector<ByteRange> ranges;
    bool runWithin = true;
    bool runCovers = false;
};

void decodeRunlist(const std::vector<uint8_t> &buf, uint64_t recordSize,
                   uint64_t pos, uint64_t partStart, uint64_t partLen,
                   uint64_t clusterBytes, uint64_t realSize,
                   std::vector<ByteRange> &ranges, bool &within, bool &covers) {
    within = true;
    covers = false;
    uint64_t covered = 0;
    int64_t lcn = 0;
    int entries = 0;

    uint64_t partEnd = 0;
    const bool partOk = !addOverflow(partStart, partLen, partEnd);
    if (!partOk) partEnd = std::numeric_limits<uint64_t>::max();

    while (pos < recordSize && entries < 10000) {
        uint8_t header = buf[pos++];
        if (header == 0) break;
        const uint8_t lenSize = header & 0x0F;
        const uint8_t offSize = static_cast<uint8_t>(header >> 4);
        if (lenSize == 0 || lenSize > 8 || offSize > 8) {
            within = false;
            break;
        }
        if (pos + lenSize + offSize > recordSize) {
            within = false;
            break;
        }
        const uint64_t runLen = readUnsignedLE(buf.data() + pos, lenSize);
        pos += lenSize;
        const int64_t delta = readSignedLE(buf.data() + pos, offSize);
        pos += offSize;
        ++entries;

        uint64_t bytes = 0;
        if (mulOverflow(runLen, clusterBytes, bytes)) {
            within = false;
            break;
        }
        if (addOverflow(covered, bytes, covered)) {
            within = false;
            break;
        }
        if (offSize == 0) continue;

        const int64_t iMax = std::numeric_limits<int64_t>::max();
        const int64_t iMin = std::numeric_limits<int64_t>::min();
        if ((delta > 0 && lcn > iMax - delta) || (delta < 0 && lcn < iMin - delta)) {
            within = false;
            break;
        }
        lcn += delta;
        if (lcn < 0) {
            within = false;
            continue;
        }

        uint64_t rel = 0;
        uint64_t abs = 0;
        if (mulOverflow(static_cast<uint64_t>(lcn), clusterBytes, rel) ||
            addOverflow(partStart, rel, abs)) {
            within = false;
            continue;
        }
        if (abs >= partEnd) {
            within = false;
            continue;
        }
        uint64_t len = bytes;
        if (len > partEnd - abs) {
            within = false;
            len = partEnd - abs;
        }
        if (len == 0) continue;

        if (!ranges.empty()) {
            ByteRange &prev = ranges.back();
            uint64_t prevEnd = 0;
            uint64_t merged = 0;
            if (!addOverflow(prev.offset, prev.length, prevEnd) && prevEnd == abs &&
                !addOverflow(prev.length, len, merged)) {
                prev.length = merged;
                continue;
            }
        }
        ranges.push_back({abs, len});
    }

    covers = covered >= realSize;

    uint64_t remaining = realSize;
    for (auto it = ranges.begin(); it != ranges.end();) {
        if (remaining == 0 || it->length == 0) {
            it = ranges.erase(it);
            continue;
        }
        if (it->length > remaining) it->length = remaining;
        remaining -= it->length;
        ++it;
    }
}

bool parseRecord(std::vector<uint8_t> &buf, uint64_t recordSize, uint64_t bps,
                 uint64_t recordAbs, uint64_t partStart, uint64_t partLen,
                 uint64_t clusterBytes, ParsedRecord &out) {
    if (buf.size() < 48 || std::memcmp(buf.data(), "FILE", 4) != 0) return false;

    const uint16_t usaOff = le16(buf.data() + 4);
    const uint16_t usaCount = le16(buf.data() + 6);
    out.usaIntact = true;
    if (usaCount != 0 && uint64_t(usaOff) + 2ULL * usaCount <= recordSize && bps >= 2) {
        const uint16_t endTag = le16(buf.data() + usaOff);
        const uint64_t sectors = static_cast<uint64_t>(usaCount) - 1;
        for (uint64_t i = 0; i < sectors; ++i) {
            const uint64_t end = (i + 1) * bps;
            const uint64_t usaPos = static_cast<uint64_t>(usaOff) + 2 * (i + 1);
            if (end < 2 || end > recordSize || usaPos + 2 > recordSize) {
                out.usaIntact = false;
                break;
            }
            if (le16(buf.data() + end - 2) != endTag) out.usaIntact = false;
            buf[end - 2] = buf[usaPos];
            buf[end - 1] = buf[usaPos + 1];
        }
    } else if (usaCount != 0) {
        out.usaIntact = false;
    }

    out.sequence = le16(buf.data() + 16);
    out.linkCount = le16(buf.data() + 18);
    const uint16_t attrOffset = le16(buf.data() + 20);
    out.flags = le16(buf.data() + 22);
    uint32_t usedSize = le32(buf.data() + 24);
    const uint32_t allocSize = le32(buf.data() + 28);
    (void)allocSize;
    const uint64_t baseRecord = le64(buf.data() + 32);
    if (baseRecord != 0) return false;

    if (usedSize > recordSize) usedSize = static_cast<uint32_t>(recordSize);

    uint64_t off = attrOffset;
    while (off + 8 <= recordSize && off < usedSize) {
        const uint32_t type = le32(buf.data() + off);
        if (type == 0xFFFFFFFFu) break;
        const uint32_t len = le32(buf.data() + off + 4);
        if (len < 8 || off + len > recordSize) break;

        const uint8_t nonresident = buf[off + 8];
        if (nonresident == 0) {
            if (len < 24 || off + 24 > recordSize) {
                off += len;
                continue;
            }
            const uint32_t valueLen = le32(buf.data() + off + 16);
            const uint16_t valueOffset = le16(buf.data() + off + 20);
            if (valueOffset > recordSize) {
                off += len;
                continue;
            }
            const uint8_t *value = buf.data() + valueOffset;
            const uint64_t valueCap = std::min<uint64_t>(valueLen, recordSize - valueOffset);

            if (type == 0x10u) {
                if (valueCap >= 32) {
                    out.hasSi = true;
                    out.created = ticksToUnix(le64(value + 0));
                    out.modified = ticksToUnix(le64(value + 8));
                    out.mftChanged = ticksToUnix(le64(value + 16));
                    out.accessed = ticksToUnix(le64(value + 24));
                }
            } else if (type == 0x30u) {
                if (valueCap >= 66) {
                    const uint8_t ns = value[65];
                    const uint8_t nameLen = value[64];
                    if (66ULL + 2ULL * nameLen <= valueCap) {
                        std::string name = utf16LeToUtf8(value + 66, nameLen);
                        if (!name.empty() && (out.name.empty() || (out.nameNs == 2 && ns != 2))) {
                            out.name = name;
                            out.nameNs = ns;
                            out.parent = le64(value + 0) & 0x0000FFFFFFFFFFFFULL;
                        }
                    }
                }
            } else if (type == 0x80u && !out.hasData) {
                out.hasData = true;
                out.dataResident = true;
                out.dataSize = valueLen;
                out.runWithin = true;
                out.runCovers = true;
                if (valueLen > 0 && valueCap > 0)
                    out.ranges.push_back({recordAbs + valueOffset, valueCap});
            }
        } else {
            if (type == 0x80u && !out.hasData) {
                if (len < 64 || off + 64 > recordSize) {
                    off += len;
                    continue;
                }
                const uint16_t runlistOffset = le16(buf.data() + off + 32);
                out.hasData = true;
                out.dataResident = false;
                out.dataAllocated = le64(buf.data() + off + 40);
                out.dataSize = le64(buf.data() + off + 48);
                out.dataInitialized = le64(buf.data() + off + 56);
                decodeRunlist(buf, recordSize, off + runlistOffset, partStart, partLen,
                              clusterBytes, out.dataSize, out.ranges,
                              out.runWithin, out.runCovers);
            }
        }
        off += len;
    }
    return true;
}

std::string buildPath(uint64_t recordNumber, const std::vector<NameInfo> &names) {
    std::string path;
    for (int depth = 0; depth < 12; ++depth) {
        if (recordNumber >= names.size()) break;
        const NameInfo &info = names[static_cast<size_t>(recordNumber)];
        if (info.name.empty()) break;
        if (!path.empty()) path.insert(path.begin(), '/');
        path.insert(0, info.name);
        if (info.parent == 5 || info.parent == recordNumber) break;
        recordNumber = info.parent;
    }
    return path;
}

} // namespace

void scanNtfs(ScanContext &ctx) {
    if (!ctx.reader.isOpen() || ctx.partitionLength == 0) return;

    const uint64_t partStart = ctx.partitionStart;
    const uint64_t partLen = ctx.partitionLength;

    char signature[8]{};
    if (!ctx.reader.readExact(partStart + 3, signature, 8) ||
        std::memcmp(signature, "NTFS    ", 8) != 0)
        return;

    const uint16_t bps = ctx.reader.u16(partStart + 11);
    const int8_t spcRaw = static_cast<int8_t>(ctx.reader.u8(partStart + 13));
    const uint64_t mftLCN = ctx.reader.u64(partStart + 48);
    const int8_t cprRaw = static_cast<int8_t>(ctx.reader.u8(partStart + 64));
    if (bps == 0 || spcRaw <= 0) return;

    uint64_t recordSize = 0;
    if (cprRaw < 0) {
        const int shift = -static_cast<int>(cprRaw);
        if (shift < 0 || shift >= 63) return;
        recordSize = uint64_t(1) << shift;
    } else {
        if (mulOverflow(static_cast<uint64_t>(cprRaw), static_cast<uint64_t>(spcRaw), recordSize) ||
            mulOverflow(recordSize, static_cast<uint64_t>(bps), recordSize))
            return;
    }
    if (recordSize < 256 || recordSize > 65536 || (recordSize & (recordSize - 1)) != 0) return;

    uint64_t clusterBytes = 0;
    if (mulOverflow(static_cast<uint64_t>(spcRaw), static_cast<uint64_t>(bps), clusterBytes) ||
        clusterBytes == 0)
        return;

    uint64_t mftRelative = 0;
    uint64_t mftOffset = 0;
    if (mulOverflow(mftLCN, clusterBytes, mftRelative) ||
        addOverflow(partStart, mftRelative, mftOffset))
        return;

    uint64_t count = std::min<uint64_t>(1000000ULL, partLen / recordSize);
    count = std::min<uint64_t>(count, 200000ULL);
    if (count == 0) return;

    std::vector<NameInfo> names(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        if (ctx.cancelledNow()) return;
        uint64_t recordAbs = 0;
        if (addOverflow(mftOffset, i * recordSize, recordAbs)) break;

        std::vector<uint8_t> buffer(static_cast<size_t>(recordSize));
        if (!ctx.reader.readExact(recordAbs, buffer.data(), recordSize)) continue;

        ParsedRecord parsed;
        if (!parseRecord(buffer, recordSize, bps, recordAbs, partStart, partLen,
                         clusterBytes, parsed))
            continue;
        if (!parsed.name.empty()) {
            NameInfo &info = names[static_cast<size_t>(i)];
            info.parent = parsed.parent;
            info.name = parsed.name;
        }
        if ((i & 63) == 0 || i + 1 == count)
            ctx.progress(static_cast<int>((i * 50) / count), "NTFS: indexing MFT");
    }

    for (uint64_t i = 0; i < count; ++i) {
        if (ctx.cancelledNow()) return;
        uint64_t recordAbs = 0;
        if (addOverflow(mftOffset, i * recordSize, recordAbs)) break;

        std::vector<uint8_t> buffer(static_cast<size_t>(recordSize));
        if (!ctx.reader.readExact(recordAbs, buffer.data(), recordSize)) continue;

        ParsedRecord parsed;
        if (!parseRecord(buffer, recordSize, bps, recordAbs, partStart, partLen,
                         clusterBytes, parsed))
            continue;

        const bool deleted = (parsed.flags & 0x01u) == 0;
        const bool directory = (parsed.flags & 0x02u) != 0;
        if (directory) continue;
        if (deleted && !ctx.options.includeDeleted) continue;
        if (!deleted && !ctx.options.includeExisting) continue;

        FileRecord rec;
        rec.id = i;
        rec.inode = i;
        rec.name = parsed.name.empty()
                       ? "mft_" + std::to_string(i) + "_" + std::to_string(parsed.sequence)
                       : parsed.name;
        rec.path = buildPath(i, names);
        if (rec.path.empty()) rec.path = rec.name;
        rec.size = parsed.dataSize;
        rec.status = deleted ? Status::Deleted : Status::Existing;
        rec.fs = FsKind::Ntfs;
        rec.type = typeFromName(rec.name);
        rec.ranges = parsed.ranges;
        rec.modified = parsed.modified;

        uint64_t totalRange = 0;
        for (const ByteRange &range : rec.ranges) {
            if (addOverflow(totalRange, range.length, totalRange)) {
                totalRange = std::numeric_limits<uint64_t>::max();
                break;
            }
        }
        const bool hasRanges = !rec.ranges.empty() && totalRange > 0;
        const bool sequenceIntact = parsed.sequence != 0 && parsed.usaIntact;

        if (!deleted) {
            if (parsed.hasData && hasRanges) {
                rec.chance = Chance::High;
                rec.why = "MFT record in use, data runlist intact";
            } else {
                rec.chance = Chance::Low;
                rec.why = "MFT record in use, no data extent (metadata only)";
            }
        } else if (!parsed.hasData || parsed.dataSize == 0 || !hasRanges) {
            rec.chance = Chance::Low;
            rec.why = "Deleted MFT record, metadata only";
        } else if (parsed.runWithin && sequenceIntact && parsed.runCovers &&
                   totalRange <= parsed.dataSize) {
            rec.chance = Chance::High;
            rec.why = "Deleted MFT record, runlist intact, sequence valid, "
                      "extent fully within partition";
        } else if (hasRanges && totalRange <= parsed.dataSize) {
            rec.chance = Chance::Medium;
            rec.why = "Deleted MFT record, data extents valid";
        } else {
            rec.chance = Chance::Low;
            rec.why = "Deleted MFT record, data extents incomplete (metadata only)";
        }

        ++ctx.stats.ntfsFound;
        if (!deleted) ++ctx.stats.existingFound;
        ctx.result(rec);

        if ((i & 63) == 0 || i + 1 == count)
            ctx.progress(50 + static_cast<int>((i * 50) / count), "NTFS: scanning MFT records");
    }

    ctx.progress(100, "NTFS: done");
}

} // namespace dd
