#include "core/FsScanner.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace dd {
namespace {

constexpr size_t CHUNK_SIZE = 16u * 1024u * 1024u;
constexpr size_t OVERLAP = 64u * 1024u;
constexpr size_t BLOCK_SIZE = 256u * 1024u;
constexpr size_t MAX_HEADER = 16u;
constexpr uint64_t JPEG_LIMIT = 32u * 1024u * 1024u;
constexpr uint64_t ZIP_LIMIT = 64u * 1024u * 1024u;
constexpr uint64_t DEFAULT_LIMIT = 16u * 1024u * 1024u;
constexpr uint64_t NEXT_HEADER_LIMIT = 64u * 1024u * 1024u;
constexpr uint64_t VIDEO_LIMIT = std::numeric_limits<uint64_t>::max();
constexpr uint64_t FIRST_ID = 90000000ULL;

struct Range {
    uint64_t begin = 0;
    uint64_t end = 0;
};

const uint8_t JPEG_EOF[] = {0xFF, 0xD9};
const uint8_t PNG_EOF[] = {'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82};
const uint8_t GIF_EOF[] = {0x3B};
const uint8_t PDF_EOF[] = {'%', '%', 'E', 'O', 'F'};
const uint8_t ZIP_EOF[] = {'P', 'K', 0x05, 0x06};
const uint8_t MPEG_PS_EOF[] = {0x00, 0x00, 0x01, 0xB9};
const uint8_t ASF_GUID[] = {0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
                            0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C};

struct Match {
    const char *ext = "bin";
    size_t headerLen = 0;
    const uint8_t *footer = nullptr;
    size_t footerLen = 0;
    uint64_t limit = DEFAULT_LIMIT;
    uint64_t declared = 0;
    bool boxChain = false;  // ISO-BMFF (MP4/MOV/3GP): length comes from the box chain
};

bool eq(const uint8_t *p, size_t n, const char *s, size_t len) {
    return n >= len && std::memcmp(p, s, len) == 0;
}

uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

bool matchAt(const uint8_t *p, size_t n, Match &m) {
    m = Match{};
    if (n < 2) return false;

    if (n >= 8 && p[4] == 'f' && p[5] == 't' && p[6] == 'y' && p[7] == 'p') {
        const uint8_t *brand = p + 8;
        const size_t brandLen = (n >= 12) ? 4 : 0;
        m.ext = "mp4";
        if (brandLen == 4) {
            if (eq(brand, brandLen, "qt  ", 4)) m.ext = "mov";
            else if (brand[0] == '3' && brand[1] == 'g' &&
                     (brand[2] == 'p' || brand[2] == '2')) m.ext = "3gp";
            else if (eq(brand, brandLen, "heic", 4) || eq(brand, brandLen, "heix", 4) ||
                     eq(brand, brandLen, "hevc", 4) || eq(brand, brandLen, "hevx", 4) ||
                     eq(brand, brandLen, "heim", 4) || eq(brand, brandLen, "heis", 4) ||
                     eq(brand, brandLen, "hevm", 4) || eq(brand, brandLen, "hevs", 4))
                m.ext = "heic";
            else if (eq(brand, brandLen, "mif1", 4) || eq(brand, brandLen, "msf1", 4))
                m.ext = "heif";
            else if (eq(brand, brandLen, "avif", 4) || eq(brand, brandLen, "avis", 4))
                m.ext = "avif";
            else if (eq(brand, brandLen, "crx ", 4))
                m.ext = "cr3";
        }
        m.headerLen = 8;
        m.boxChain = true;
        m.limit = VIDEO_LIMIT;
        return true;
    }

    switch (p[0]) {
        case 0xFF:
            if (n >= 3 && p[1] == 0xD8 && p[2] == 0xFF) {
                m.ext = "jpg";
                m.headerLen = 3;
                m.footer = JPEG_EOF;
                m.footerLen = sizeof(JPEG_EOF);
                m.limit = JPEG_LIMIT;
                return true;
            }
            if (p[1] == 0xFB || p[1] == 0xF3 || p[1] == 0xF2) {
                m.ext = "mp3";
                m.headerLen = 2;
                return true;
            }
            break;
        case 0x89:
            if (eq(p + 1, n - 1, "PNG\r\n\x1A\n", 7)) {
                m.ext = "png";
                m.headerLen = 8;
                m.footer = PNG_EOF;
                m.footerLen = sizeof(PNG_EOF);
                m.limit = JPEG_LIMIT;
                return true;
            }
            break;
        case '%':
            if (eq(p, n, "%PDF-", 5)) {
                m.ext = "pdf";
                m.headerLen = 5;
                m.footer = PDF_EOF;
                m.footerLen = sizeof(PDF_EOF);
                m.limit = ZIP_LIMIT;
                return true;
            }
            break;
        case 'P':
            if (p[1] == 'K' && n >= 4) {
                if (p[2] == 0x03 && p[3] == 0x04) {
                    m.ext = "zip";
                    m.headerLen = 4;
                    m.footer = ZIP_EOF;
                    m.footerLen = sizeof(ZIP_EOF);
                    m.limit = ZIP_LIMIT;
                    return true;
                }
                if (p[2] == 0x05 && p[3] == 0x06) {
                    m.ext = "zip";
                    m.headerLen = 4;
                    m.footer = ZIP_EOF;
                    m.footerLen = sizeof(ZIP_EOF);
                    m.limit = ZIP_LIMIT;
                    m.declared = 22;
                    return true;
                }
                if (p[2] == 0x01 || p[2] == 0x06 || p[2] == 0x07) {
                    m.ext = "zip";
                    m.headerLen = 2;
                    m.footer = ZIP_EOF;
                    m.footerLen = sizeof(ZIP_EOF);
                    m.limit = ZIP_LIMIT;
                    return true;
                }
            }
            break;
        case 'B':
            if (p[1] == 'M') {
                m.ext = "bmp";
                m.headerLen = 2;
                if (n >= 6) m.declared = le32(p + 2);
                return true;
            }
            break;
        case 'I':
            if (n >= 4 && p[1] == 'I' && p[2] == '*' && p[3] == 0) {
                m.ext = "tif";
                m.headerLen = 4;
                return true;
            }
            break;
        case 'M':
            if (n >= 4 && p[1] == 'M' && p[2] == 0 && p[3] == '*') {
                m.ext = "tif";
                m.headerLen = 4;
                return true;
            }
            break;
        case 'G':
            if (n >= 6 && eq(p, n, "GIF8", 4) && (p[4] == '7' || p[4] == '9') &&
                p[5] == 'a') {
                m.ext = "gif";
                m.headerLen = 6;
                m.footer = GIF_EOF;
                m.footerLen = sizeof(GIF_EOF);
                m.limit = JPEG_LIMIT;
                return true;
            }
            break;
        case 'f':
            if (eq(p, n, "fLaC", 4)) {
                m.ext = "flac";
                m.headerLen = 4;
                return true;
            }
            break;
        case 'O':
            if (eq(p, n, "OggS", 4)) {
                m.ext = "ogg";
                m.headerLen = 4;
                return true;
            }
            break;
        case 'R':
            if (n >= 12 && eq(p, n, "RIFF", 4)) {
                m.ext = eq(p + 8, n - 8, "WAVE", 4) ? "wav"
                        : eq(p + 8, n - 8, "AVI ", 4) ? "avi"
                                                      : "riff";
                m.headerLen = 12;
                m.declared = static_cast<uint64_t>(le32(p + 4)) + 8u;
                return true;
            }
            if (eq(p, n, "Rar!\x1A\x07\x00", 7)) {
                m.ext = "rar";
                m.headerLen = 7;
                return true;
            }
            break;
        case '7':
            if (eq(p, n, "7z\xBC\xAF\x27\x1C", 6)) {
                m.ext = "7z";
                m.headerLen = 6;
                return true;
            }
            break;
        case 0x1F:
            if (n >= 3 && p[1] == 0x8B && p[2] == 0x08) {
                m.ext = "gz";
                m.headerLen = 3;
                return true;
            }
            break;
        case 0x7F:
            if (eq(p + 1, n - 1, "ELF", 3)) {
                m.ext = "elf";
                m.headerLen = 4;
                return true;
            }
            break;
        case 'S':
            if (eq(p, n, "SQLite format 3\0", 16)) {
                m.ext = "sqlite";
                m.headerLen = 16;
                return true;
            }
            break;
        case 0x1A:
            if (n >= 4 && p[1] == 0x45 && p[2] == 0xDF && p[3] == 0xA3) {
                m.ext = "mkv";
                for (size_t k = 4; k + 4 <= n && k < 512; ++k) {
                    if (eq(p + k, n - k, "webm", 4)) {
                        m.ext = "webm";
                        break;
                    }
                }
                m.headerLen = 4;
                m.limit = VIDEO_LIMIT;
                return true;
            }
            break;
        case 'F':
            if (n >= 4 && eq(p, n, "FLV\x01", 4)) {
                m.ext = "flv";
                m.headerLen = 4;
                m.limit = VIDEO_LIMIT;
                return true;
            }
            break;
        case 0x30:
            if (n >= sizeof(ASF_GUID) && std::memcmp(p, ASF_GUID, sizeof(ASF_GUID)) == 0) {
                m.ext = "wmv";
                m.headerLen = sizeof(ASF_GUID);
                m.limit = VIDEO_LIMIT;
                return true;
            }
            break;
        case 0x00:
            if (n >= 4 && p[1] == 0x00 && p[2] == 0x01 && p[3] == 0xBA) {
                m.ext = "mpg";
                m.headerLen = 4;
                m.footer = MPEG_PS_EOF;
                m.footerLen = sizeof(MPEG_PS_EOF);
                m.limit = VIDEO_LIMIT;
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

uint64_t cappedAdd(uint64_t base, uint64_t delta, uint64_t ceiling) {
    return delta >= ceiling - base ? ceiling : base + delta;
}

auto rangeAfter = [](uint64_t value, const Range &r) { return value < r.begin; };
auto rangeBefore = [](const Range &r, uint64_t value) { return r.begin < value; };

uint64_t coveringEnd(const std::vector<Range> &v, uint64_t pos) {
    auto it = std::upper_bound(v.begin(), v.end(), pos, rangeAfter);
    if (it == v.begin()) return 0;
    --it;
    return pos < it->end ? it->end : 0;
}

uint64_t nextCoveredStart(const std::vector<Range> &v, uint64_t pos) {
    auto it = std::upper_bound(v.begin(), v.end(), pos, rangeAfter);
    return it == v.end() ? std::numeric_limits<uint64_t>::max() : it->begin;
}

void addCovered(std::vector<Range> &v, const Range &r) {
    // Carving walks positions monotonically, so the common case is appending a
    // non-overlapping range at the end. Keep it O(1); fall back to a sorted
    // insert only if a range ever arrives out of order.
    if (!v.empty() && r.begin >= v.back().begin) {
        if (r.begin <= v.back().end && r.end > v.back().end)
            v.back().end = r.end;
        else if (r.begin > v.back().end)
            v.push_back(r);
        return;
    }
    auto it = std::lower_bound(v.begin(), v.end(), r.begin, rangeBefore);
    v.insert(it, r);
}

std::string hexBytes(const uint8_t *p, size_t n) {
    static const char digits[] = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) s.push_back(' ');
        s.push_back(digits[p[i] >> 4]);
        s.push_back(digits[p[i] & 0x0F]);
    }
    return s;
}

static inline bool sigCandidate(uint8_t c) {
    switch (c) {
        case 0x00: case 0xFF: case 0x89: case 0x25: case 0x50: case 0x42: case 0x49:
        case 0x4D: case 0x47: case 0x66: case 0x4F: case 0x52: case 0x37: case 0x1F:
        case 0x7F: case 0x53: case 0x1A: case 0x46: case 0x30:
            return true;
        default:
            return false;
    }
}

bool findFooter(const ScanContext &ctx, uint64_t start, uint64_t limitEnd,
                const uint8_t *pat, size_t patLen, std::vector<uint8_t> &scratch,
                uint64_t &foundAt) {
    if (pat == nullptr || patLen == 0 || start >= limitEnd) return false;
    uint64_t pos = start;
    while (pos < limitEnd) {
        if (ctx.cancelledNow()) return false;
        const size_t want = static_cast<size_t>(std::min<uint64_t>(BLOCK_SIZE, limitEnd - pos));
        const size_t extra = static_cast<size_t>(
            std::min<uint64_t>(patLen - 1, limitEnd - pos - want));
        const int64_t got = ctx.reader.readAt(pos, scratch.data(), want + extra);
        if (got <= 0) return false;
        const size_t n = static_cast<size_t>(got);
        if (n >= patLen) {
            const uint8_t *first = scratch.data();
            const uint8_t *last = first + (n - patLen + 1);
            const uint8_t *hit = std::search(first, last, pat, pat + patLen);
            if (hit != last) {
                foundAt = pos + static_cast<uint64_t>(hit - first);
                return true;
            }
        }
        pos += want;
    }
    return false;
}

bool findNextHeader(const ScanContext &ctx, uint64_t start, uint64_t limitEnd,
                    std::vector<uint8_t> &scratch, uint64_t &foundAt) {
    if (start >= limitEnd) return false;
    uint64_t pos = start;
    while (pos < limitEnd) {
        if (ctx.cancelledNow()) return false;
        const size_t want = static_cast<size_t>(std::min<uint64_t>(BLOCK_SIZE, limitEnd - pos));
        const size_t extra = static_cast<size_t>(
            std::min<uint64_t>(MAX_HEADER - 1, limitEnd - pos - want));
        const int64_t got = ctx.reader.readAt(pos, scratch.data(), want + extra);
        if (got <= 0) return false;
        const size_t n = static_cast<size_t>(got);
        for (size_t i = 0; i < n; ++i) {
            Match probe;
            if (matchAt(scratch.data() + i, n - i, probe)) {
                foundAt = pos + i;
                return true;
            }
        }
        pos += want;
    }
    return false;
}

// Walks the top-level ISO-BMFF box chain (ftyp/moov/mdat/...) and returns the
// end offset of the last structurally valid box. The first box size is only the
// size of that box (usually the small ftyp header), not the size of the file.
uint64_t boxChainEnd(const ScanContext &ctx, uint64_t start, uint64_t limitEnd,
                     std::string &boundary) {
    uint64_t pos = start;
    uint32_t boxes = 0;
    bool sawMdat = false;
    while (pos + 8 <= limitEnd && boxes < 100000) {
        if (ctx.cancelledNow()) return 0;
        uint8_t hdr[16];
        if (ctx.reader.readAt(pos, hdr, 8) != 8) break;
        uint64_t boxLen = le32(hdr);
        size_t headerLen = 8;
        if (boxLen == 1) {
            if (pos + 16 > limitEnd) break;
            if (ctx.reader.readAt(pos + 8, hdr + 8, 8) != 8) break;
            boxLen = le64(hdr + 8);
            headerLen = 16;
        }
        // A zero size means "extends to end of file"; the real end is unknown.
        if (boxLen == 0 || boxLen < headerLen || boxLen > limitEnd - pos) break;
        bool printable = true;
        for (size_t k = 4; k < 8; ++k) {
            uint8_t c = hdr[k];
            if (c < 0x20 || c > 0x7E) {
                printable = false;
                break;
            }
        }
        if (!printable) break;
        if (std::memcmp(hdr + 4, "mdat", 4) == 0) sawMdat = true;
        pos += boxLen;
        ++boxes;
    }
    // Without a media-data box this is not a usable video; let the caller fall
    // back to footer / next-signature detection.
    if (!sawMdat) return 0;
    boundary = "ISO-BMFF box chain";
    return pos;
}

} // namespace

void carve(ScanContext &ctx, const std::vector<FileRecord> &known) {
    if (!ctx.options.carveFreeSpace) return;
    const uint64_t total = ctx.reader.size();
    if (total == 0) return;

    std::vector<Range> covered;
    covered.reserve(known.size() + 16);
    for (const FileRecord &rec : known) {
        if (rec.status == Status::Deleted) {
            uint64_t sum = 0;
            for (const ByteRange &b : rec.ranges) sum += b.length;
            if (sum < rec.size) continue;  // partial/stale deleted entry; let carving recover real data
        }
        for (const ByteRange &b : rec.ranges) {
            if (b.length == 0 || b.offset >= total) continue;
            covered.push_back({b.offset, b.offset + std::min<uint64_t>(b.length, total - b.offset)});
        }
    }
    std::sort(covered.begin(), covered.end(),
              [](const Range &a, const Range &b) { return a.begin < b.begin; });
    std::vector<Range> merged;
    merged.reserve(covered.size());
    for (const Range &r : covered) {
        if (!merged.empty() && r.begin <= merged.back().end)
            merged.back().end = std::max(merged.back().end, r.end);
        else
            merged.push_back(r);
    }
    covered.swap(merged);

    std::vector<uint8_t> scanBuf(CHUNK_SIZE + OVERLAP);
    std::vector<uint8_t> scratch(BLOCK_SIZE + MAX_HEADER);

    const uint32_t maxFiles = ctx.options.maxCarveFiles;
    const uint64_t byteBudget = ctx.options.maxCarveBytes;
    uint32_t emittedCount = 0;
    uint64_t emittedBytes = 0;
    int lastPct = -1;
    if (ctx.progress) ctx.progress(0, "Carving unallocated space...");

    uint64_t pos = 0;
    while (pos < total) {
        if (ctx.cancelledNow()) break;
        if (emittedCount >= maxFiles) break;
        if (byteBudget > 0 && emittedBytes >= byteBudget) break;

        const size_t want = static_cast<size_t>(
            std::min<uint64_t>(CHUNK_SIZE + OVERLAP, total - pos));
        const int64_t got = ctx.reader.readAt(pos, scanBuf.data(), want);
        if (got <= 0) break;
        const size_t avail = static_cast<size_t>(got);
        const size_t primaryLen = std::min<size_t>(avail, CHUNK_SIZE);
        const uint64_t primaryEnd = pos + primaryLen;

        size_t i = 0;
        while (i < primaryLen) {
            if (ctx.cancelledNow()) break;
            const uint8_t *cursor = scanBuf.data() + i;
            bool tryMatch = sigCandidate(cursor[0]);
            // ftyp is detected by its "ftyp" magic at offset 4, whose leading
            // box-size byte can be anything, so check it explicitly too.
            if (!tryMatch && i + 4 < avail) {
                tryMatch = (cursor[4] == 'f' && cursor[5] == 't' &&
                            cursor[6] == 'y' && cursor[7] == 'p');
            }
            if (!tryMatch) {
                ++i;
                continue;
            }
            Match m;
            if (!matchAt(cursor, avail - i, m)) {
                ++i;
                continue;
            }

            const uint64_t hit = pos + i;
            const uint64_t cover = coveringEnd(covered, hit);
            if (cover != 0) {
                if (cover >= primaryEnd) {
                    i = primaryLen;
                    break;
                }
                i = static_cast<size_t>(cover - pos);
                continue;
            }

            uint64_t limitEnd = cappedAdd(hit, m.limit, total);
            if (byteBudget > 0)
                limitEnd = std::min(limitEnd,
                                    cappedAdd(hit, byteBudget - emittedBytes, total));

            uint64_t end = 0;
            std::string boundary;
            if (m.boxChain) {
                end = boxChainEnd(ctx, hit, limitEnd, boundary);
            }
            if (end == 0 && m.declared > 0 && m.declared >= m.headerLen &&
                m.declared <= limitEnd - hit) {
                end = hit + m.declared;
                boundary = "header size field";
            }
            if (end == 0 && m.footer != nullptr) {
                uint64_t found = 0;
                if (findFooter(ctx, hit + m.headerLen, limitEnd, m.footer, m.footerLen,
                               scratch, found)) {
                    end = cappedAdd(found, m.footerLen, limitEnd);
                    boundary = "footer '" + hexBytes(m.footer, m.footerLen) + "'";
                }
            }
            if (end == 0) {
                uint64_t found = 0;
                if (findNextHeader(ctx, hit + m.headerLen,
                                   cappedAdd(hit, NEXT_HEADER_LIMIT, limitEnd),
                                   scratch, found) &&
                    found > hit) {
                    end = found;
                    boundary = "next signature";
                } else {
                    end = cappedAdd(hit, DEFAULT_LIMIT, limitEnd);
                    boundary = "default size cap";
                }
            }

            const uint64_t nextKnown = nextCoveredStart(covered, hit);
            if (end > nextKnown) end = nextKnown;
            if (end <= hit + m.headerLen) {
                i += std::max<size_t>(m.headerLen, 1);
                continue;
            }

            FileRecord rec;
            rec.id = FIRST_ID + emittedCount;
            char name[64];
            std::snprintf(name, sizeof(name), "carved_%08llX_%s",
                          static_cast<unsigned long long>(hit), m.ext);
            rec.name = name;
            rec.size = end - hit;
            rec.status = Status::Carved;
            rec.chance = Chance::Low;
            rec.fs = FsKind::WholeDisk;
            rec.type = typeFromName(rec.name);
            rec.ranges.push_back({hit, rec.size});
            rec.why = "Signature match only; file boundaries guessed from " + boundary +
                      " - verify manually";
            rec.inode = hit;
            if (ctx.result) ctx.result(rec);

            ++ctx.stats.carvedFound;
            ++emittedCount;
            emittedBytes = emittedBytes > std::numeric_limits<uint64_t>::max() - rec.size
                               ? std::numeric_limits<uint64_t>::max()
                               : emittedBytes + rec.size;
            addCovered(covered, {hit, end});

            i += std::max<size_t>(m.headerLen, 1);
            if (emittedCount >= maxFiles) break;
            if (byteBudget > 0 && emittedBytes >= byteBudget) break;
        }

        pos = (total - pos > CHUNK_SIZE) ? pos + CHUNK_SIZE : total;
        const int pct = std::min(100, static_cast<int>(
            (static_cast<double>(pos) / static_cast<double>(total)) * 100.0));
        if (pct != lastPct) {
            if (ctx.progress) ctx.progress(pct, "Carving unallocated space...");
            lastPct = pct;
        }
    }
}

} // namespace dd
