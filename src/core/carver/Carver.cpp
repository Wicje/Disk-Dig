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

constexpr size_t CHUNK_SIZE = 4u * 1024u * 1024u;
constexpr size_t OVERLAP = 64u * 1024u;
constexpr size_t BLOCK_SIZE = 256u * 1024u;
constexpr size_t MAX_HEADER = 16u;
constexpr uint64_t JPEG_LIMIT = 32u * 1024u * 1024u;
constexpr uint64_t ZIP_LIMIT = 64u * 1024u * 1024u;
constexpr uint64_t DEFAULT_LIMIT = 16u * 1024u * 1024u;
constexpr uint64_t NEXT_HEADER_LIMIT = 64u * 1024u * 1024u;
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

struct Match {
    const char *ext = "bin";
    size_t headerLen = 0;
    const uint8_t *footer = nullptr;
    size_t footerLen = 0;
    uint64_t limit = DEFAULT_LIMIT;
    uint64_t declared = 0;
};

bool eq(const uint8_t *p, size_t n, const char *s, size_t len) {
    return n >= len && std::memcmp(p, s, len) == 0;
}

uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

bool matchAt(const uint8_t *p, size_t n, Match &m) {
    m = Match{};
    if (n < 2) return false;

    if (n >= 8 && p[4] == 'f' && p[5] == 't' && p[6] == 'y' && p[7] == 'p') {
        m.ext = (n >= 12 && eq(p + 8, n - 8, "qt  ", 4)) ? "mov"
                : (n >= 11 && p[8] == '3' && p[9] == 'g' && p[10] == 'p') ? "3gp"
                                                                          : "mp4";
        m.headerLen = 8;
        m.declared = le32(p);
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

} // namespace

void carve(ScanContext &ctx, const std::vector<FileRecord> &known) {
    if (!ctx.options.carveFreeSpace) return;
    const uint64_t total = ctx.reader.size();
    if (total == 0) return;

    std::vector<Range> covered;
    covered.reserve(known.size() + 16);
    for (const FileRecord &rec : known) {
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
            Match m;
            if (!matchAt(scanBuf.data() + i, avail - i, m)) {
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
            if (m.declared > 0 && m.declared >= m.headerLen && m.declared <= limitEnd - hit) {
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
