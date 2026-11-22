#include "Scanner.h"
#include "FsScanner.h"
#include "PartitionTable.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sys/stat.h>

namespace dd {

void runScan(ScanSession &session, const std::string &path,
             const ScanOptions &options, ProgressFn progress, ResultFn result) {
    session.records.clear();
    session.partitions.clear();
    session.stats = ScanStats{};
    session.error.clear();

    if (!session.reader.open(path, &session.error)) {
        if (progress) progress(100, session.error);
        return;
    }
    session.stats.total = session.reader.size();
    session.cancelledFlag = false;
    session.cancelled.store(false);

    auto parts = readPartitions(session.reader);
    for (const auto &p : parts)
        session.partitions.push_back(p.description + " | " + fsName(p.fs) +
            (p.fsLabel.empty() ? "" : " " + p.fsLabel) + " | " + formatBytes(p.length) +
            " @ " + formatBytes(p.start));

    uint32_t nextId = 1;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (session.cancelledFlag) break;
        const Partition &p = parts[i];
        ScanContext ctx{session.reader, p.start, p.length, options, progress, result,
                        session.stats, &session.cancelledFlag};
        auto collecting = [&](const FileRecord &rec) {
            FileRecord copy = rec;
            if (copy.id == 0) copy.id = nextId++;
            else if (copy.id >= nextId) nextId = copy.id + 1;
            session.records.push_back(copy);
            if (result) result(copy);
        };
        ctx.result = collecting;
        int pct = static_cast<int>(5 + (i * 75) / std::max<size_t>(1, parts.size()));
        if (progress) progress(pct, "Scanning " + p.description);
        switch (p.fs) {
            case FsKind::Ext: scanExt4(ctx); break;
            case FsKind::Fat: scanFat32(ctx); break;
            case FsKind::ExFat: scanExfat(ctx); break;
            case FsKind::Ntfs: scanNtfs(ctx); break;
            default: break;
        }
    }

    // Only fully-mapped records are excluded from signature carving. Incomplete
    // deleted entries (zero or partial ranges) are left uncovered so carving can
    // re-discover their real data by signature and recover complete files.
    std::vector<FileRecord> carveKnown;
    if (options.carveFreeSpace && !session.records.empty()) {
        carveKnown.reserve(session.records.size());
        for (const FileRecord &r : session.records) {
            if (r.status == Status::Existing) {
                carveKnown.push_back(r);
                continue;
            }
            if (r.status == Status::Deleted && r.size > 0) {
                uint64_t sum = 0;
                for (const ByteRange &b : r.ranges) sum += b.length;
                if (sum >= r.size) carveKnown.push_back(r);
            }
        }
    }

    if (!session.cancelledFlag && options.carveFreeSpace) {
        if (progress) progress(82, "Carving unallocated space (signatures)...");
        for (const auto &p : parts) {
            if (session.cancelledFlag) break;
            ScanContext ctx{session.reader, p.start, p.length, options, progress, result,
                            session.stats, &session.cancelledFlag};
            auto collecting = [&](const FileRecord &rec) {
                FileRecord copy = rec;
                copy.id = nextId++;
                session.records.push_back(copy);
                if (result) result(copy);
            };
            ctx.result = collecting;
            carve(ctx, carveKnown);
        }
    }
    if (progress) progress(100, "Scan complete");
}

namespace {
std::string cacheDir() {
    const char *home = std::getenv("HOME");
    std::string base = home ? home : ".";
    base += "/.cache/diskdig";
    ::mkdir(base.c_str(), 0700);
    return base;
}

static std::string fnvHex(const std::string &s) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return buf;
}

static std::string esc(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back((c == '|' || c == '\n' || c == '\r') ? ' ' : c);
    return out;
}

static std::string cacheFile(const std::string &source, uint64_t sourceSize) {
    return cacheDir() + "/" + fnvHex(source) + "_" + std::to_string(sourceSize) + ".cache";
}

static std::vector<std::string> splitPipe(const std::string &line) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= line.size(); ++i) {
        if (i == line.size() || line[i] == '|') {
            out.push_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

static uint64_t toU64(const std::string &s, uint64_t def = 0) {
    try { return std::stoull(s); } catch (...) { return def; }
}

static int toInt(const std::string &s, int def = 0) {
    try { return std::stoi(s); } catch (...) { return def;
    }
}
} // namespace

bool loadScanCache(const std::string &source, uint64_t sourceSize,
                   std::vector<FileRecord> &outRecords, ScanStats &outStats) {
    outRecords.clear();
    outStats = ScanStats{};
    std::ifstream in(cacheFile(source, sourceSize));
    if (!in) return false;
    std::string line;
    if (!std::getline(in, line) || line != "DISKDIGCACHE1") return false;
    uint64_t cachedSize = 0, scanned = 0, total = 0, count = 0;
    uint64_t extFound = 0, fatFound = 0, exfatFound = 0, ntfsFound = 0;
    uint64_t carvedFound = 0, existingFound = 0;
    while (std::getline(in, line)) {
        if (line.rfind("source_size ", 0) == 0) cachedSize = toU64(line.substr(12));
        else if (line.rfind("scanned ", 0) == 0) scanned = toU64(line.substr(8));
        else if (line.rfind("total ", 0) == 0) total = toU64(line.substr(6));
        else if (line.rfind("extFound ", 0) == 0) extFound = toU64(line.substr(9));
        else if (line.rfind("fatFound ", 0) == 0) fatFound = toU64(line.substr(9));
        else if (line.rfind("exfatFound ", 0) == 0) exfatFound = toU64(line.substr(11));
        else if (line.rfind("ntfsFound ", 0) == 0) ntfsFound = toU64(line.substr(10));
        else if (line.rfind("carvedFound ", 0) == 0) carvedFound = toU64(line.substr(12));
        else if (line.rfind("existingFound ", 0) == 0) existingFound = toU64(line.substr(14));
        else if (line.rfind("count ", 0) == 0) { count = toU64(line.substr(6)); break; }
    }
    if (cachedSize != sourceSize) return false;
    outStats.scanned = scanned; outStats.total = total;
    outStats.extFound = (uint32_t)extFound; outStats.fatFound = (uint32_t)fatFound;
    outStats.exfatFound = (uint32_t)exfatFound; outStats.ntfsFound = (uint32_t)ntfsFound;
    outStats.carvedFound = (uint32_t)carvedFound; outStats.existingFound = (uint32_t)existingFound;
    outRecords.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        if (!std::getline(in, line)) return false;
        auto f = splitPipe(line);
        if (f.size() < 11) return false;
        FileRecord r;
        r.id = toU64(f[0]);
        r.status = static_cast<Status>(toInt(f[1]));
        r.chance = static_cast<Chance>(toInt(f[2]));
        r.size = toU64(f[3]);
        r.fs = static_cast<FsKind>(toInt(f[4]));
        r.type = f[5];
        r.modified = toU64(f[6]);
        r.why = f[7];
        r.path = f[8];
        r.name = f[9];
        // f[10] holds ranges as "off1:len1;off2:len2"
        size_t rs = 0;
        while (rs <= f[10].size()) {
            size_t re = f[10].find(';', rs);
            if (re == std::string::npos) re = f[10].size();
            std::string rg = f[10].substr(rs, re - rs);
            if (!rg.empty()) {
                size_t colon = rg.find(':');
                if (colon != std::string::npos) {
                    ByteRange b;
                    b.offset = toU64(rg.substr(0, colon));
                    b.length = toU64(rg.substr(colon + 1));
                    r.ranges.push_back(b);
                }
            }
            if (re == f[10].size()) break;
            rs = re + 1;
        }
        outRecords.push_back(std::move(r));
    }
    return true;
}

bool saveScanCache(const std::string &source, uint64_t sourceSize,
                   const std::vector<FileRecord> &records,
                   const ScanStats &stats) {
    std::string file = cacheFile(source, sourceSize);
    std::ofstream out(file);
    if (!out) return false;
    out << "DISKDIGCACHE1\n";
    out << "source_size " << sourceSize << "\n";
    out << "scanned " << stats.scanned << "\n";
    out << "total " << stats.total << "\n";
    out << "extFound " << stats.extFound << "\n";
    out << "fatFound " << stats.fatFound << "\n";
    out << "exfatFound " << stats.exfatFound << "\n";
    out << "ntfsFound " << stats.ntfsFound << "\n";
    out << "carvedFound " << stats.carvedFound << "\n";
    out << "existingFound " << stats.existingFound << "\n";
    out << "count " << records.size() << "\n";
    for (const FileRecord &r : records) {
        out << r.id << "|" << static_cast<int>(r.status) << "|"
            << static_cast<int>(r.chance) << "|" << r.size << "|"
            << static_cast<int>(r.fs) << "|" << esc(r.type) << "|"
            << r.modified << "|" << esc(r.why) << "|"
            << esc(r.path) << "|" << esc(r.name) << "|";
        for (size_t i = 0; i < r.ranges.size(); ++i) {
            out << r.ranges[i].offset << ":" << r.ranges[i].length;
            if (i + 1 < r.ranges.size()) out << ";";
        }
        out << "\n";
    }
    return out.good();
}

} // namespace dd
