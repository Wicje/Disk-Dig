#include "Scanner.h"
#include "FsScanner.h"
#include "PartitionTable.h"
#include <algorithm>

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
            carve(ctx, session.records);
        }
    }
    if (progress) progress(100, "Scan complete");
}

} // namespace dd
