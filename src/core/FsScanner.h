#pragma once
#include "Types.h"
#include "RawReader.h"

namespace dd {

struct ScanContext {
    const RawReader &reader;
    uint64_t partitionStart;
    uint64_t partitionLength;
    const ScanOptions &options;
    ProgressFn progress;
    ResultFn result;
    ScanStats &stats;
    const volatile bool *cancelled = nullptr;

    bool cancelledNow() const { return cancelled && *cancelled; }
};

void scanExt4(ScanContext &ctx);
void scanFat32(ScanContext &ctx);
void scanExfat(ScanContext &ctx);
void scanNtfs(ScanContext &ctx);

// Signature-based carving of unallocated space, deduplicated against files
// already found through filesystem metadata.
void carve(ScanContext &ctx, const std::vector<FileRecord> &known);

} // namespace dd
