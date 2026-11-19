#pragma once
#include "Types.h"
#include "RawReader.h"
#include <atomic>
#include <string>
#include <vector>

namespace dd {

struct ScanSession {
    RawReader reader;
    std::vector<FileRecord> records;
    std::vector<std::string> partitions;
    ScanStats stats{};
    std::string error;
    std::atomic<bool> cancelled{false};
    volatile bool cancelledFlag = false;
};

// Opens the source once, detects partitions, scans each filesystem, then carves.
// `progress` is called from the calling thread; run this in a worker thread.
void runScan(ScanSession &session, const std::string &path,
             const ScanOptions &options, ProgressFn progress, ResultFn result);

} // namespace dd
