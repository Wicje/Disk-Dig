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

// Persist a completed scan to a user cache so re-scanning the same source is
// avoided. The cache is invalidated when the source size changes.
bool loadScanCache(const std::string &source, uint64_t sourceSize,
                   std::vector<FileRecord> &outRecords, ScanStats &outStats);
bool saveScanCache(const std::string &source, uint64_t sourceSize,
                   const std::vector<FileRecord> &records,
                   const ScanStats &stats);

} // namespace dd
