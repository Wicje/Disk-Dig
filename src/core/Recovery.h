#pragma once
#include "Types.h"
#include "RawReader.h"
#include <functional>
#include <string>
#include <vector>

namespace dd {

struct RecoverySummary {
    uint32_t succeeded = 0;
    uint32_t failed = 0;
    uint64_t bytesWritten = 0;
    std::string reportPath;
    std::vector<std::string> errors;
};

// Copies the byte ranges of each selected record into targetDir. Never writes
// to the source device. Prefixes with status to avoid collisions, writes a
// CSV report. Returns false only for fatal setup errors.
bool recoverFiles(const RawReader &source,
                  const std::vector<const FileRecord *> &files,
                  const std::string &targetDir,
                  RecoverySummary &summary,
                  std::function<void(int percent, const std::string &phase)> progress,
                  const volatile bool *cancelled = nullptr);

} // namespace dd
