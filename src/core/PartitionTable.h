#pragma once
#include "Types.h"
#include "RawReader.h"
#include <vector>

namespace dd {

// Detects MBR/GPT partition tables and filesystems. If no partition table is
// present the whole device is returned as one partition.
std::vector<Partition> readPartitions(const RawReader &r);

// Probes a filesystem signature at an absolute byte offset.
FsKind probeFs(const RawReader &r, uint64_t offset, std::string *label = nullptr);

// True if the source looks like it has a protective GPT at LBA1.
bool hasGPT(const RawReader &r);

} // namespace dd
