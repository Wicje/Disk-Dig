#include "PartitionTable.h"
#include <cstring>

namespace dd {
namespace {

bool hasMBRSignature(const RawReader &r) {
    return r.u16(510, nullptr) == 0xAA55;
}

} // namespace

bool hasGPT(const RawReader &r) {
    char magic[8]{};
    return r.readExact(512, magic, 8) && std::memcmp(magic, "EFI PART", 8) == 0;
}

FsKind probeFs(const RawReader &r, uint64_t off, std::string *label) {
    char sig[16]{};
    if (r.readExact(off + 1024 + 56, sig, 2) &&
        static_cast<unsigned char>(sig[0]) == 0x53 &&
        static_cast<unsigned char>(sig[1]) == 0xEF)
        return FsKind::Ext;
    if (r.readExact(off + 3, sig, 8) && std::memcmp(sig, "NTFS    ", 8) == 0)
        return FsKind::Ntfs;
    if (r.readExact(off + 82, sig, 8) && std::memcmp(sig, "FAT32   ", 8) == 0)
        return FsKind::Fat;
    if (r.readExact(off + 54, sig, 8) && std::memcmp(sig, "FAT16   ", 8) == 0)
        return FsKind::Fat;
    if (r.readExact(off + 3, sig, 8) && std::memcmp(sig, "EXFAT   ", 8) == 0)
        return FsKind::Fat;
    if (label && r.readExact(off + 1024 + 120, sig, 16)) {
        std::string s(sig, 16);
        if (s[0]) *label = s;
    }
    return FsKind::Unknown;
}

std::vector<Partition> readPartitions(const RawReader &r) {
    std::vector<Partition> parts;
    if (!r.isOpen() || r.size() < 1024) return parts;

    if (hasGPT(r)) {
        uint32_t entrySize = r.u32(512 + 84, nullptr);
        uint64_t lba1 = r.u64(512 + 72, nullptr);
        if (entrySize < 128) entrySize = 128;
        uint64_t entriesLba = lba1 ? lba1 : 2;
        uint64_t tableOff = entriesLba * 512;
        for (uint32_t i = 0; i < 128; ++i) {
            uint64_t e = tableOff + static_cast<uint64_t>(i) * entrySize;
            char typeGuid[16]{};
            if (!r.readExact(e, typeGuid, 16)) break;
            bool zero = true;
            for (char c : typeGuid) if (c) { zero = false; break; }
            if (zero) continue;
            uint64_t start = r.u64(e + 32, nullptr);
            uint64_t end = r.u64(e + 40, nullptr);
            if (end < start) continue;
            Partition p;
            p.start = start * 512;
            p.length = (end - start + 1) * 512;
            p.number = i + 1;
            p.fs = probeFs(r, p.start, &p.fsLabel);
            p.description = p.fs == FsKind::Unknown ? "Unknown partition" :
                            (p.fs == FsKind::Ext ? "Linux filesystem" :
                             p.fs == FsKind::Fat ? "FAT filesystem" : "NTFS partition");
            parts.push_back(p);
        }
        if (!parts.empty()) return parts;
    }

    if (hasMBRSignature(r)) {
        for (int i = 0; i < 4; ++i) {
            uint64_t e = 446 + static_cast<uint64_t>(i) * 16;
            uint8_t type = r.u8(e + 4, nullptr);
            if (!type || type == 0xEE) continue;
            uint32_t startSec = r.u32(e + 8, nullptr);
            uint32_t countSec = r.u32(e + 12, nullptr);
            if (!countSec || startSec == 0) continue;
            uint64_t start = static_cast<uint64_t>(startSec) * 512;
            uint64_t length = static_cast<uint64_t>(countSec) * 512;
            if (start + length > r.size()) length = r.size() - start;
            Partition p;
            p.start = start;
            p.length = length;
            p.number = static_cast<uint32_t>(i + 1);
            p.type = type;
            p.fs = probeFs(r, p.start, &p.fsLabel);
            if (p.fs == FsKind::Unknown && (type == 0x83 || type == 0x07 || type == 0x0b || type == 0x0c))
                p.fs = type == 0x07 ? FsKind::Ntfs : FsKind::Ext;
            p.description = p.fs == FsKind::Ext ? "Linux filesystem" :
                            p.fs == FsKind::Fat ? "FAT filesystem" :
                            p.fs == FsKind::Ntfs ? "NTFS partition" : "MBR partition";
            parts.push_back(p);
        }
        if (!parts.empty()) return parts;
    }

    Partition whole;
    whole.number = 0;
    whole.start = 0;
    whole.length = r.size();
    whole.fs = probeFs(r, 0, &whole.fsLabel);
    whole.description = whole.fs == FsKind::Unknown ? "Unformatted space" : "Whole device";
    parts.push_back(whole);
    return parts;
}

} // namespace dd
