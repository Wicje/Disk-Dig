#include "PartitionTable.h"
#include <cstring>

namespace dd {
namespace {

bool hasMBRSignature(const RawReader &r) {
    return r.u16(510, nullptr) == 0xAA55;
}

bool isPow2(uint32_t v) {
    return v && ((v & (v - 1)) == 0);
}

FsKind probeFat(const RawReader &r, uint64_t off) {
    bool ok = false;
    uint16_t bytesPerSector = r.u16(off + 11, &ok); if (!ok) return FsKind::Unknown;
    uint8_t sectorsPerCluster = r.u8(off + 13, &ok); if (!ok) return FsKind::Unknown;
    uint16_t reservedSectors = r.u16(off + 14, &ok); if (!ok) return FsKind::Unknown;
    uint8_t numFATs = r.u8(off + 16, &ok); if (!ok) return FsKind::Unknown;
    uint16_t rootEntries = r.u16(off + 17, &ok); if (!ok) return FsKind::Unknown;
    uint16_t totalSec16 = r.u16(off + 19, &ok); if (!ok) return FsKind::Unknown;
    uint16_t fatSize16 = r.u16(off + 22, &ok); if (!ok) return FsKind::Unknown;
    uint32_t totalSec32 = r.u32(off + 32, &ok); if (!ok) return FsKind::Unknown;
    uint32_t fatSize32 = r.u32(off + 36, &ok); if (!ok) return FsKind::Unknown;

    if (bytesPerSector < 512 || bytesPerSector > 4096 || !isPow2(bytesPerSector)) return FsKind::Unknown;
    if (sectorsPerCluster == 0 || sectorsPerCluster > 128 || numFATs == 0) return FsKind::Unknown;

    uint64_t fatSectors = fatSize32 ? fatSize32 : fatSize16;
    uint64_t totalSectors = totalSec16 ? totalSec16 : totalSec32;
    if (fatSectors == 0 || totalSectors == 0) return FsKind::Unknown;

    uint64_t rootDirSectors = ((static_cast<uint64_t>(rootEntries) * 32 + bytesPerSector - 1) /
                               bytesPerSector);
    uint64_t overhead = static_cast<uint64_t>(reservedSectors) +
                        static_cast<uint64_t>(numFATs) * fatSectors + rootDirSectors;
    if (overhead >= totalSectors) return FsKind::Unknown;
    uint64_t clusterCount = (totalSectors - overhead) / sectorsPerCluster;
    if (clusterCount < 1) return FsKind::Unknown;

    char sig[8]{};
    bool hasFat32Sig = r.readExact(off + 82, sig, 8) && std::memcmp(sig, "FAT32   ", 8) == 0;
    bool hasFat16Sig = r.readExact(off + 54, sig, 8) && std::memcmp(sig, "FAT16   ", 8) == 0;
    if (hasFat32Sig || (rootEntries == 0 && clusterCount >= 65525)) return FsKind::Fat;
    if (hasFat16Sig || (rootEntries > 0 && clusterCount >= 4085 && clusterCount < 65525))
        return FsKind::Fat;
    return FsKind::Unknown;
}

bool probeExfat(const RawReader &r, uint64_t off) {
    bool ok = false;
    uint8_t sectorShift = r.u8(off + 0x6C, &ok); if (!ok) return false;
    uint8_t clusterShift = r.u8(off + 0x6D, &ok); if (!ok) return false;
    uint8_t numFATs = r.u8(off + 0x6E, &ok); if (!ok) return false;
    uint32_t fatOffset = r.u32(off + 0x50, &ok); if (!ok) return false;
    uint32_t fatLength = r.u32(off + 0x54, &ok); if (!ok) return false;
    uint32_t heapOffset = r.u32(off + 0x58, &ok); if (!ok) return false;
    uint32_t clusterCount = r.u32(off + 0x5C, &ok); if (!ok) return false;
    uint32_t rootCluster = r.u32(off + 0x60, &ok); if (!ok) return false;
    if (sectorShift < 9 || sectorShift > 12 || clusterShift > 25 || numFATs == 0) return false;
    if (fatLength == 0 || clusterCount == 0 || heapOffset == 0) return false;
    if (rootCluster < 2 || rootCluster > clusterCount + 1) return false;
    uint64_t bps = uint64_t{1} << sectorShift;
    uint64_t fatEnd = (static_cast<uint64_t>(fatOffset) + static_cast<uint64_t>(fatLength) * numFATs) * bps;
    uint64_t heapStart = static_cast<uint64_t>(heapOffset) * bps;
    if (heapStart < fatEnd && heapStart < r.size()) return false;
    return true;
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
    if (r.readExact(off + 3, sig, 8) && std::memcmp(sig, "EXFAT   ", 8) == 0 &&
        probeExfat(r, off))
        return FsKind::ExFat;
    FsKind fat = probeFat(r, off);
    if (fat != FsKind::Unknown) return fat;
    if (label && r.readExact(off + 1024 + 120, sig, 16)) {
        std::string s(sig, 16);
        if (s[0]) *label = s;
    }
    return FsKind::Unknown;
}

std::vector<Partition> readPartitions(const RawReader &r) {
    std::vector<Partition> parts;
    if (!r.isOpen() || r.size() < 1024) return parts;

    std::string wholeLabel;
    FsKind wholeFs = probeFs(r, 0, &wholeLabel);
    if (wholeFs != FsKind::Unknown) {
        Partition whole;
        whole.number = 0;
        whole.start = 0;
        whole.length = r.size();
        whole.fs = wholeFs;
        whole.fsLabel = wholeLabel;
        whole.description = std::string("Whole device ") + fsName(wholeFs);
        parts.push_back(whole);
        return parts;
    }

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
                             p.fs == FsKind::Fat ? "FAT filesystem" :
                             p.fs == FsKind::ExFat ? "exFAT partition" : "NTFS partition");
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
            if (p.fs == FsKind::Unknown) {
                if (type == 0x07) p.fs = FsKind::Ntfs;
                else if (type == 0x01 || type == 0x04 || type == 0x06 || type == 0x0b ||
                         type == 0x0c || type == 0x0e || type == 0x0f) p.fs = FsKind::Fat;
                else if (type == 0x83) p.fs = FsKind::Ext;
            }
            p.description = p.fs == FsKind::Ext ? "Linux filesystem" :
                            p.fs == FsKind::Fat ? "FAT filesystem" :
                            p.fs == FsKind::ExFat ? "exFAT partition" :
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
