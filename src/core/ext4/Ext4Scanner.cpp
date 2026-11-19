#include "core/FsScanner.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dd {
namespace {

constexpr uint16_t kExtMagic = 0xEF53;
constexpr uint32_t kFeatExtents = 0x40;
constexpr uint32_t kFeat64Bit = 0x80;
constexpr uint32_t kInodeFlagExtents = 0x80000;
constexpr uint16_t kModeTypeMask = 0xF000;
constexpr uint16_t kModeRegular = 0x8000;
constexpr uint16_t kModeDirectory = 0x4000;
constexpr uint16_t kExtentMagic = 0xF30A;
constexpr uint32_t kMaxInodes = 2000000;
constexpr uint32_t kMaxRecords = 200000;
constexpr uint32_t kMaxBlocksPerInode = 100000;
constexpr uint32_t kMaxExtentDepth = 5;
constexpr uint32_t kMaxDirCandidates = 200000;
constexpr uint64_t kMaxNames = 1000000;
constexpr uint64_t kMaxGroups = 1048576;
constexpr uint64_t kDirBudgetBytes = 64ull * 1024 * 1024;

uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

struct GroupDesc {
    uint64_t blockBitmap = 0;
    uint64_t inodeBitmap = 0;
    uint64_t inodeTable = 0;
    std::vector<uint8_t> bitmap;
    bool bitmapLoaded = false;
};

struct InodeInfo {
    uint32_t number = 0;
    uint16_t mode = 0;
    uint64_t size = 0;
    uint32_t flags = 0;
    uint16_t links = 0;
    uint32_t dtime = 0;
    uint32_t mtime = 0;
    std::array<uint8_t, 60> block{};
};

class Ext4Scanner {
public:
    explicit Ext4Scanner(ScanContext &ctx) : ctx_(ctx) {}

    void run() {
        if (!ctx_.reader.isOpen()) return;
        if (ctx_.partitionStart >= ctx_.reader.size()) return;
        if (ctx_.partitionLength > std::numeric_limits<uint64_t>::max() - ctx_.partitionStart) return;
        partStart_ = ctx_.partitionStart;
        partLen_ = ctx_.partitionLength;
        uint64_t available = ctx_.reader.size() - partStart_;
        if (partLen_ == 0 || partLen_ > available) partLen_ = available;
        if (partLen_ < 2048) return;
        report(0, "Reading ext4 superblock");
        if (!readSuperblock() || !readGroups()) return;
        if (cancelled()) return;
        if (!ctx_.options.includeExisting && !ctx_.options.includeDeleted) {
            report(100, "ext4 scan complete");
            return;
        }
        collectInodes();
        if (cancelled()) return;
        scanDirectories();
        if (cancelled()) return;
        emitFiles();
        if (!cancelled()) report(100, "ext4 scan complete");
    }

private:
    ScanContext &ctx_;
    uint64_t partStart_ = 0;
    uint64_t partLen_ = 0;
    uint32_t blockSize_ = 1024;
    uint64_t blocksCount_ = 0;
    uint32_t blocksPerGroup_ = 0;
    uint32_t inodesPerGroup_ = 0;
    uint32_t inodeSize_ = 128;
    uint32_t firstDataBlock_ = 0;
    uint64_t inodesCount_ = 0;
    uint32_t features_ = 0;
    std::vector<GroupDesc> groups_;
    std::vector<InodeInfo> dirs_;
    std::unordered_set<uint32_t> dirInodes_;
    std::unordered_set<uint32_t> deletedInodes_;
    std::unordered_map<uint32_t, std::string> names_;
    std::unordered_map<uint32_t, uint32_t> parents_;
    std::unordered_set<uint32_t> slackNames_;
    uint64_t nextId_ = 1;
    uint32_t emitted_ = 0;

    bool cancelled() const { return ctx_.cancelledNow(); }

    void report(int percent, const char *phase) const {
        if (ctx_.progress) ctx_.progress(std::max(0, std::min(100, percent)), phase);
    }

    void progressAt(uint64_t done, uint64_t total, const char *phase) const {
        int percent = total ? static_cast<int>((done * 100) / total) : 100;
        report(percent, phase);
    }

    bool relOk(uint64_t rel, uint64_t len) const {
        return rel <= partLen_ && len <= partLen_ - rel;
    }

    bool readRel(uint64_t rel, void *buf, uint64_t len) const {
        if (!relOk(rel, len) || len > std::numeric_limits<size_t>::max()) return false;
        return ctx_.reader.readExact(partStart_ + rel, buf, static_cast<size_t>(len));
    }

    bool r16(uint64_t rel, uint16_t &v) const {
        if (!relOk(rel, 2)) return false;
        bool ok = false;
        v = ctx_.reader.u16(partStart_ + rel, &ok);
        return ok;
    }

    bool r32(uint64_t rel, uint32_t &v) const {
        if (!relOk(rel, 4)) return false;
        bool ok = false;
        v = ctx_.reader.u32(partStart_ + rel, &ok);
        return ok;
    }

    bool readSuperblock() {
        const uint64_t sb = 1024;
        uint16_t magic = 0;
        uint16_t inodeSize = 0;
        uint32_t logBlock = 0;
        uint32_t blocksLo = 0;
        uint32_t blocksHi = 0;
        uint32_t inodeCountLo = 0;
        if (!r16(sb + 0x38, magic) || magic != kExtMagic) return false;
        if (!r32(sb + 0x18, logBlock)) return false;
        if (!r32(sb + 0x04, blocksLo)) return false;
        if (!r32(sb + 0x14, firstDataBlock_)) return false;
        if (!r32(sb + 0x20, blocksPerGroup_) || !r32(sb + 0x28, inodesPerGroup_)) return false;
        if (!r32(sb + 0x00, inodeCountLo)) return false;
        if (!r16(sb + 0x58, inodeSize)) return false;
        if (!r32(sb + 0x60, features_)) return false;
        if ((features_ & kFeat64Bit) && !r32(sb + 0x150, blocksHi)) return false;
        inodeSize_ = inodeSize;
        blockSize_ = 1024u << std::min<uint32_t>(logBlock, 6);
        blockSize_ = std::max<uint32_t>(1024, std::min<uint32_t>(blockSize_, 65536));
        blocksCount_ = static_cast<uint64_t>(blocksLo) | (static_cast<uint64_t>(blocksHi) << 32);
        inodesCount_ = inodeCountLo;
        if (inodeSize_ < 128 || inodeSize_ > 4096 || (inodeSize_ & (inodeSize_ - 1)) != 0) return false;
        if (blocksCount_ == 0 || blocksPerGroup_ == 0 || inodesPerGroup_ == 0 || inodesCount_ == 0) return false;
        return true;
    }

    bool readGroups() {
        uint64_t gdtRel = (static_cast<uint64_t>(firstDataBlock_) + 1) * blockSize_;
        uint64_t count = (blocksCount_ + blocksPerGroup_ - 1) / blocksPerGroup_;
        uint32_t gdSize = (features_ & kFeat64Bit) ? 64u : 32u;
        if (count == 0 || count > kMaxGroups) return false;
        if (!relOk(gdtRel, count * gdSize)) return false;
        groups_.resize(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t base = gdtRel + i * gdSize;
            uint32_t lo = 0;
            uint32_t hi = 0;
            GroupDesc g;
            if (!r32(base + 0x00, lo)) continue;
            if ((features_ & kFeat64Bit) && !r32(base + 0x20, hi)) continue;
            g.blockBitmap = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
            lo = 0;
            hi = 0;
            if (!r32(base + 0x04, lo)) continue;
            if ((features_ & kFeat64Bit) && !r32(base + 0x24, hi)) continue;
            g.inodeBitmap = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
            lo = 0;
            hi = 0;
            if (!r32(base + 0x08, lo)) continue;
            if ((features_ & kFeat64Bit) && !r32(base + 0x28, hi)) continue;
            g.inodeTable = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
            groups_[static_cast<size_t>(i)] = std::move(g);
            if ((i & 1023) == 0 && cancelled()) return false;
        }
        return true;
    }

    uint64_t inodeOffset(uint32_t ino) const {
        if (ino == 0 || ino > inodesCount_) return 0;
        uint64_t idx = ino - 1;
        uint64_t group = idx / inodesPerGroup_;
        uint64_t within = idx % inodesPerGroup_;
        if (group >= groups_.size()) return 0;
        uint64_t table = groups_[static_cast<size_t>(group)].inodeTable;
        if (table > partLen_ / blockSize_) return 0;
        uint64_t rel = table * blockSize_ + within * inodeSize_;
        if (!relOk(rel, 128)) return 0;
        return rel;
    }

    bool readInode(uint32_t ino, InodeInfo &out) const {
        uint64_t off = inodeOffset(ino);
        if (off == 0) return false;
        std::array<uint8_t, 128> buf{};
        if (!readRel(off, buf.data(), buf.size())) return false;
        out = InodeInfo{};
        out.number = ino;
        out.mode = le16(buf.data() + 0x00);
        uint64_t sizeLo = le32(buf.data() + 0x04);
        out.mtime = le32(buf.data() + 0x10);
        out.dtime = le32(buf.data() + 0x14);
        out.links = le16(buf.data() + 0x1A);
        out.flags = le32(buf.data() + 0x20);
        std::copy(buf.begin() + 0x28, buf.begin() + 0x64, out.block.begin());
        if ((out.mode & kModeTypeMask) == kModeDirectory) {
            out.size = sizeLo;
        } else {
            uint64_t sizeHi = le32(buf.data() + 0x6C);
            out.size = sizeLo | (sizeHi << 32);
        }
        if (out.size > partLen_) out.size = partLen_;
        return true;
    }

    bool blockValid(uint64_t blk) const {
        uint64_t maxBlk = std::min<uint64_t>(blocksCount_, partLen_ / blockSize_);
        return blk != 0 && blk < maxBlk;
    }

    void addRange(std::vector<ByteRange> &out, uint64_t block, uint64_t count, uint64_t &remaining) const {
        if (remaining == 0 || count == 0 || out.size() >= kMaxBlocksPerInode) return;
        uint64_t maxBlk = std::min<uint64_t>(blocksCount_, partLen_ / blockSize_);
        if (block == 0 || block >= maxBlk) return;
        uint64_t end = (count > maxBlk - block) ? maxBlk : block + count;
        uint64_t bytes = (end - block) * blockSize_;
        if (bytes > remaining) {
            bytes = remaining;
            end = block + (bytes + blockSize_ - 1) / blockSize_;
        }
        out.push_back(ByteRange{partStart_ + block * blockSize_, bytes});
        remaining -= bytes;
    }

    bool walkExtent(const uint8_t *data, size_t dataLen, uint32_t depth, uint64_t totalBytes,
                    uint64_t &remaining, std::vector<ByteRange> &out,
                    std::unordered_set<uint64_t> &visited) const {
        if (depth > kMaxExtentDepth || dataLen < 12 || le16(data + 0x00) != kExtentMagic) return false;
        uint32_t entries = le16(data + 0x02);
        uint32_t capacity = le16(data + 0x04);
        uint32_t fit = static_cast<uint32_t>((dataLen - 12) / 12);
        uint32_t limit = std::min(entries, fit);
        if (capacity != 0) limit = std::min(limit, capacity);
        for (uint32_t i = 0; i < limit && remaining > 0; ++i) {
            if (cancelled() || out.size() >= kMaxBlocksPerInode) break;
            const uint8_t *p = data + 12 + static_cast<size_t>(i) * 12;
            if (depth == 0) {
                uint64_t logical = le32(p + 0x00);
                uint32_t len = le16(p + 0x04) & 0x7FFFu;
                if (logical > totalBytes / blockSize_ || len == 0) continue;
                uint64_t phys = static_cast<uint64_t>(le32(p + 0x08)) |
                                (static_cast<uint64_t>(le16(p + 0x06)) << 32);
                addRange(out, phys, len, remaining);
            } else {
                uint64_t child = static_cast<uint64_t>(le32(p + 0x04)) |
                                 (static_cast<uint64_t>(le16(p + 0x08)) << 32);
                if (!blockValid(child) || visited.find(child) != visited.end()) continue;
                visited.insert(child);
                std::vector<uint8_t> buf(blockSize_);
                if (!readRel(child * blockSize_, buf.data(), blockSize_)) continue;
                walkExtent(buf.data(), buf.size(), depth - 1, totalBytes, remaining, out, visited);
            }
        }
        return true;
    }

    void collectIndirect(uint32_t block, int level, uint64_t &remaining, std::vector<ByteRange> &out,
                         std::unordered_set<uint32_t> &visited) const {
        if (level < 0 || remaining == 0 || out.size() >= kMaxBlocksPerInode) return;
        if (!blockValid(block) || visited.find(block) != visited.end() || visited.size() > 200000) return;
        visited.insert(block);
        std::vector<uint8_t> buf(blockSize_);
        if (!readRel(static_cast<uint64_t>(block) * blockSize_, buf.data(), blockSize_)) return;
        uint32_t entries = blockSize_ / 4;
        for (uint32_t i = 0; i < entries && remaining > 0; ++i) {
            if (cancelled() || out.size() >= kMaxBlocksPerInode) break;
            uint32_t ptr = le32(buf.data() + static_cast<size_t>(i) * 4);
            if (ptr == 0) continue;
            if (level == 0) addRange(out, ptr, 1, remaining);
            else collectIndirect(ptr, level - 1, remaining, out, visited);
        }
    }

    std::vector<ByteRange> resolveBlocks(const InodeInfo &inode) const {
        std::vector<ByteRange> out;
        if (inode.size == 0) return out;
        uint64_t remaining = inode.size;
        if ((inode.flags & kInodeFlagExtents) && (features_ & kFeatExtents)) {
            uint32_t depth = le16(inode.block.data() + 0x06);
            std::unordered_set<uint64_t> visited;
            walkExtent(inode.block.data(), inode.block.size(), depth, inode.size, remaining, out, visited);
        } else {
            for (uint32_t i = 0; i < 12 && remaining > 0; ++i) {
                uint32_t blk = le32(inode.block.data() + static_cast<size_t>(i) * 4);
                if (blk != 0) addRange(out, blk, 1, remaining);
                if (cancelled()) break;
            }
            std::unordered_set<uint32_t> visited;
            uint32_t single = le32(inode.block.data() + 48);
            uint32_t doubleInd = le32(inode.block.data() + 52);
            uint32_t triple = le32(inode.block.data() + 56);
            collectIndirect(single, 0, remaining, out, visited);
            collectIndirect(doubleInd, 1, remaining, out, visited);
            collectIndirect(triple, 2, remaining, out, visited);
        }
        return out;
    }

    void collectInodes() {
        uint64_t total = std::min<uint64_t>(inodesCount_, kMaxInodes);
        uint64_t step = std::max<uint64_t>(1, total / 100);
        for (uint32_t ino = 1; ino <= total; ++ino) {
            if ((ino & 1023) == 0 && cancelled()) return;
            if (ino % step == 0) progressAt(ino, total, "Reading ext4 inode table");
            InodeInfo info;
            if (!readInode(ino, info)) continue;
            uint16_t type = info.mode & kModeTypeMask;
            if (type == kModeDirectory) {
                if ((info.links > 0 || info.dtime != 0) && dirs_.size() < kMaxDirCandidates) {
                    dirs_.push_back(info);
                    dirInodes_.insert(ino);
                }
            } else if (type == kModeRegular && info.dtime != 0 && info.links == 0) {
                deletedInodes_.insert(ino);
            }
        }
        report(100, "Reading ext4 inode table");
    }

    void considerName(uint32_t dirIno, uint32_t ino, const std::string &name, bool fromSlack) {
        if (ino == 0 || ino > inodesCount_ || name.empty() || name == "." || name == "..") return;
        if (name.find('\0') != std::string::npos) return;
        bool isDeleted = deletedInodes_.find(ino) != deletedInodes_.end();
        bool isDir = dirInodes_.find(ino) != dirInodes_.end();
        if (!isDeleted && !isDir) return;
        auto it = names_.find(ino);
        if (it == names_.end()) {
            if (names_.size() >= kMaxNames) return;
            names_.emplace(ino, name);
            if (fromSlack) slackNames_.insert(ino);
            if (isDeleted) parents_[ino] = dirIno;
        } else if (!fromSlack && slackNames_.erase(ino) != 0) {
            it->second = name;
            if (isDeleted) parents_[ino] = dirIno;
        }
    }

    void parseDirBlock(uint32_t dirIno, const uint8_t *buf) {
        uint64_t off = 0;
        while (off + 8 <= blockSize_) {
            uint32_t ino = le32(buf + static_cast<size_t>(off));
            uint16_t recLen = le16(buf + static_cast<size_t>(off) + 4);
            uint8_t nameLen = buf[static_cast<size_t>(off) + 6];
            if (recLen < 8 || (recLen & 3u) != 0 || off + recLen > blockSize_) break;
            if (ino != 0 && nameLen >= 1 && 8u + nameLen <= recLen) {
                std::string name(reinterpret_cast<const char *>(buf + static_cast<size_t>(off) + 8), nameLen);
                considerName(dirIno, ino, name, false);
            }
            uint64_t used = 8 + ((static_cast<uint64_t>(nameLen) + 3) & ~uint64_t(3));
            if (recLen > used && used >= 8) {
                for (uint64_t p = off + used; p + 8 <= off + recLen; p += 4) {
                    uint32_t candIno = le32(buf + static_cast<size_t>(p));
                    uint16_t candRec = le16(buf + static_cast<size_t>(p) + 4);
                    uint8_t candNameLen = buf[static_cast<size_t>(p) + 6];
                    if (candIno == 0 || candIno > inodesCount_) continue;
                    if (candNameLen < 1) continue;
                    if (candRec < 8 || (candRec & 3u) != 0) continue;
                    if (8u + candNameLen > candRec || p + candRec > off + recLen) continue;
                    std::string candName(reinterpret_cast<const char *>(buf + static_cast<size_t>(p) + 8),
                                         candNameLen);
                    considerName(dirIno, candIno, candName, true);
                }
            }
            off += recLen;
        }
    }

    void scanDirectories() {
        uint64_t budget = kDirBudgetBytes / blockSize_;
        if (budget == 0) return;
        size_t total = dirs_.size();
        size_t step = std::max<size_t>(1, total / 100);
        std::vector<uint8_t> buf(blockSize_);
        for (size_t i = 0; i < total && budget > 0; ++i) {
            if ((i & 31) == 0 && cancelled()) return;
            if (i % step == 0) progressAt(i, total, "Recovering ext4 names");
            const InodeInfo &info = dirs_[i];
            std::vector<ByteRange> ranges = resolveBlocks(info);
            for (const ByteRange &r : ranges) {
                uint64_t blocks = (r.length + blockSize_ - 1) / blockSize_;
                uint64_t rel = r.offset - partStart_;
                for (uint64_t b = 0; b < blocks && budget > 0; ++b) {
                    --budget;
                    if (readRel(rel + b * blockSize_, buf.data(), blockSize_)) {
                        parseDirBlock(info.number, buf.data());
                    }
                    if (cancelled() || names_.size() >= kMaxNames) return;
                }
                if (budget == 0) break;
            }
        }
        report(100, "Recovering ext4 names");
    }

    bool blockIsFree(uint64_t blk) {
        if (blk < firstDataBlock_) return false;
        uint64_t rel = blk - firstDataBlock_;
        uint64_t group = rel / blocksPerGroup_;
        if (group >= groups_.size()) return false;
        GroupDesc &gd = groups_[static_cast<size_t>(group)];
        if (!gd.bitmapLoaded) {
            gd.bitmapLoaded = true;
            gd.bitmap.assign(blockSize_, 0);
            if (!blockValid(gd.blockBitmap) ||
                !readRel(gd.blockBitmap * blockSize_, gd.bitmap.data(), blockSize_)) {
                gd.bitmap.clear();
                return false;
            }
        }
        if (gd.bitmap.empty()) return false;
        uint64_t bit = rel % blocksPerGroup_;
        if (bit / 8 >= gd.bitmap.size()) return false;
        return (gd.bitmap[static_cast<size_t>(bit / 8)] & (1u << (bit & 7))) == 0;
    }

    void countFreeBlocks(const std::vector<ByteRange> &ranges, uint64_t &total, uint64_t &free) {
        for (const ByteRange &r : ranges) {
            uint64_t start = (r.offset - partStart_) / blockSize_;
            uint64_t blocks = (r.length + blockSize_ - 1) / blockSize_;
            for (uint64_t i = 0; i < blocks && total < kMaxBlocksPerInode; ++i) {
                ++total;
                if (blockIsFree(start + i)) ++free;
                if ((i & 1023) == 0 && cancelled()) return;
            }
            if (total >= kMaxBlocksPerInode) break;
        }
    }

    void emitFiles() {
        uint64_t total = std::min<uint64_t>(inodesCount_, kMaxInodes);
        uint64_t step = std::max<uint64_t>(1, total / 100);
        for (uint32_t ino = 1; ino <= total; ++ino) {
            if ((ino & 1023) == 0 && cancelled()) return;
            if (ino % step == 0) progressAt(ino, total, "Scanning ext4 files");
            InodeInfo info;
            if (!readInode(ino, info)) continue;
            if ((info.mode & kModeTypeMask) != kModeRegular) continue;
            bool deleted = info.dtime != 0 && info.links == 0;
            bool existing = info.dtime == 0 && info.links > 0;
            if (!deleted && !existing) continue;
            if (deleted && !ctx_.options.includeDeleted) continue;
            if (existing && !ctx_.options.includeExisting) continue;

            std::string name;
            auto nit = names_.find(ino);
            if (nit != names_.end()) name = nit->second;
            else name = "inode_" + std::to_string(ino);

            std::string path;
            auto pit = parents_.find(ino);
            if (pit == parents_.end() || pit->second <= 2 || pit->second == ino) {
                path = "/" + name;
            } else {
                std::string dirname = "inode_" + std::to_string(pit->second);
                auto dit = names_.find(pit->second);
                if (dit != names_.end()) dirname = dit->second;
                path = "/" + dirname + "/" + name;
            }

            std::vector<ByteRange> ranges = resolveBlocks(info);
            Chance chance = Chance::Low;
            std::string why;
            if (info.size == 0) {
                chance = Chance::Medium;
                why = "Empty file; no data blocks";
            } else if (ranges.empty()) {
                chance = Chance::Low;
                why = "Data block pointers could not be resolved";
            } else if (!deleted) {
                chance = Chance::High;
                why = "Metadata intact";
            } else {
                uint64_t blockTotal = 0;
                uint64_t blockFree = 0;
                countFreeBlocks(ranges, blockTotal, blockFree);
                if (blockTotal == 0) {
                    chance = Chance::Low;
                    why = "Deleted inode; no physical blocks to check";
                } else if (blockFree == blockTotal) {
                    chance = Chance::High;
                    why = "Deleted inode; 100% of blocks free -> high chance";
                } else {
                    uint64_t percent = (blockFree * 100) / blockTotal;
                    chance = percent > 80 ? Chance::Medium : Chance::Low;
                    why = "Metadata intact but " + std::to_string(blockTotal - blockFree) +
                          " blocks reused; " + std::to_string(percent) + "% of blocks free";
                }
            }
            if (slackNames_.find(ino) != slackNames_.end()) {
                if (!why.empty()) why += "; ";
                why += "Name recovered from directory slack";
            }

            FileRecord rec;
            rec.id = nextId_++;
            rec.name = name;
            rec.path = path;
            rec.size = info.size;
            rec.status = deleted ? Status::Deleted : Status::Existing;
            rec.chance = chance;
            rec.fs = FsKind::Ext;
            rec.type = typeFromName(name);
            rec.ranges = std::move(ranges);
            rec.why = std::move(why);
            rec.modified = info.mtime;
            rec.deleted = info.dtime;
            rec.inode = ino;
            if (ctx_.result) ctx_.result(rec);
            if (deleted) ++ctx_.stats.extFound;
            else ++ctx_.stats.existingFound;
            if (++emitted_ >= kMaxRecords) return;
        }
        report(100, "Scanning ext4 files");
    }
};

} // namespace

void scanExt4(ScanContext &ctx) {
    Ext4Scanner scanner(ctx);
    scanner.run();
}

} // namespace dd
