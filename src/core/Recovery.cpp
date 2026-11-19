#include "Recovery.h"
#include "RawReader.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace dd {
namespace {

std::string safeName(const std::string &name) {
    std::string out;
    for (unsigned char c : name) {
        if (c == '/' || c == '\\' || c == 0 || c < 32 || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|') out += '_';
        else out += static_cast<char>(c);
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    if (out.empty()) out = "unnamed";
    return out;
}

std::string uniquePath(const std::string &dir, const std::string &name, int index) {
    std::string base = dir + "/" + safeName(name);
    if (index == 0) return base;
    size_t dot = base.find_last_of('.');
    if (dot == std::string::npos || dot < dir.size() + 1) return base + "_" + std::to_string(index);
    return base.substr(0, dot) + "_" + std::to_string(index) + base.substr(dot);
}

std::string mountSourceFor(const std::string &path) {
    char resolvedBuf[PATH_MAX]{};
    if (!realpath(path.c_str(), resolvedBuf)) return {};
    std::string resolved(resolvedBuf);

    std::ifstream f("/proc/self/mountinfo");
    std::string line, best;
    size_t bestLen = 0;
    while (std::getline(f, line)) {
        std::string device;
        size_t sep = line.find(" - ");
        if (sep == std::string::npos) continue;
        {
            std::istringstream is(line.substr(sep + 3));
            is >> device;
        }
        std::istringstream is(line);
        std::string id, parent, majmin, root, mount;
        if (!(is >> id >> parent >> majmin >> root >> mount)) continue;
        if (mount.size() <= bestLen) continue;
        if (resolved == mount ||
            (resolved.compare(0, mount.size(), mount) == 0 &&
             (resolved.size() == mount.size() || resolved[mount.size()] == '/'))) {
            best = device;
            bestLen = mount.size();
        }
    }
    return best;
}

bool sameMount(const std::string &sourcePath, const std::string &targetDir) {
    std::string src = mountSourceFor(sourcePath);
    std::string dst = mountSourceFor(targetDir);
    return !src.empty() && src == dst;
}

void makeDirs(const std::string &path) {
    std::string cur;
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        cur.append(path.substr(i, j - i));
        if (!cur.empty()) ::mkdir(cur.c_str(), 0755);
        cur.push_back('/');
        i = j + 1;
    }
}

// Recreates the original folder structure below the target directory, like
// Disk Drill. Returns "" when the record has no known path (e.g. carved).
std::string relativeDirFor(const std::string &path) {
    if (path.empty()) return {};
    std::string p = path;
    if (p.front() == '/') p.erase(0, 1);
    auto slash = p.find_last_of('/');
    if (slash == std::string::npos) return {};
    std::string dir = p.substr(0, slash);
    std::string out, comp;
    for (size_t i = 0; i <= dir.size(); ++i) {
        if (i == dir.size() || dir[i] == '/') {
            if (comp != "." && comp != "..") {
                std::string s = safeName(comp);
                if (!s.empty()) {
                    if (!out.empty()) out += '/';
                    out += s;
                }
            }
            comp.clear();
        } else {
            comp.push_back(dir[i]);
        }
    }
    return out;
}

} // namespace

bool recoverFiles(const RawReader &source,
                  const std::vector<const FileRecord *> &files,
                  const std::string &targetDir,
                  RecoverySummary &summary,
                  std::function<void(int percent, const std::string &phase)> progress,
                  const volatile bool *cancelled) {
    if (!source.isOpen() || files.empty()) {
        summary.errors.push_back("No source open or no files selected");
        return false;
    }
    struct stat st{};
    if (stat(targetDir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        summary.errors.push_back("Target directory does not exist: " + targetDir);
        return false;
    }
    if (access(targetDir.c_str(), W_OK) != 0) {
        summary.errors.push_back("Target directory is not writable: " + targetDir);
        return false;
    }
    struct stat sourceStat{};
    const bool sourceIsRegularFile = stat(source.path().c_str(), &sourceStat) == 0 &&
                                     S_ISREG(sourceStat.st_mode);
    if (!sourceIsRegularFile && sameMount(source.path(), targetDir)) {
        summary.errors.push_back("Refusing to recover onto the source drive: " + targetDir +
            ". Choose a different physical disk or external drive.");
        return false;
    }

    uint64_t total = 0;
    for (auto *f : files) total += f->size;
    struct statvfs vfs{};
    if (statvfs(targetDir.c_str(), &vfs) == 0) {
        uint64_t available = static_cast<uint64_t>(vfs.f_bavail) * vfs.f_frsize;
        if (total > available) {
            summary.errors.push_back("Target may not have enough free space (need " +
                                     formatBytes(total) + ")");
        }
    }

    std::ofstream report(targetDir + "/diskdig_recovery_report.csv", std::ios::app);
    bool reportOpen = report.is_open();
    if (reportOpen && report.tellp() == 0)
        report << "name,status,chance,size,source_offset,bytes_written,result,why\n";

    std::vector<std::string> used;
    size_t done = 0;
    const size_t chunk = 1 << 20;
    std::vector<uint8_t> buffer(chunk);

    for (const FileRecord *f : files) {
        if (cancelled && *cancelled) break;
        std::string relDir = relativeDirFor(f->path);
        std::string dir = targetDir;
        if (!relDir.empty()) {
            dir = targetDir + "/" + relDir;
            makeDirs(dir);
        }
        int index = 0;
        std::string path;
        do {
            path = uniquePath(dir, f->name + (f->ranges.empty() ? ".bin" : ""), index++);
        } while (access(path.c_str(), F_OK) == 0 && index < 10000);

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            summary.failed++;
            summary.errors.push_back("Could not create " + path + ": " + strerror(errno));
            if (reportOpen) report << safeName(f->name) << "," << statusName(f->status) << ","
                                   << chanceName(f->chance) << "," << f->size << ",,0,failed,open error\n";
            continue;
        }
        uint64_t writtenTotal = 0;
        bool ok = true;
        for (const auto &range : f->ranges) {
            uint64_t pos = 0;
            while (pos < range.length) {
                if (cancelled && *cancelled) { ok = false; break; }
                size_t want = static_cast<size_t>(std::min<uint64_t>(chunk, range.length - pos));
                if (source.readAt(range.offset + pos, buffer.data(), want) != static_cast<int64_t>(want)) {
                    ok = false;
                    break;
                }
                out.write(reinterpret_cast<const char *>(buffer.data()), static_cast<std::streamsize>(want));
                if (!out) { ok = false; break; }
                pos += want;
                writtenTotal += want;
            }
            if (!ok) break;
        }
        out.close();
        if (ok) {
            summary.succeeded++;
            summary.bytesWritten += writtenTotal;
        } else {
            summary.failed++;
            summary.errors.push_back("Short read/write for " + f->name);
            ::unlink(path.c_str());
        }
        if (reportOpen) {
            report << safeName(f->name) << "," << statusName(f->status) << ","
                   << chanceName(f->chance) << "," << f->size << ","
                   << (f->ranges.empty() ? 0 : f->ranges[0].offset) << ","
                   << writtenTotal << "," << (ok ? "ok" : "failed") << ","
                   << f->why << "\n";
        }
        ++done;
        if (progress) progress(static_cast<int>(done * 100 / files.size()),
                               "Recovering " + f->name);
    }
    if (reportOpen) {
        report.close();
        summary.reportPath = targetDir + "/diskdig_recovery_report.csv";
    }
    return summary.failed == 0;
}
} // namespace dd
