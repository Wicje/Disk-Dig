#include "DeviceEnumerator.h"

#include <algorithm>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace dd {
namespace {

std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string readFile(const std::string &path) {
    std::ifstream f(path);
    if (!f) return {};
    std::string line;
    std::getline(f, line);
    return trim(line);
}

std::vector<std::pair<std::string, std::string>> mountPoints() {
    std::vector<std::pair<std::string, std::string>> out;
    std::ifstream f("/proc/self/mountinfo");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream is(line);
        std::string id, parent, majmin, root, mount;
        if (!(is >> id >> parent >> majmin >> root >> mount)) continue;
        std::string dev;
        size_t sep = line.find(" - ");
        if (sep != std::string::npos) {
            std::istringstream tail(line.substr(sep + 3));
            tail >> dev;
        }
        if (!dev.empty()) out.emplace_back(dev, mount);
    }
    return out;
}

std::string readModel(const std::string &name) {
    std::string base = "/sys/block/" + name + "/device/";
    std::string model = readFile(base + "model");
    if (model.empty()) model = readFile(base + "vendor");
    if (model.empty()) {
        std::string serial = readFile("/sys/block/" + name + "/serial");
        if (!serial.empty()) model = "Disk " + serial;
    }
    if (model.empty()) {
        if (name.rfind("loop", 0) == 0) model = "Loop device";
        else if (name.rfind("nvme", 0) == 0) model = "NVMe controller";
        else model = "Block device";
    }
    return model;
}

} // namespace

DeviceInfo describePath(const std::string &path) {
    DeviceInfo d;
    d.path = path;
    struct stat st{};
    if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        d.isImage = true;
        d.bytes = static_cast<uint64_t>(st.st_size);
        d.model = "Disk image";
    } else {
        size_t slash = path.find_last_of('/');
        std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
        d.model = readModel(name);
        std::string sizeText = readFile("/sys/block/" + name + "/size");
        if (!sizeText.empty()) {
            try { d.bytes = std::stoull(sizeText) * 512; } catch (...) {}
        }
        d.removable = readFile("/sys/block/" + name + "/removable") == "1";
        d.removable = d.removable || name.rfind("loop", 0) == 0;
    }
    for (const auto &m : mountPoints()) {
        if (m.first == path ||
            (!d.isImage && !path.empty() && m.first.compare(0, path.size(), path) == 0)) {
            if (!d.mounts.empty()) d.mounts += ", ";
            d.mounts += m.second;
        }
    }
    d.mounted = !d.mounts.empty();
    probeReadable(d);
    return d;
}

void probeReadable(DeviceInfo &dev) {
    if (access(dev.path.c_str(), R_OK) == 0) {
        dev.readable = true;
        dev.error.clear();
    } else {
        dev.readable = false;
        dev.error = "Permission denied: run as root or add your user to the 'disk' group";
    }
}

std::vector<DeviceInfo> enumerateDevices() {
    std::vector<DeviceInfo> out;
    DIR *dir = opendir("/sys/block");
    if (!dir) return out;
    std::vector<std::string> names;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (name.rfind("ram", 0) == 0 || name.rfind("zd", 0) == 0) continue;
        names.push_back(name);
    }
    closedir(dir);
    std::sort(names.begin(), names.end());
    for (const auto &name : names) {
        std::string sizeText = readFile("/sys/block/" + name + "/size");
        uint64_t sectors = 0;
        try { sectors = std::stoull(sizeText); } catch (...) { continue; }
        if (sectors == 0) continue;
        DeviceInfo d = describePath("/dev/" + name);
        d.bytes = sectors * 512;
        if (!d.mounted) {
            DIR *pdir = opendir(("/sys/block/" + name).c_str());
            if (pdir) {
                struct dirent *pe;
                while ((pe = readdir(pdir)) != nullptr) {
                    std::string pn = pe->d_name;
                    if (pn.find(name) != 0 || pn == name) continue;
                    if (!d.mounts.empty()) d.mounts += ", ";
                    for (const auto &m : mountPoints()) {
                        if (m.first == "/dev/" + pn) {
                            if (!d.mounts.empty() && d.mounts.back() != ' ') d.mounts += ", ";
                            d.mounts += m.second;
                        }
                    }
                }
                closedir(pdir);
            }
            d.mounted = !d.mounts.empty();
        }
        out.push_back(d);
    }
    return out;
}

} // namespace dd
