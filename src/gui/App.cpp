#include "core/DeviceEnumerator.h"
#include "core/Recovery.h"
#include "core/Scanner.h"
#include "core/Types.h"

#include <cui/cui.h>
#include <cui/cui_app.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace dd {
void runApp();
}

namespace {

struct TreeNode {
    int recordIndex = -1;  // -1 = folder node
    std::string label;
    std::string key;       // folder open-state key
    int depth = 0;
    bool folder = false;
    bool open = true;
    bool hasChildren = false;
    uint64_t sizeSum = 0;
    uint32_t fileCount = 0;
    std::vector<int> members;  // folder nodes: record indices below them
    const char *icon = CUI_ICON_FOLDER;
};

struct AppState {
    std::vector<dd::DeviceInfo> devices;
    int selectedDevice = -1;
    char sourcePath[512] = {};

    dd::ScanSession session;
    std::thread scanThread;
    std::atomic<bool> scanning{false};
    std::atomic<int> scanPercent{0};
    std::atomic<bool> cancelScan{false};
    std::mutex textMutex;
    std::string scanPhase;
    volatile bool cancelFlag = false;
    bool scanActive = false;
    bool resultsReady = false;

    std::vector<uint8_t> selected;
    int filter = 0;
    char search[256] = {};
    int selectedRow = -1;

    int category = 0;  // 0 = all files, 1..6 = category filter
    std::vector<TreeNode> tree;
    bool treeDirty = true;
    int treeFilter = -1;
    int treeCategory = -1;
    size_t treeRecordCount = 0;
    char treeSearch[256] = {};
    std::map<std::string, bool> folderOpen;  // absent key = expanded

    std::thread recoveryThread;
    std::atomic<bool> recovering{false};
    std::atomic<int> recoverPercent{0};
    std::atomic<bool> cancelRecovery{false};
    volatile bool recoverCancelFlag = false;
    bool recoverActive = false;
    bool recoverSuccess = false;
    std::string recoverPhase;
    std::string summaryText;
    char targetDir[512] = {};

    bool imagePickerOpen = false;
    bool folderPickerOpen = false;
    bool showRecoveryToast = false;
};

void setPhase(AppState &s, const char *phase) {
    std::lock_guard<std::mutex> lock(s.textMutex);
    s.scanPhase = phase;
}

void resetResults(AppState &s) {
    s.resultsReady = false;
    s.selected.clear();
    s.tree.clear();
    s.treeDirty = true;
    s.folderOpen.clear();
    s.category = 0;
    s.selectedRow = -1;
    s.filter = 0;
    s.search[0] = 0;
    s.session.~ScanSession();
    new (&s.session) dd::ScanSession{};
    s.summaryText.clear();
    s.recoverSuccess = false;
    s.showRecoveryToast = false;
    s.scanPercent.store(0);
    s.cancelScan.store(false);
    s.cancelFlag = false;
}

bool busy(AppState &s) {
    return s.scanning.load() || s.scanActive || s.recovering.load() || s.recoverActive;
}

void selectDevice(AppState &s, int index) {
    if (index < 0 || index >= static_cast<int>(s.devices.size())) return;
    if (busy(s)) return;
    s.selectedDevice = index;
    snprintf(s.sourcePath, sizeof(s.sourcePath), "%s", s.devices[index].path.c_str());
    resetResults(s);
}

void startScan(AppState &s) {
    if (s.scanning.load() || s.scanActive || s.recovering.load() || s.recoverActive ||
        !s.sourcePath[0]) return;
    resetResults(s);
    s.scanActive = true;
    s.scanning.store(true);
    setPhase(s, "Opening source...");

    const std::string path = s.sourcePath;
    const dd::ScanOptions options{};
    s.scanThread = std::thread([&s, path, options]() {
        dd::ProgressFn progress = [&s](int percent, const std::string &phase) {
            if (s.cancelScan.load()) {
                s.session.cancelled.store(true);
                s.session.cancelledFlag = true;
            }
            s.scanPercent.store(percent);
            std::lock_guard<std::mutex> lock(s.textMutex);
            s.scanPhase = phase;
        };
        dd::ResultFn result = [](const dd::FileRecord &) {};
        dd::runScan(s.session, path, options, progress, result);
        setPhase(s, s.session.error.empty() ? "Scan complete" : "Scan stopped");
        s.scanning.store(false);
    });
}

void requestScanCancel(AppState &s) {
    if (!s.scanning.load()) return;
    s.cancelScan.store(true);
    s.cancelFlag = true;
}

void startRecovery(AppState &s) {
    if (s.recovering.load() || s.recoverActive || !s.resultsReady) return;

    std::vector<const dd::FileRecord *> files;
    for (size_t i = 0; i < s.session.records.size() && i < s.selected.size(); ++i) {
        if (s.selected[i]) files.push_back(&s.session.records[i]);
    }
    if (files.empty()) return;

    const std::string target = s.targetDir[0] ? s.targetDir : "./recovered";
    s.recoverActive = true;
    s.recovering.store(true);
    s.recoverPercent.store(0);
    s.cancelRecovery.store(false);
    s.recoverCancelFlag = false;
    s.recoverSuccess = false;
    {
        std::lock_guard<std::mutex> lock(s.textMutex);
        s.recoverPhase = "Preparing recovery...";
        s.summaryText.clear();
    }

    s.recoveryThread = std::thread([&s, files, target]() {
        dd::RecoverySummary summary;
        dd::ProgressFn progress = [&s](int percent, const std::string &phase) {
            s.recoverPercent.store(percent);
            std::lock_guard<std::mutex> lock(s.textMutex);
            s.recoverPhase = phase;
        };
        const bool ok = dd::recoverFiles(s.session.reader, files, target, summary,
                                         progress, &s.recoverCancelFlag);

        char buffer[768];
        snprintf(buffer, sizeof(buffer), "%u recovered, %u failed, %s written\nReport: %s",
                 summary.succeeded, summary.failed,
                 dd::formatBytes(summary.bytesWritten).c_str(),
                 summary.reportPath.empty() ? "(none)" : summary.reportPath.c_str());
        std::string full = buffer;
        size_t shown = 0;
        for (const std::string &err : summary.errors) {
            if (shown++ >= 4) { full += "\n  ... (" + std::to_string(summary.errors.size() - shown + 1) + " more)"; break; }
            full += "\n  ! " + err;
        }
        {
            std::lock_guard<std::mutex> lock(s.textMutex);
            s.summaryText = full;
            s.recoverPhase = "Recovery complete";
        }
        s.recoverSuccess = ok && summary.failed == 0 && !s.cancelRecovery.load();
        s.recovering.store(false);
    });
}

void requestRecoveryCancel(AppState &s) {
    if (!s.recovering.load()) return;
    s.cancelRecovery.store(true);
    s.recoverCancelFlag = true;
}

bool containsCI(const std::string &text, const char *needle) {
    if (!needle || !*needle) return true;
    std::string a = text;
    std::string b = needle;
    for (char &c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (char &c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return a.find(b) != std::string::npos;
}

int categoryOf(const dd::FileRecord &r) {
    dd::Category c = dd::categoryFromName(r.name);
    if (c == dd::Category::Other) c = dd::categoryFromType(r.type);
    return static_cast<int>(c);
}

// Rebuilds the folder tree shown in the results view: category roots, then the
// original folder hierarchy of each file, like Disk Drill's "Reconstructed".
void rebuildTree(AppState &s) {
    if (!s.treeDirty && s.treeFilter == s.filter && s.treeCategory == s.category &&
        s.treeRecordCount == s.session.records.size() &&
        std::strcmp(s.treeSearch, s.search) == 0)
        return;
    s.treeDirty = false;
    s.treeFilter = s.filter;
    s.treeCategory = s.category;
    s.treeRecordCount = s.session.records.size();
    std::snprintf(s.treeSearch, sizeof(s.treeSearch), "%s", s.search);

    s.tree.clear();
    if (!s.resultsReady) return;

    struct BuildNode {
        std::map<std::string, BuildNode> children;
        std::map<std::string, BuildNode> extensions;  // carved files grouped by extension
        std::vector<int> files;
    };

    BuildNode roots[7];
    for (size_t i = 0; i < s.session.records.size(); ++i) {
        const dd::FileRecord &r = s.session.records[i];
        if (s.filter == 1 && r.status != dd::Status::Existing) continue;
        if (s.filter == 2 && r.status != dd::Status::Deleted) continue;
        if (s.filter == 3 && r.status != dd::Status::Carved) continue;
        if (!containsCI(r.name, s.search) && !containsCI(r.path, s.search)) continue;
        if (r.type == "Directory") continue;  // folders come from the path structure
        int cat = categoryOf(r);
        if (s.category != 0 && cat != s.category) continue;

        BuildNode *node = &roots[cat];
        if (r.status == dd::Status::Carved) {
            // carved files have no original folder: group them by extension
            std::string ext = dd::extensionOf(r.name);
            if (ext.empty()) ext = "other";
            roots[cat].extensions[ext].files.push_back(static_cast<int>(i));
            continue;
        }
        std::string comp;
        for (size_t p = 0; p < r.path.size(); ++p) {
            if (r.path[p] == '/') {
                if (!comp.empty()) {
                    node = &node->children[comp];
                    comp.clear();
                }
            } else {
                comp.push_back(r.path[p]);
            }
        }
        node->files.push_back(static_cast<int>(i));
    }

    std::function<void(const BuildNode &, uint64_t &, uint32_t &)> computeSums =
        [&](const BuildNode &n, uint64_t &size, uint32_t &count) {
            for (int idx : n.files) {
                size += s.session.records[static_cast<size_t>(idx)].size;
                ++count;
            }
            for (const auto &kv : n.children) computeSums(kv.second, size, count);
            for (const auto &kv : n.extensions) computeSums(kv.second, size, count);
        };

    std::function<void(const BuildNode &, std::vector<int> &)> collectMembers =
        [&](const BuildNode &n, std::vector<int> &out) {
            out.insert(out.end(), n.files.begin(), n.files.end());
            for (const auto &kv : n.children) collectMembers(kv.second, out);
            for (const auto &kv : n.extensions) collectMembers(kv.second, out);
        };

    std::function<void(const BuildNode &, int, const std::string &, const std::string &,
                       const char *)> emitFolder =
        [&](const BuildNode &n, int depth, const std::string &key, const std::string &label,
            const char *icon) {
            uint64_t size = 0;
            uint32_t count = 0;
            computeSums(n, size, count);
            bool open = true;
            auto it = s.folderOpen.find(key);
            if (it != s.folderOpen.end()) open = it->second;
            bool hasChildren = !n.children.empty() || !n.extensions.empty() || !n.files.empty();
            TreeNode tn;
            tn.label = label;
            tn.key = key;
            tn.depth = depth;
            tn.folder = true;
            tn.open = open;
            tn.hasChildren = hasChildren;
            tn.sizeSum = size;
            tn.fileCount = count;
            tn.icon = icon;
            collectMembers(n, tn.members);
            s.tree.push_back(std::move(tn));
            if (!open) return;

            for (const auto &kv : n.children)
                emitFolder(kv.second, depth + 1, key + "/" + kv.first, kv.first,
                           CUI_ICON_FOLDER);

            for (const auto &kv : n.extensions) {
                uint64_t sz = 0;
                uint32_t cnt = 0;
                computeSums(kv.second, sz, cnt);
                char el[64];
                std::snprintf(el, sizeof(el), "%s (%u)", kv.first.c_str(), cnt);
                emitFolder(kv.second, depth + 1, key + "#" + kv.first, el, CUI_ICON_FILE);
            }

            std::vector<int> files = n.files;
            std::sort(files.begin(), files.end(), [&](int a, int b) {
                const std::string &na = s.session.records[static_cast<size_t>(a)].name;
                const std::string &nb = s.session.records[static_cast<size_t>(b)].name;
                if (na != nb) return na < nb;
                return a < b;
            });
            for (int idx : files) {
                const dd::FileRecord &r = s.session.records[static_cast<size_t>(idx)];
                s.tree.push_back(TreeNode{idx, r.name, "", depth + 1, false, false, false,
                                          r.size, 1, {}, CUI_ICON_FILE});
            }
        };

    for (int cat = 1; cat <= 6; ++cat) {
        if (roots[cat].children.empty() && roots[cat].files.empty() &&
            roots[cat].extensions.empty())
            continue;
        char key[32];
        std::snprintf(key, sizeof(key), "cat:%d", cat);
        uint64_t size = 0;
        uint32_t count = 0;
        computeSums(roots[cat], size, count);
        char label[64];
        std::snprintf(label, sizeof(label), "%s (%u)",
                      dd::categoryName(static_cast<dd::Category>(cat)), count);
        emitFolder(roots[cat], 0, key, label, CUI_ICON_LAYERS);
    }
}

int selectedCount(const AppState &s) {
    int count = 0;
    for (size_t i = 0; i < s.selected.size(); ++i)
        if (s.selected[i]) ++count;
    return count;
}

cui_tone chanceTone(dd::Chance chance) {
    switch (chance) {
        case dd::Chance::High: return CUI_TONE_SUCCESS;
        case dd::Chance::Medium: return CUI_TONE_WARNING;
        case dd::Chance::Low: return CUI_TONE_DANGER;
    }
    return CUI_TONE_NEUTRAL;
}

void drawSidebar(cui_ctx *ui, AppState &s) {
    cui_box box{};
    box.id = "sidebar";
    box.dir = CUI_COLUMN;
    box.width = CUI_PX(240);
    box.height = CUI_FILL;
    box.pad = 14;
    box.gap = 8;
    box.bg = CUI_COLOR_SURFACE;
    box.border = 1;
    box.radius = 14;
    cui_box_begin(ui, &box);

    cui_heading(ui, "DiskDig", 2);
    cui_secondary(ui, "Data Recovery Studio");

    cui_button_opts refresh{};
    refresh.icon = CUI_ICON_REFRESH_CW;
    refresh.size = CUI_SIZE_SM;
    refresh.full_width = true;
    if (cui_button_ex(ui, "Refresh devices", &refresh)) {
        if (!busy(s)) {
            s.devices = dd::enumerateDevices();
            if (s.selectedDevice >= static_cast<int>(s.devices.size())) s.selectedDevice = -1;
            if (s.selectedDevice < 0 && !s.devices.empty()) selectDevice(s, 0);
        }
    }

    cui_separator(ui);
    cui_nav_section(ui, "STORAGE DEVICES");

    if (s.devices.empty()) {
        cui_secondary(ui, "No devices found.");
    }

    for (size_t i = 0; i < s.devices.size(); ++i) {
        const dd::DeviceInfo &dev = s.devices[i];
        cui_push_id_int(ui, static_cast<int>(i));

        char label[300];
        snprintf(label, sizeof(label), "%s  %s",
                 dev.model.empty() ? dev.path.c_str() : dev.model.c_str(),
                 dd::formatBytes(dev.bytes).c_str());

        char badgeText[40];
        if (!dev.error.empty() || !dev.readable) snprintf(badgeText, sizeof(badgeText), "Restricted");
        else if (dev.removable) snprintf(badgeText, sizeof(badgeText), "Removable");
        else snprintf(badgeText, sizeof(badgeText), "Fixed");

        cui_nav_opts nav{};
        nav.icon = CUI_ICON_DATABASE;
        nav.group = "devices";
        nav.selected = s.selectedDevice == static_cast<int>(i);
        nav.badge = badgeText;
        if (cui_nav_item_ex(ui, label, &nav)) selectDevice(s, static_cast<int>(i));

        char status[256];
        if (!dev.error.empty()) {
            snprintf(status, sizeof(status), "%s", dev.error.c_str());
        } else if (dev.mounted) {
            snprintf(status, sizeof(status), "Mounted%s%s",
                     dev.mounts.empty() ? "" : " at ",
                     dev.mounts.empty() ? (dev.readable ? "" : " (no read access)")
                                        : dev.mounts.c_str());
        } else {
            snprintf(status, sizeof(status), "%s",
                     dev.readable ? "Not mounted" : "No read permission");
        }

        cui_badge_opts tone{};
        tone.size = CUI_SIZE_SM;
        tone.dot = true;
        tone.tone = dev.readable && dev.error.empty() ? CUI_TONE_SUCCESS : CUI_TONE_DANGER;
        cui_badge_ex(ui, dev.readable && dev.error.empty() ? "Readable" : "No access", &tone);

        cui_text_opts statusOpts{};
        statusOpts.size = 11;
        statusOpts.color = dev.readable && dev.error.empty() ? CUI_COLOR_TEXT_SECONDARY
                                                             : CUI_COLOR_DANGER;
        cui_text_ex(ui, status, &statusOpts);
        cui_pop_id(ui);
    }

    if (s.resultsReady) {
        cui_separator(ui);
        cui_nav_section(ui, "SCAN RESULTS");

        uint32_t counts[7] = {};
        uint32_t total = 0;
        for (const auto &r : s.session.records) {
            ++counts[categoryOf(r)];
            ++total;
        }

        static const dd::Category cats[6] = {
            dd::Category::Pictures, dd::Category::Videos, dd::Category::Audio,
            dd::Category::Documents, dd::Category::Archives, dd::Category::Other,
        };
        static const char *icons[6] = {
            CUI_ICON_IMAGE, CUI_ICON_VIDEO, CUI_ICON_MUSIC,
            CUI_ICON_FILE_TEXT, CUI_ICON_ARCHIVE, CUI_ICON_LAYERS,
        };

        cui_push_id_int(ui, 900);
        cui_nav_opts all{};
        all.icon = CUI_ICON_GRID_3X3;
        all.group = "categories";
        all.selected = s.category == 0;
        char allBadge[16];
        std::snprintf(allBadge, sizeof(allBadge), "%u", total);
        all.badge = allBadge;
        if (cui_nav_item_ex(ui, "All files", &all)) {
            s.category = 0;
            s.treeDirty = true;
        }
        cui_pop_id(ui);

        for (int i = 0; i < 6; ++i) {
            cui_push_id_int(ui, 910 + i);
            cui_nav_opts nav{};
            nav.icon = icons[i];
            nav.group = "categories";
            nav.selected = s.category == i + 1;
            char badge[16];
            std::snprintf(badge, sizeof(badge), "%u", counts[i + 1]);
            nav.badge = badge;
            if (cui_nav_item_ex(ui, dd::categoryName(cats[i]), &nav)) {
                s.category = i + 1;
                s.treeDirty = true;
            }
            cui_pop_id(ui);
        }
    }

    cui_spacer(ui);
    cui_separator(ui);

    cui_button_opts openImage{};
    openImage.icon = CUI_ICON_FILE;
    openImage.size = CUI_SIZE_SM;
    if (cui_button_ex(ui, "Open image file...", &openImage)) s.imagePickerOpen = true;

    cui_secondary(ui, "Or enter a source path:");
    cui_input_opts src{};
    src.placeholder = "/dev/sdX or image file";
    src.icon = CUI_ICON_FOLDER_OPEN;
    src.size = CUI_SIZE_SM;
    src.disabled = busy(s);
    if ((cui_input_ex(ui, "source", s.sourcePath, sizeof(s.sourcePath), &src) & CUI_CHANGED) &&
        !busy(s)) {
        s.selectedDevice = -1;
        resetResults(s);
    }

    cui_box_end(ui);
}

void drawDetailCard(cui_ctx *ui, AppState &s) {
    if (s.selectedRow < 0 || s.selectedRow >= static_cast<int>(s.session.records.size())) return;
    const dd::FileRecord &r = s.session.records[static_cast<size_t>(s.selectedRow)];

    cui_card_opts card{};
    card.id = "detail";
    card.width = CUI_FILL;
    card.pad = 14;
    card.gap = 6;
    cui_card_begin(ui, &card);

    cui_heading(ui, r.name.c_str(), 4);
    cui_secondary(ui, r.path.empty() ? "(root)" : r.path.c_str());

    cui_box detailRow{};
    detailRow.dir = CUI_ROW;
    detailRow.gap = 10;
    detailRow.align = CUI_ALIGN_CENTER;
    cui_row_begin(ui, &detailRow);

    cui_badge_opts badge{};
    badge.tone = chanceTone(r.chance);
    badge.dot = true;
    badge.size = CUI_SIZE_SM;
    cui_badge_ex(ui, dd::chanceName(r.chance), &badge);

    char info[192];
    snprintf(info, sizeof(info), "%s  |  %s  |  %s", dd::statusName(r.status),
             dd::fsName(r.fs), dd::formatBytes(r.size).c_str());
    cui_text_ex(ui, info, nullptr);
    cui_box_end(ui);

    cui_textf(ui, "Why: %s", r.why.empty() ? "No explanation available." : r.why.c_str());
    cui_textf(ui, "Inode / entry: %llu   Segments: %zu",
              static_cast<unsigned long long>(r.inode), r.ranges.size());

    char offsets[320];
    size_t used = 0;
    const size_t shown = std::min<size_t>(r.ranges.size(), 4);
    for (size_t i = 0; i < shown; ++i) {
        used += snprintf(offsets + used, sizeof(offsets) - used, "%s0x%llx (+%s)",
                         i ? "  " : "",
                         static_cast<unsigned long long>(r.ranges[i].offset),
                         dd::formatBytes(r.ranges[i].length).c_str());
        if (used >= sizeof(offsets)) break;
    }
    if (r.ranges.size() > shown) {
        snprintf(offsets + used, sizeof(offsets) - used, "  ... (+%zu more)",
                 r.ranges.size() - shown);
    }
    if (r.ranges.empty()) snprintf(offsets, sizeof(offsets), "(no byte ranges)");
    cui_textf(ui, "Offsets: %s", offsets);

    cui_card_end(ui);
}

void drawResults(cui_ctx *ui, AppState &s) {
    if (s.tree.empty()) {
        cui_empty_opts empty{};
        empty.icon = CUI_ICON_SEARCH;
        empty.description = s.resultsReady
                                ? (s.session.records.empty()
                                       ? "No files were found in this source."
                                       : "No files match the current filter or search.")
                                : "Choose a device or image, then press Scan to begin.";
        cui_empty_state_ex(ui, s.resultsReady ? "Nothing to show" : "Ready to scan", &empty);
        return;
    }

    cui_scroll_opts scroll{};
    scroll.id = "results-scroll";
    scroll.width = CUI_FILL;
    scroll.height = CUI_FILL;
    scroll.pad = 2;
    scroll.gap = 2;
    cui_scroll_begin(ui, &scroll);

    cui_table_column columns[] = {
        {"", CUI_PX(34), CUI_TEXT_LEFT, false},
        {"Status", CUI_PX(110), CUI_TEXT_LEFT, false},
        {"Chance", CUI_PX(84), CUI_TEXT_LEFT, false},
        {"Name", CUI_FILL, CUI_TEXT_LEFT, false},
        {"Path", CUI_FILL, CUI_TEXT_LEFT, false},
        {"Size", CUI_PX(92), CUI_TEXT_RIGHT, false},
        {"Type", CUI_PX(108), CUI_TEXT_LEFT, false},
        {"Source", CUI_PX(88), CUI_TEXT_LEFT, false},
    };

    cui_table_opts table{};
    table.striped = true;
    table.compact = true;
    table.selectable = true;
    if (cui_table_begin_ex(ui, "results", columns, 8, &table)) {
        for (size_t row = 0; row < s.tree.size(); ++row) {
            const TreeNode &node = s.tree[row];
            if (node.folder) {
                cui_push_id_int(ui, -static_cast<int>(row) - 1);
                cui_table_row(ui, false);
                cui_table_cell(ui);
                bool picked = !node.members.empty();
                for (int idx : node.members) {
                    if (idx < 0 || idx >= static_cast<int>(s.selected.size()) ||
                        !s.selected[static_cast<size_t>(idx)]) {
                        picked = false;
                        break;
                    }
                }
                if (cui_checkbox_ex(ui, "##pickdir", &picked, nullptr)) {
                    for (int idx : node.members) {
                        if (idx >= 0 && idx < static_cast<int>(s.selected.size()))
                            s.selected[static_cast<size_t>(idx)] = picked ? 1 : 0;
                    }
                }
                cui_table_cell_text(ui, "");
                cui_table_cell_text(ui, "");
                cui_table_cell(ui);
                bool open = node.open;
                if (cui_tree_cell(ui, node.label.c_str(), node.depth, node.hasChildren,
                                  &open, node.icon)) {
                    s.folderOpen[node.key] = open;
                    s.treeDirty = true;
                }
                cui_table_cell_text(ui, "");
                cui_table_cell_text(ui, dd::formatBytes(node.sizeSum).c_str());
                char kind[48];
                std::snprintf(kind, sizeof(kind), "Folder (%u)", node.fileCount);
                cui_table_cell_text(ui, kind);
                cui_table_cell_text(ui, "");
                cui_pop_id(ui);
                continue;
            }

            const int index = node.recordIndex;
            const dd::FileRecord &r = s.session.records[static_cast<size_t>(index)];
            cui_push_id_int(ui, index);
            if (cui_table_row(ui, s.selectedRow == index)) s.selectedRow = index;

            cui_table_cell(ui);
            bool picked = s.selected[static_cast<size_t>(index)] != 0;
            if (cui_checkbox_ex(ui, "##pick", &picked, nullptr)) {
                s.selected[static_cast<size_t>(index)] = picked ? 1 : 0;
            }
            cui_table_cell_text(ui, dd::statusName(r.status));

            cui_table_cell(ui);
            cui_badge_opts badge{};
            badge.tone = chanceTone(r.chance);
            badge.size = CUI_SIZE_SM;
            cui_badge_ex(ui, dd::chanceName(r.chance), &badge);

            cui_table_cell(ui);
            cui_text_opts nameOpts{};
            nameOpts.nowrap = true;
            cui_text_ex(ui, r.name.c_str(), &nameOpts);

            cui_table_cell_text(ui, r.path.c_str());
            cui_table_cell_text(ui, dd::formatBytes(r.size).c_str());
            cui_table_cell_text(ui, r.type.c_str());
            cui_table_cell_text(ui, dd::fsName(r.fs));
            cui_pop_id(ui);
        }
        cui_table_end(ui);
    }
    cui_scroll_end(ui);
}

void drawToolbar(cui_ctx *ui, AppState &s) {
    cui_box bar{};
    bar.dir = CUI_ROW;
    bar.width = CUI_FILL;
    bar.gap = 10;
    bar.align = CUI_ALIGN_CENTER;
    cui_row_begin(ui, &bar);

    cui_button_opts scan{};
    scan.variant = CUI_BUTTON_PRIMARY;
    scan.icon = CUI_ICON_SEARCH;
    scan.disabled = !s.sourcePath[0] || s.scanning.load() || s.scanActive ||
                    s.recovering.load() || s.recoverActive;
    if (cui_button_ex(ui, "Scan", &scan)) startScan(s);

    const bool scanning = s.scanning.load() || s.scanActive;
    cui_button_opts stop{};
    stop.variant = CUI_BUTTON_DANGER;
    stop.disabled = !scanning;
    if (cui_button_ex(ui, "Stop", &stop)) requestScanCancel(s);

    static const char *filters[] = {"All", "Existing", "Deleted", "Carved"};
    cui_segmented_ex(ui, "filter", filters, 4, &s.filter, nullptr);

    cui_input_opts search{};
    search.icon = CUI_ICON_SEARCH;
    search.placeholder = "Search files";
    search.width = CUI_PX(220);
    cui_input_ex(ui, "search", s.search, sizeof(s.search), &search);

    cui_spacer(ui);
    if (s.resultsReady) {
        char counts[192];
        snprintf(counts, sizeof(counts), "%llu / %llu scanned  |  %u carved  |  %u existing",
                 static_cast<unsigned long long>(s.session.stats.scanned),
                 static_cast<unsigned long long>(s.session.stats.total),
                 static_cast<unsigned>(s.session.stats.carvedFound),
                 static_cast<unsigned>(s.session.stats.existingFound));
        cui_secondary(ui, counts);
    } else {
        cui_secondary(ui, "No scan results yet");
    }
    cui_box_end(ui);
}

void drawScanProgress(cui_ctx *ui, AppState &s) {
    if (!s.scanning.load() && !s.scanActive) return;
    char label[320];
    {
        std::lock_guard<std::mutex> lock(s.textMutex);
        snprintf(label, sizeof(label), "%s  %d%%", s.scanPhase.c_str(), s.scanPercent.load());
    }
    cui_progress_opts progress{};
    progress.label = label;
    progress.show_value = true;
    progress.width = CUI_FILL;
    cui_progress_ex(ui, static_cast<float>(s.scanPercent.load()) / 100.0f, &progress);
    cui_request_redraw(ui);
}

void drawRecoveryBar(cui_ctx *ui, AppState &s) {
    cui_separator(ui);
    cui_box bar{};
    bar.id = "recovery-bar";
    bar.dir = CUI_ROW;
    bar.width = CUI_FILL;
    bar.pad = 12;
    bar.gap = 10;
    bar.align = CUI_ALIGN_CENTER;
    bar.bg = CUI_COLOR_SURFACE;
    bar.radius = 12;
    cui_row_begin(ui, &bar);

    cui_text_ex(ui, "Recover to:", nullptr);

    cui_input_opts target{};
    target.placeholder = "Choose a destination folder";
    target.icon = CUI_ICON_FOLDER;
    target.width = CUI_FILL;
    cui_input_ex(ui, "target", s.targetDir, sizeof(s.targetDir), &target);

    cui_button_opts browse{};
    browse.icon = CUI_ICON_FOLDER_OPEN;
    if (cui_button_ex(ui, "Browse...", &browse)) s.folderPickerOpen = true;

    const int count = selectedCount(s);
    cui_button_opts recover{};
    recover.variant = CUI_BUTTON_PRIMARY;
    recover.icon = CUI_ICON_DOWNLOAD;
    recover.disabled = count == 0 || !s.resultsReady || s.recovering.load() || s.recoverActive;
    char recoverLabel[64];
    snprintf(recoverLabel, sizeof(recoverLabel), "Recover selected (%d)", count);
    if (cui_button_ex(ui, recoverLabel, &recover)) startRecovery(s);

    if (s.recovering.load() || s.recoverActive) {
        char phase[256];
        {
            std::lock_guard<std::mutex> lock(s.textMutex);
            snprintf(phase, sizeof(phase), "%s", s.recoverPhase.c_str());
        }
        cui_text_opts phaseOpts{};
        phaseOpts.nowrap = true;
        phaseOpts.width = CUI_PX(200);
        cui_text_ex(ui, phase, &phaseOpts);
        cui_progress_opts progress{};
        progress.width = CUI_PX(180);
        progress.show_value = true;
        cui_progress_ex(ui, static_cast<float>(s.recoverPercent.load()) / 100.0f, &progress);

        cui_button_opts cancel{};
        cancel.variant = CUI_BUTTON_DANGER;
        cancel.size = CUI_SIZE_SM;
        if (cui_button_ex(ui, "Cancel", &cancel)) requestRecoveryCancel(s);
        cui_request_redraw(ui);
    }
    cui_box_end(ui);

    if (!s.recovering.load() && !s.recoverActive) {
        std::string summary;
        {
            std::lock_guard<std::mutex> lock(s.textMutex);
            summary = s.summaryText;
        }
        if (!summary.empty()) {
            cui_card_opts card{};
            card.id = "summary";
            card.width = CUI_FILL;
            card.pad = 10;
            card.gap = 2;
            cui_card_begin(ui, &card);
            cui_label(ui, "Recovery summary");
            cui_text_ex(ui, summary.c_str(), nullptr);
            cui_card_end(ui);
        }
    }
}

void drawFrame(cui_ctx *ui, AppState &s) {
    if (!s.scanning.load() && s.scanThread.joinable()) {
        s.scanThread.join();
        s.scanActive = false;
        s.resultsReady = true;
        s.selected.resize(s.session.records.size(), 0);
        if (s.selectedRow >= static_cast<int>(s.session.records.size())) s.selectedRow = -1;
    }
    if (!s.recovering.load() && s.recoveryThread.joinable()) {
        s.recoveryThread.join();
        s.recoverActive = false;
        s.showRecoveryToast = s.recoverSuccess;
    }
    rebuildTree(s);

    cui_box root{};
    root.id = "root";
    root.dir = CUI_ROW;
    root.width = CUI_FILL;
    root.height = CUI_FILL;
    root.pad = 14;
    root.gap = 14;
    cui_box_begin(ui, &root);

    drawSidebar(ui, s);

    cui_box main{};
    main.id = "main";
    main.dir = CUI_COLUMN;
    main.width = CUI_FILL;
    main.height = CUI_FILL;
    main.gap = 10;
    cui_column_begin(ui, &main);

    cui_heading(ui, "Drive contents", 2);
    char sourceLine[560];
    snprintf(sourceLine, sizeof(sourceLine), "Source: %s", s.sourcePath[0] ? s.sourcePath : "(none)");
    cui_secondary(ui, sourceLine);

    drawToolbar(ui, s);
    drawScanProgress(ui, s);

    if (s.resultsReady && !s.session.error.empty()) {
        cui_alert_opts alert{};
        alert.description = s.session.error.c_str();
        alert.tone = CUI_TONE_WARNING;
        alert.dismissible = true;
        cui_alert_ex(ui, "Scan warning", &alert);
    }

    drawResults(ui, s);
    drawDetailCard(ui, s);
    drawRecoveryBar(ui, s);

    cui_box_end(ui);
    cui_box_end(ui);

    cui_file_picker_opts imageOpts{};
    imageOpts.title = "Open disk image";
    imageOpts.folders = false;
    imageOpts.filter = "*.img;*.iso;*.raw;*.dd;*";
    imageOpts.filter_label = "Disk images";
    if (cui_file_picker_ex(ui, "image-picker", &s.imagePickerOpen, s.sourcePath,
                           sizeof(s.sourcePath), &imageOpts)) {
        s.selectedDevice = -1;
        if (!busy(s)) resetResults(s);
    }

    cui_file_picker_opts folderOpts{};
    folderOpts.title = "Choose recovery destination";
    folderOpts.folders = true;
    if (cui_file_picker_ex(ui, "folder-picker", &s.folderPickerOpen, s.targetDir,
                           sizeof(s.targetDir), &folderOpts)) {
        /* The picker writes the chosen folder into targetDir. */
    }

    if (s.showRecoveryToast) {
        char message[640];
        {
            std::lock_guard<std::mutex> lock(s.textMutex);
            snprintf(message, sizeof(message), "%s", s.summaryText.c_str());
        }
        cui_toast_opts toast{};
        toast.description = message;
        toast.tone = CUI_TONE_SUCCESS;
        cui_toast_ex(ui, "Recovery complete", &toast);
        s.showRecoveryToast = false;
    }
}

} // namespace

void dd::runApp() {
    cui_app_desc desc{};
    desc.title = "DiskDig";
    desc.width = 1200;
    desc.height = 780;
    desc.continuous = false;

    AppState state;
    state.devices = dd::enumerateDevices();
    if (!state.devices.empty()) selectDevice(state, 0);
    snprintf(state.targetDir, sizeof(state.targetDir), "./recovered");

    cui_app *app = cui_app_create(&desc);
    if (!app) return;

    while (cui_app_frame(app)) {
        drawFrame(cui_app_ui(app), state);
    }

    requestScanCancel(state);
    requestRecoveryCancel(state);
    if (state.scanThread.joinable()) state.scanThread.join();
    if (state.recoveryThread.joinable()) state.recoveryThread.join();
    cui_app_destroy(app);
}
