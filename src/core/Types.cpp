#include "Types.h"

namespace dd {

const char *chanceName(Chance c) {
    switch (c) {
        case Chance::High: return "High";
        case Chance::Medium: return "Medium";
        case Chance::Low: return "Low";
    }
    return "Low";
}

const char *statusName(Status s) {
    switch (s) {
        case Status::Existing: return "Existing";
        case Status::Deleted: return "Deleted";
        case Status::Carved: return "Carved";
    }
    return "Deleted";
}

const char *fsName(FsKind f) {
    switch (f) {
        case FsKind::Ext: return "ext2/3/4";
        case FsKind::Fat: return "FAT12/16/32";
        case FsKind::ExFat: return "exFAT";
        case FsKind::Ntfs: return "NTFS";
        case FsKind::WholeDisk: return "Raw";
        case FsKind::Unknown: return "Unknown";
    }
    return "Unknown";
}

std::string formatBytes(uint64_t n) {
    static const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; ++i; }
    char buf[48];
    if (i == 0) snprintf(buf, sizeof buf, "%llu %s", (unsigned long long)n, units[i]);
    else snprintf(buf, sizeof buf, "%.1f %s", v, units[i]);
    return buf;
}

const char *categoryName(Category c) {
    switch (c) {
        case Category::All: return "All files";
        case Category::Pictures: return "Pictures";
        case Category::Videos: return "Videos";
        case Category::Audio: return "Audio";
        case Category::Documents: return "Documents";
        case Category::Archives: return "Archives";
        case Category::Other: return "Other";
    }
    return "Other";
}

Category categoryFromName(const std::string &name) {
    auto dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) return Category::Other;
    std::string ext = name.substr(dot + 1);
    for (char &c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    struct Entry { const char *ext; Category cat; };
    static const Entry table[] = {
        {"jpg",Category::Pictures},{"jpeg",Category::Pictures},{"png",Category::Pictures},
        {"gif",Category::Pictures},{"bmp",Category::Pictures},{"tif",Category::Pictures},
        {"tiff",Category::Pictures},{"webp",Category::Pictures},{"heic",Category::Pictures},
        {"heif",Category::Pictures},{"raw",Category::Pictures},{"cr2",Category::Pictures},
        {"nef",Category::Pictures},{"arw",Category::Pictures},{"dng",Category::Pictures},
        {"svg",Category::Pictures},{"ico",Category::Pictures},{"psd",Category::Pictures},
        {"mp4",Category::Videos},{"mov",Category::Videos},{"avi",Category::Videos},
        {"mkv",Category::Videos},{"webm",Category::Videos},{"wmv",Category::Videos},
        {"flv",Category::Videos},{"3gp",Category::Videos},{"m4v",Category::Videos},
        {"mpg",Category::Videos},{"mpeg",Category::Videos},{"ts",Category::Videos},
        {"m2ts",Category::Videos},{"mts",Category::Videos},{"vob",Category::Videos},
        {"mp3",Category::Audio},{"wav",Category::Audio},{"flac",Category::Audio},
        {"aac",Category::Audio},{"ogg",Category::Audio},{"m4a",Category::Audio},
        {"wma",Category::Audio},{"opus",Category::Audio},{"mid",Category::Audio},
        {"midi",Category::Audio},{"aiff",Category::Audio},{"mka",Category::Audio},
        {"pdf",Category::Documents},{"doc",Category::Documents},{"docx",Category::Documents},
        {"xls",Category::Documents},{"xlsx",Category::Documents},{"ppt",Category::Documents},
        {"pptx",Category::Documents},{"odt",Category::Documents},{"ods",Category::Documents},
        {"odp",Category::Documents},{"rtf",Category::Documents},{"txt",Category::Documents},
        {"csv",Category::Documents},{"log",Category::Documents},{"md",Category::Documents},
        {"json",Category::Documents},{"xml",Category::Documents},{"html",Category::Documents},
        {"htm",Category::Documents},{"epub",Category::Documents},{"mobi",Category::Documents},
        {"dwg",Category::Documents},{"key",Category::Documents},{"pages",Category::Documents},
        {"numbers",Category::Documents},{"zip",Category::Archives},{"rar",Category::Archives},
        {"7z",Category::Archives},{"tar",Category::Archives},{"gz",Category::Archives},
        {"bz2",Category::Archives},{"xz",Category::Archives},{"iso",Category::Archives},
        {"tgz",Category::Archives},{"zst",Category::Archives},{"cab",Category::Archives},
        {"arj",Category::Archives},{"lz4",Category::Archives},{"apk",Category::Archives},
    };
    for (const auto &e : table)
        if (ext == e.ext) return e.cat;
    return Category::Other;
}

Category categoryFromType(const std::string &type) {
    std::string t = type;
    for (char &c : t) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    auto has = [&](const char *word) { return t.find(word) != std::string::npos; };
    if (has("image") || has("photo") || has("icon") || has("illustrator") ||
        has("photoshop") || has("vector"))
        return Category::Pictures;
    if (has("video") || has("movie")) return Category::Videos;
    if (has("audio") || has("mp3") || has("sound")) return Category::Audio;
    if (has("archive") || has("gzip") || has("bzip") || has("disc image") ||
        has("7-zip") || has("tar"))
        return Category::Archives;
    if (has("document") || has("text") || has("sheet") || has("powerpoint") ||
        has("opendocument") || has("markdown") || has("web page") || has("e-book") ||
        has("json") || has("xml") || has("log") || has("csv"))
        return Category::Documents;
    return Category::Other;
}

std::string typeFromName(const std::string &name) {
    auto dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) return "File";
    std::string ext = name.substr(dot + 1);
    for (char &c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    struct Entry { const char *ext; const char *label; };
    static const Entry table[] = {
        {"jpg","JPEG image"},{"jpeg","JPEG image"},{"png","PNG image"},{"gif","GIF image"},
        {"bmp","Bitmap image"},{"tif","TIFF image"},{"tiff","TIFF image"},{"webp","WebP image"},
        {"heic","HEIF image"},{"raw","RAW photo"},{"cr2","Canon RAW"},{"nef","Nikon RAW"},
        {"arw","Sony RAW"},{"dng","Digital negative"},{"svg","Vector image"},{"ico","Icon"},
        {"pdf","PDF document"},{"doc","Word document"},{"docx","Word document"},
        {"xls","Excel sheet"},{"xlsx","Excel sheet"},{"ppt","PowerPoint"},{"pptx","PowerPoint"},
        {"odt","OpenDocument"},{"ods","OpenDocument sheet"},{"rtf","Rich text"},
        {"txt","Text file"},{"csv","Spreadsheet CSV"},{"log","Log file"},{"md","Markdown"},
        {"mp3","MP3 audio"},{"wav","WAV audio"},{"flac","FLAC audio"},{"aac","AAC audio"},
        {"ogg","Ogg audio"},{"m4a","M4A audio"},{"mp4","MP4 video"},{"mov","QuickTime movie"},
        {"avi","AVI video"},{"mkv","Matroska video"},{"webm","WebM video"},{"wmv","WMV video"},
        {"flv","Flash video"},{"3gp","3GP video"},{"zip","ZIP archive"},{"rar","RAR archive"},
        {"7z","7-Zip archive"},{"tar","TAR archive"},{"gz","Gzip archive"},{"bz2","Bzip2 archive"},
        {"xz","XZ archive"},{"iso","Disc image"},{"exe","Executable"},{"dll","Library"},
        {"so","Shared library"},{"bin","Binary file"},{"db","Database"},{"sqlite","SQLite database"},
        {"sqlite3","SQLite database"},{"json","JSON data"},{"xml","XML data"},{"html","Web page"},
        {"htm","Web page"},{"epub","E-book"},{"mobi","E-book"},{"psd","Photoshop file"},
        {"ai","Illustrator file"},{"blend","Blender file"},{"dwg","CAD drawing"},
    };
    for (const auto &e : table)
        if (ext == e.ext) return e.label;
    return ext + " file";
}

} // namespace dd
