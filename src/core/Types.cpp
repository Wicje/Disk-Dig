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
        case FsKind::Fat: return "FAT32";
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
