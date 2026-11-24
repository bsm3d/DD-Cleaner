// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the shared helpers: UTF-8 and wide string conversion, Windows path handling and the reserved file names set.

#include <ddcore/common.hpp>

#include <algorithm>
#include <cwctype>
#include <ctime>
#include <set>

#include <windows.h>
#include <shlobj.h>

namespace dd {

// region Strings

std::wstring wide(const std::string& text) {
    if (text.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), out.data(), n);
    return out;
}

std::string utf8(const std::wstring& text) {
    if (text.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring lower(std::wstring text) {
    if (text.empty()) return text;
    // LCMapStringEx handles non-ASCII letters the way Windows file names compare
    LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, text.data(), (int)text.size(), text.data(),
                  (int)text.size(), nullptr, nullptr, 0);
    return text;
}

std::wstring trim(const std::wstring& text) {
    std::size_t a = 0, b = text.size();
    while (a < b && iswspace(text[a])) ++a;
    while (b > a && iswspace(text[b - 1])) --b;
    return text.substr(a, b - a);
}

std::wstring strip_quotes(const std::wstring& text) {
    std::size_t a = 0, b = text.size();
    while (a < b && text[a] == L'"') ++a;
    while (b > a && text[b - 1] == L'"') --b;
    return text.substr(a, b - a);
}

bool starts_with(const std::wstring& text, const std::wstring& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::wstring& text, const std::wstring& suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::wstring> split(const std::wstring& text, wchar_t separator) {
    std::vector<std::wstring> parts;
    std::size_t start = 0;
    while (true) {
        std::size_t at = text.find(separator, start);
        if (at == std::wstring::npos) {
            parts.push_back(text.substr(start));
            return parts;
        }
        parts.push_back(text.substr(start, at - start));
        start = at + 1;
    }
}

std::wstring norm_key(const std::wstring& text) {
    std::wstring out;
    for (wchar_t c : text) {
        if (c < 128 && iswalnum(c)) out.push_back((wchar_t)towlower(c));
    }
    return out;
}

std::wstring human_size(std::uint64_t size) {
    double value = (double)size;
    const wchar_t* units[] = {L"B", L"KB", L"MB"};
    wchar_t buf[64];
    for (const wchar_t* unit : units) {
        if (value < 1024) {
            if (unit == units[0]) swprintf(buf, 64, L"%d B", (int)value);
            else swprintf(buf, 64, L"%.1f %ls", value, unit);
            return buf;
        }
        value /= 1024;
    }
    swprintf(buf, 64, L"%.1f GB", value);
    return buf;
}

// endregion

// region Paths

std::wstring system_root() {
    wchar_t buf[MAX_PATH];
    UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
    return n ? std::wstring(buf, n) : L"C:\\Windows";
}

std::wstring system32() { return system_root() + L"\\System32"; }

std::wstring known_folder(int csidl) {
    wchar_t buf[MAX_PATH];
    if (SHGetFolderPathW(nullptr, csidl, nullptr, 0, buf) == S_OK) return buf;
    return L"";
}

std::wstring temp_dir() {
    wchar_t buf[MAX_PATH + 1];
    DWORD n = GetTempPathW(MAX_PATH, buf);
    std::wstring out(buf, n);
    while (out.size() > 3 && (out.back() == L'\\' || out.back() == L'/')) out.pop_back();
    return out;
}

std::wstring exe_dir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return dir_name(std::wstring(buf, n));
}

std::wstring expand_env(const std::wstring& text) {
    if (text.find(L'%') == std::wstring::npos) return text;
    DWORD n = ExpandEnvironmentStringsW(text.c_str(), nullptr, 0);
    if (!n) return text;
    std::wstring out(n, L'\0');
    n = ExpandEnvironmentStringsW(text.c_str(), out.data(), n);
    out.resize(n ? n - 1 : 0);
    return out;
}

std::wstring normcase(const std::wstring& path) {
    std::wstring p = path;
    std::replace(p.begin(), p.end(), L'/', L'\\');
    while (p.size() > 3 && p.back() == L'\\') p.pop_back();
    return lower(p);
}

static std::size_t last_separator(const std::wstring& path) {
    return path.find_last_of(L"\\/");
}

std::wstring base_name(const std::wstring& path) {
    std::wstring p = path;
    while (p.size() > 1 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    std::size_t at = last_separator(p);
    return at == std::wstring::npos ? p : p.substr(at + 1);
}

std::wstring dir_name(const std::wstring& path) {
    std::size_t at = last_separator(path);
    if (at == std::wstring::npos) return L"";
    if (at == 2 && path.size() > 1 && path[1] == L':') return path.substr(0, 3);  // a drive root keeps its slash
    return path.substr(0, at);
}

std::wstring extension(const std::wstring& path) {
    std::wstring name = base_name(path);
    std::size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos || dot == 0) return L"";
    return lower(name.substr(dot));
}

std::wstring join(const std::wstring& folder, const std::wstring& name) {
    if (folder.empty()) return name;
    if (folder.back() == L'\\' || folder.back() == L'/') return folder + name;
    return folder + L"\\" + name;
}

bool is_absolute(const std::wstring& path) {
    if (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) return true;
    return path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\';
}

static std::wstring full_path_name(const std::wstring& path) {
    DWORD n = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!n) return path;
    std::wstring out(n, L'\0');
    n = GetFullPathNameW(path.c_str(), n, out.data(), nullptr);
    out.resize(n);
    return out;
}

std::wstring absolute(const std::wstring& path) {
    if (path.size() <= 3 && path.size() >= 2 && path[1] == L':') return full_path_name(path);   // a drive root
    std::wstring folder = dir_name(path), name = base_name(path);
    if (folder.empty()) folder = L".";
    return join(full_path_name(folder), name);
}

std::wstring long_path(const std::wstring& path) {
    if (starts_with(path, L"\\\\")) return path;
    return L"\\\\?\\" + absolute(path);
}

bool is_reserved_name(const std::wstring& path) {
    static const std::set<std::wstring> reserved = [] {
        std::set<std::wstring> s{L"con", L"prn", L"aux", L"nul"};
        for (int i = 1; i <= 9; ++i) {
            s.insert(L"com" + std::to_wstring(i));
            s.insert(L"lpt" + std::to_wstring(i));
        }
        return s;
    }();
    std::wstring name = base_name(path);
    return reserved.count(lower(name.substr(0, name.find(L'.')))) > 0;
}

bool exists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }

bool lexists(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    return GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) != 0;
}

bool is_file(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool is_dir(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// endregion

// region Files and data folder

std::wstring env_var(const std::wstring& name) {
    DWORD n = GetEnvironmentVariableW(name.c_str(), nullptr, 0);
    if (!n) return L"";
    std::wstring out(n, L'\0');
    n = GetEnvironmentVariableW(name.c_str(), out.data(), n);
    out.resize(n);
    return out;
}

bool make_dirs(const std::wstring& path) {
    if (path.empty() || is_dir(path)) return true;
    std::wstring parent = dir_name(path);
    if (!parent.empty() && parent != path && !is_dir(parent) && !make_dirs(parent)) return false;
    return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

std::wstring data_dir() {
    static std::wstring cached;
    if (!cached.empty()) return cached;
    std::wstring home = env_var(L"DDCLEANER_HOME");
    cached = home.empty() ? join(join(known_folder(0x1A), L"BSM"), L"DDCleaner") : home;   // CSIDL_APPDATA
    make_dirs(cached);
    return cached;
}

std::wstring data_subdir(const std::wstring& name) {
    std::wstring path = join(data_dir(), name);
    make_dirs(path);
    return path;
}

bool read_file(const std::wstring& path, std::string& bytes, std::size_t max_bytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    bool ok = GetFileSizeEx(h, &size) && (std::uint64_t)size.QuadPart <= max_bytes;
    bytes.clear();
    if (ok) {
        bytes.resize((std::size_t)size.QuadPart);
        std::size_t done = 0;
        while (done < bytes.size()) {
            DWORD got = 0;
            if (!ReadFile(h, bytes.data() + done, (DWORD)std::min<std::size_t>(bytes.size() - done, 1u << 24), &got, nullptr) || !got) break;
            done += got;
        }
        bytes.resize(done);
    }
    CloseHandle(h);
    return ok;
}

bool read_file_head(const std::wstring& path, std::string& bytes, std::size_t count) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bytes.assign(count, 0);
    DWORD got = 0;
    BOOL ok = ReadFile(h, bytes.data(), (DWORD)count, &got, nullptr);
    CloseHandle(h);
    bytes.resize(ok ? got : 0);
    return ok != 0;
}

bool write_file(const std::wstring& path, const std::string& bytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::size_t done = 0;
    bool ok = true;
    while (done < bytes.size() && ok) {
        DWORD put = 0;
        ok = WriteFile(h, bytes.data() + done, (DWORD)std::min<std::size_t>(bytes.size() - done, 1u << 24), &put, nullptr) && put;
        done += put;
    }
    CloseHandle(h);
    return ok;
}

bool move_file(const std::wstring& from, const std::wstring& to) {
    return MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_COPY_ALLOWED) != 0;
}

bool delete_file(const std::wstring& path) { return DeleteFileW(path.c_str()) != 0; }

std::wstring timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[32];
    wcsftime(buf, 32, L"%Y%m%d_%H%M%S", &tm);
    return buf;
}

std::wstring safe_name(const std::wstring& text, std::size_t keep) {
    std::wstring out;
    bool in_run = false;
    for (wchar_t c : text) {
        bool good = (c < 128 && iswalnum(c)) || c == L'.' || c == L'_' || c == L'-';
        if (good) {
            out.push_back(c);
            in_run = false;
        } else if (!in_run) {
            out.push_back(L'_');
            in_run = true;
        }
    }
    return out.size() > keep ? out.substr(out.size() - keep) : out;
}

// endregion

// region Directory listing

static double to_seconds(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (double)(u.QuadPart / 10000000ULL) - 11644473600.0;
}

static long long to_nanoseconds(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return ((long long)u.QuadPart - 116444736000000000LL) * 100;
}

static void fill(const WIN32_FIND_DATAW& d, const std::wstring& folder, Entry& e) {
    e.name = d.cFileName;
    e.path = join(folder, d.cFileName);
    e.attributes = d.dwFileAttributes;
    e.size = ((std::uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    e.modified = to_seconds(d.ftLastWriteTime);
    e.mtime_ns = to_nanoseconds(d.ftLastWriteTime);
}

bool list_dir(const std::wstring& folder, std::vector<Entry>& out) {
    out.clear();
    WIN32_FIND_DATAW d;
    HANDLE h = FindFirstFileExW(join(folder, L"*").c_str(), FindExInfoBasic, &d, FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return false;
    do {
        if (!wcscmp(d.cFileName, L".") || !wcscmp(d.cFileName, L"..")) continue;
        Entry e;
        fill(d, folder, e);
        out.push_back(std::move(e));
    } while (FindNextFileW(h, &d));
    FindClose(h);
    return true;
}

bool stat_path(const std::wstring& path, Entry& out) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d)) return false;
    out.name = base_name(path);
    out.path = path;
    out.attributes = d.dwFileAttributes;
    out.size = ((std::uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    out.modified = to_seconds(d.ftLastWriteTime);
    out.mtime_ns = to_nanoseconds(d.ftLastWriteTime);
    return true;
}

double now_seconds() { return (double)std::time(nullptr); }

std::wstring format_date(double seconds) {
    std::time_t t = (std::time_t)seconds;
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[32];
    wcsftime(buf, 32, L"%Y-%m-%d", &tm);
    return buf;
}

std::uint64_t folder_size(const std::wstring& path, const Stop& stop, std::size_t max_files) {
    std::uint64_t total = 0;
    std::size_t seen = 0;
    std::vector<std::wstring> stack{path};
    std::vector<Entry> entries;
    while (!stack.empty() && seen < max_files && !stop()) {
        std::wstring folder = stack.back();
        stack.pop_back();
        if (!list_dir(folder, entries)) continue;
        for (const Entry& e : entries) {
            if (e.is_link()) continue;
            if (e.is_dir()) {
                stack.push_back(e.path);
            } else {
                total += e.size;
                ++seen;
            }
        }
    }
    return total;
}

std::vector<std::wstring> fixed_drives() {
    std::vector<std::wstring> roots;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        std::wstring root = std::wstring(1, (wchar_t)(L'A' + i)) + L":\\";
        if (GetDriveTypeW(root.c_str()) == DRIVE_FIXED) roots.push_back(root);
    }
    return roots;
}

std::vector<DriveUsage> drive_usage(const std::vector<std::wstring>& roots) {
    std::vector<DriveUsage> usage;
    for (const auto& root : roots) {
        ULARGE_INTEGER avail, total, free_bytes;
        if (!GetDiskFreeSpaceExW(root.c_str(), &avail, &total, &free_bytes)) continue;
        usage.push_back({root, total.QuadPart, total.QuadPart - free_bytes.QuadPart, free_bytes.QuadPart});
    }
    return usage;
}

// endregion

}  // namespace dd
