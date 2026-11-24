// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the registry wrapper: the hive handle lookup and the read access to keys and values.

#include <ddcore/registry.hpp>

#include <utility>

namespace dd {

HKEY hive_handle(const std::wstring& hive) {
    if (hive == L"HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == L"HKCU") return HKEY_CURRENT_USER;
    return nullptr;
}

RegKey::~RegKey() {
    if (handle_) RegCloseKey(handle_);
}

RegKey::RegKey(RegKey&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

RegKey& RegKey::operator=(RegKey&& other) noexcept {
    if (this != &other) {
        if (handle_) RegCloseKey(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

RegKey RegKey::open(const std::wstring& hive, const std::wstring& path, bool view32) {
    RegKey key;
    HKEY root = hive_handle(hive);
    if (!root) return key;
    REGSAM access = KEY_READ | (view32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);
    if (RegOpenKeyExW(root, path.c_str(), 0, access, &key.handle_) != ERROR_SUCCESS) key.handle_ = nullptr;
    return key;
}

std::vector<std::wstring> RegKey::subkeys() const {
    std::vector<std::wstring> names;
    if (!handle_) return names;
    for (DWORD i = 0;; ++i) {
        wchar_t buf[256];
        DWORD n = 256;
        LONG rc = RegEnumKeyExW(handle_, i, buf, &n, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_SUCCESS) names.emplace_back(buf, n);
    }
    return names;
}

std::vector<RegValue> RegKey::values() const {
    std::vector<RegValue> found;
    if (!handle_) return found;
    DWORD max_name = 0, max_data = 0;
    if (RegQueryInfoKeyW(handle_, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &max_name, &max_data,
                         nullptr, nullptr) != ERROR_SUCCESS)
        return found;
    std::wstring name(max_name + 1, L'\0');
    std::vector<BYTE> data(max_data + 2);
    for (DWORD i = 0;; ++i) {
        DWORD name_len = max_name + 1, data_len = (DWORD)data.size() - 2, type = 0;
        LONG rc = RegEnumValueW(handle_, i, name.data(), &name_len, nullptr, &type, data.data(), &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        RegValue v;
        v.name.assign(name.data(), name_len);
        v.type = type;
        v.raw.assign(reinterpret_cast<const char*>(data.data()), data_len);
        data[data_len] = data[data_len + 1] = 0;
        if (v.is_text()) {
            v.text = reinterpret_cast<const wchar_t*>(data.data());
            v.shown = v.text;
        } else if (type == REG_MULTI_SZ) {
            const wchar_t* p = reinterpret_cast<const wchar_t*>(data.data());
            while (*p) {
                v.shown += (v.shown.empty() ? L"" : L" ") + std::wstring(p);
                p += wcslen(p) + 1;
            }
        } else if (type == REG_DWORD && data_len >= 4) {
            memcpy(&v.dword, data.data(), 4);
        } else if (type == REG_QWORD && data_len >= 8) {
            memcpy(&v.qword, data.data(), 8);
        }
        found.push_back(std::move(v));
    }
    return found;
}

bool RegKey::get_text(const std::wstring& name, std::wstring& out) const {
    for (const RegValue& v : values()) {
        if (v.is_text() && v.name == name) {
            out = v.text;
            return true;
        }
    }
    return false;
}

bool RegKey::get_dword(const std::wstring& name, DWORD& out) const {
    for (const RegValue& v : values()) {
        if (v.type == REG_DWORD && v.name == name) {
            out = v.dword;
            return true;
        }
    }
    return false;
}

double RegKey::last_write() const {
    FILETIME ft{};
    if (!handle_ || RegQueryInfoKeyW(handle_, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                     nullptr, &ft) != ERROR_SUCCESS)
        return 0;
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (double)(u.QuadPart / 10000000ULL) - 11644473600.0;
}

RegKey RegKey::open_write(const std::wstring& hive, const std::wstring& path, bool view32) {
    RegKey key;
    HKEY root = hive_handle(hive);
    if (!root) return key;
    REGSAM access = KEY_READ | KEY_SET_VALUE | (view32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY);
    if (RegOpenKeyExW(root, path.c_str(), 0, access, &key.handle_) != ERROR_SUCCESS) key.handle_ = nullptr;
    return key;
}

RegKey RegKey::create(const std::wstring& hive, const std::wstring& path) {
    RegKey key;
    HKEY root = hive_handle(hive);
    if (!root) return key;
    if (RegCreateKeyExW(root, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key.handle_, nullptr) != ERROR_SUCCESS) key.handle_ = nullptr;
    return key;
}

LONG RegKey::set_value(const std::wstring& name, DWORD type, const std::string& bytes) const {
    if (!handle_) return ERROR_INVALID_HANDLE;
    return RegSetValueExW(handle_, name.c_str(), 0, type, reinterpret_cast<const BYTE*>(bytes.data()), (DWORD)bytes.size());
}

LONG RegKey::set_dword(const std::wstring& name, DWORD value) const {
    return set_value(name, REG_DWORD, std::string(reinterpret_cast<const char*>(&value), 4));
}

LONG RegKey::delete_value(const std::wstring& name) const {
    return handle_ ? RegDeleteValueW(handle_, name.c_str()) : ERROR_INVALID_HANDLE;
}

LONG RegKey::set_text(const std::wstring& name, const std::wstring& value) const {
    if (!handle_) return ERROR_INVALID_HANDLE;
    return RegSetValueExW(handle_, name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                          (DWORD)((value.size() + 1) * sizeof(wchar_t)));
}

LONG RegKey::delete_tree(const std::wstring& hive, const std::wstring& path, int depth) {
    if (depth > 64) return ERROR_BAD_PATHNAME;   // a tree this deep is not a program's key
    HKEY root = hive_handle(hive);
    if (!root) return ERROR_INVALID_PARAMETER;
    std::vector<std::wstring> children;
    {
        RegKey key = RegKey::open(hive, path);
        if (!key.valid()) return ERROR_SUCCESS;   // already gone
        children = key.subkeys();
    }
    for (const auto& child : children) {
        LONG rc = delete_tree(hive, path + L"\\" + child, depth + 1);
        if (rc != ERROR_SUCCESS) return rc;
    }
    LONG rc = RegDeleteKeyExW(root, path.c_str(), KEY_WOW64_64KEY, 0);
    return rc == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : rc;
}

}  // namespace dd
