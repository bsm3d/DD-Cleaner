// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares a thin Windows registry wrapper, read-only by default with the 64-bit view, and its typed values.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

namespace dd {

struct RegValue {
    std::wstring name;
    std::wstring text;   // REG_SZ and REG_EXPAND_SZ, empty otherwise
    std::wstring shown;  // text, or the strings of a REG_MULTI_SZ joined by spaces, for display and searching
    DWORD dword = 0;     // REG_DWORD
    std::uint64_t qword = 0;   // REG_QWORD
    DWORD type = 0;
    std::string raw;     // the stored bytes, whatever the type (a binary value is saved as hex in a backup)
    bool is_text() const { return type == REG_SZ || type == REG_EXPAND_SZ; }
};

class RegKey {
public:
    RegKey() = default;
    ~RegKey();
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    RegKey(RegKey&& other) noexcept;
    RegKey& operator=(RegKey&& other) noexcept;

    // hive is "HKLM" or "HKCU". view32 selects the 32-bit view.
    static RegKey open(const std::wstring& hive, const std::wstring& path, bool view32 = false);
    bool valid() const { return handle_ != nullptr; }
    std::vector<std::wstring> subkeys() const;
    std::vector<RegValue> values() const;
    bool get_text(const std::wstring& name, std::wstring& out) const;
    bool get_dword(const std::wstring& name, DWORD& out) const;
    double last_write() const;   // seconds since 1970

    // Writing (64-bit view). Callers check what they delete first: these do exactly what they are told.
    static RegKey open_write(const std::wstring& hive, const std::wstring& path, bool view32 = false);
    // Creates the key when it is missing (64-bit view).
    static RegKey create(const std::wstring& hive, const std::wstring& path);
    LONG set_value(const std::wstring& name, DWORD type, const std::string& bytes) const;
    LONG set_dword(const std::wstring& name, DWORD value) const;
    LONG delete_value(const std::wstring& name) const;
    LONG set_text(const std::wstring& name, const std::wstring& value) const;
    // The key and everything below it (64-bit view). ERROR_SUCCESS or the Windows error code.
    static LONG delete_tree(const std::wstring& hive, const std::wstring& path, int depth = 0);

private:
    HKEY handle_ = nullptr;
};

HKEY hive_handle(const std::wstring& hive);

}  // namespace dd
