// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the secrets reader: DPAPI and AES-GCM decryption, Wi-Fi profile reads and Credential Manager entries.

#include <ddcore/secrets.hpp>

#include <algorithm>
#include <regex>
#include <set>

#include <windows.h>

#include <wincrypt.h>
#include <bcrypt.h>
#include <wincred.h>
#include <wlanapi.h>

#include <sqlite3.h>

#include <ddcore/inspect.hpp>
#include <ddcore/net.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>

namespace dd {

namespace {

std::string blob_string(const DATA_BLOB& b) { return std::string(reinterpret_cast<const char*>(b.pbData), b.cbData); }

std::string status_text(NTSTATUS status, const char* name) {
    char buf[96];
    snprintf(buf, sizeof(buf), "%s failed: 0x%08lX", name, (unsigned long)status);
    return buf;
}

constexpr NTSTATUS AUTH_TAG_MISMATCH = (NTSTATUS)0xC000A002;

void check(NTSTATUS status, const char* name) {
    if (status == 0) return;
    if (status == AUTH_TAG_MISMATCH) throw CryptoError("AES-GCM authentication failed (wrong key or tampered data).");
    throw CryptoError(status_text(status, name));
}

// An open CNG AES-GCM key; the handles are always released
struct GcmKey {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    explicit GcmKey(const std::string& secret) {
        try {
            check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0), "BCryptOpenAlgorithmProvider");
            check(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0), "BCryptSetProperty");
            check(BCryptGenerateSymmetricKey(alg, &key, nullptr, 0, (PUCHAR)secret.data(), (ULONG)secret.size(), 0), "BCryptGenerateSymmetricKey");
        } catch (...) {
            release();
            throw;
        }
    }
    ~GcmKey() { release(); }
    GcmKey(const GcmKey&) = delete;
    GcmKey& operator=(const GcmKey&) = delete;
    void release() {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        key = nullptr;
        alg = nullptr;
    }
};

bool is_printable_unit(wchar_t c) {
    if (c < 0x20 || (c >= 0x7F && c <= 0xA0) || c == 0xAD) return false;   // controls, no-break space, soft hyphen
    if ((c >= 0x2000 && c <= 0x200F) || (c >= 0x2028 && c <= 0x202F) || (c >= 0x205F && c <= 0x206F)) return false;   // spaces, separators, format
    if (c == 0x3000 || c == 0xFEFF || c == 0xFFFE || c == 0xFFFF) return false;
    if (c >= 0xE000 && c <= 0xF8FF) return false;   // private use
    return true;
}

// Python's str.isprintable(), close enough for the characters a password holds
bool is_printable(const std::wstring& s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        wchar_t c = s[i];
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
                ++i;
                continue;
            }
            return false;
        }
        if (c >= 0xDC00 && c <= 0xDFFF) return false;
        if (!is_printable_unit(c)) return false;
    }
    return true;
}

bool strict_utf8(const std::string& bytes, std::wstring& out) {
    if (bytes.empty()) {
        out.clear();
        return true;
    }
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (n <= 0) return false;
    out.assign((std::size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), out.data(), n);
    return true;
}

bool strict_utf16le(const std::string& bytes, std::wstring& out) {
    if (bytes.size() % 2) return false;
    out.assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        wchar_t c = out[i];
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 >= out.size() || out[i + 1] < 0xDC00 || out[i + 1] > 0xDFFF) return false;
            ++i;
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            return false;
        }
    }
    return true;
}

std::wstring host_of(const std::wstring& url) {
    std::wstring rest = url;
    static const std::wregex scheme(LR"(^[A-Za-z][A-Za-z0-9+.\-]*:)");
    std::wsmatch m;
    if (std::regex_search(rest, m, scheme)) rest = m.suffix().str();
    if (rest.compare(0, 2, L"//") == 0) {
        std::wstring netloc = rest.substr(2, rest.find_first_of(L"/?#", 2) == std::wstring::npos ? std::wstring::npos : rest.find_first_of(L"/?#", 2) - 2);
        if (!netloc.empty()) return netloc;
    }
    return url.empty() ? L"(unknown site)" : url;
}

std::wstring strip(const std::wstring& s) { return trim(s); }

}  // namespace

// region Crypto

std::string dpapi_unprotect(const std::string& data, const std::string& entropy) {
    DATA_BLOB in{(DWORD)data.size(), (BYTE*)data.data()}, out{}, ent{(DWORD)entropy.size(), (BYTE*)entropy.data()};
    if (!CryptUnprotectData(&in, nullptr, entropy.empty() ? nullptr : &ent, nullptr, nullptr, 0, &out)) throw CryptoError("CryptUnprotectData failed (data not encrypted for this user).");
    std::string result = blob_string(out);
    LocalFree(out.pbData);
    return result;
}

std::string dpapi_protect(const std::string& data, const std::string& entropy) {
    DATA_BLOB in{(DWORD)data.size(), (BYTE*)data.data()}, out{}, ent{(DWORD)entropy.size(), (BYTE*)entropy.data()};
    if (!CryptProtectData(&in, L"", entropy.empty() ? nullptr : &ent, nullptr, nullptr, 0, &out)) throw CryptoError("CryptProtectData failed.");
    std::string result = blob_string(out);
    LocalFree(out.pbData);
    return result;
}

std::string aes_gcm_decrypt(const std::string& key, const std::string& nonce, const std::string& ciphertext, const std::string& tag, const std::string& aad) {
    GcmKey gcm(key);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce.data();
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag = (PUCHAR)tag.data();
    info.cbTag = (ULONG)tag.size();
    if (!aad.empty()) {
        info.pbAuthData = (PUCHAR)aad.data();
        info.cbAuthData = (ULONG)aad.size();
    }
    std::string out(ciphertext.size() + 1, '\0');
    ULONG written = 0;
    check(BCryptDecrypt(gcm.key, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), &info, nullptr, 0, (PUCHAR)out.data(), (ULONG)ciphertext.size(), &written, 0), "BCryptDecrypt");
    out.resize(written);
    return out;
}

std::pair<std::string, std::string> aes_gcm_encrypt(const std::string& key, const std::string& nonce, const std::string& plaintext, const std::string& aad) {
    GcmKey gcm(key);
    std::string tag(16, '\0');
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce.data();
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag = (PUCHAR)tag.data();
    info.cbTag = (ULONG)tag.size();
    if (!aad.empty()) {
        info.pbAuthData = (PUCHAR)aad.data();
        info.cbAuthData = (ULONG)aad.size();
    }
    std::string out(plaintext.size() + 1, '\0');
    ULONG written = 0;
    check(BCryptEncrypt(gcm.key, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(), &info, nullptr, 0, (PUCHAR)out.data(), (ULONG)plaintext.size(), &written, 0), "BCryptEncrypt");
    out.resize(written);
    return {out, tag};
}

std::string base64_decode(const std::string& text, bool* ok) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    unsigned value = 0;
    int bits = 0, chars = 0, pad = 0;
    for (char c : text) {
        if (c == '=') {
            ++pad;
            continue;
        }
        std::size_t at = alphabet.find(c);
        if (at == std::string::npos) continue;   // characters outside the alphabet are ignored, as Python's b64decode does
        if (pad) break;                          // data after the padding
        value = (value << 6) | (unsigned)at;
        bits += 6;
        ++chars;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((value >> bits) & 0xFF));
        }
    }
    bool good = chars % 4 != 1 && ((chars + pad) % 4 == 0);
    if (ok) *ok = good;
    return out;
}

// endregion

// region Wi-Fi

WifiProfile parse_profile_xml(const std::wstring& xml) {
    if (xml.find(L"<!DOCTYPE") != std::wstring::npos || xml.find(L"<!ENTITY") != std::wstring::npos) throw std::runtime_error("unexpected DTD in a WLAN profile");
    XmlNode root = parse_xml(utf8(xml));
    auto path_text = [&](std::initializer_list<const wchar_t*> path) -> std::wstring {
        const XmlNode* node = &root;
        for (const wchar_t* step : path) {
            node = node->child(step);
            if (!node) return L"";
        }
        return node->text;
    };
    WifiProfile p;
    p.name = path_text({L"name"});
    if (p.name.empty()) p.name = path_text({L"SSIDConfig", L"SSID", L"name"});
    p.authentication = path_text({L"MSM", L"security", L"authEncryption", L"authentication"});
    p.encryption = path_text({L"MSM", L"security", L"authEncryption", L"encryption"});
    const XmlNode* security = root.child(L"MSM") ? root.child(L"MSM")->child(L"security") : nullptr;
    const XmlNode* shared = security ? security->child(L"sharedKey") : nullptr;
    if (shared) {
        const XmlNode* prot = shared->child(L"protected");
        const XmlNode* material = shared->child(L"keyMaterial");
        bool is_protected = prot && lower(prot->text) == L"true";
        p.readable = !is_protected;
        p.password = is_protected || !material ? L"" : material->text;
    }
    return p;
}

namespace {

struct WlanApi {
    HMODULE lib = nullptr;
    DWORD(WINAPI* open)(DWORD, PVOID, PDWORD, PHANDLE) = nullptr;
    DWORD(WINAPI* close)(HANDLE, PVOID) = nullptr;
    VOID(WINAPI* free_memory)(PVOID) = nullptr;
    DWORD(WINAPI* enum_interfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*) = nullptr;
    DWORD(WINAPI* profile_list)(HANDLE, const GUID*, PVOID, PWLAN_PROFILE_INFO_LIST*) = nullptr;
    DWORD(WINAPI* get_profile)(HANDLE, const GUID*, LPCWSTR, PVOID, LPWSTR*, DWORD*, DWORD*) = nullptr;

    WlanApi() {
        lib = LoadLibraryExW((system32() + L"\\wlanapi.dll").c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!lib) return;
        auto sym = [&](const char* name) { return (void*)GetProcAddress(lib, name); };
        open = reinterpret_cast<decltype(open)>(sym("WlanOpenHandle"));
        close = reinterpret_cast<decltype(close)>(sym("WlanCloseHandle"));
        free_memory = reinterpret_cast<decltype(free_memory)>(sym("WlanFreeMemory"));
        enum_interfaces = reinterpret_cast<decltype(enum_interfaces)>(sym("WlanEnumInterfaces"));
        profile_list = reinterpret_cast<decltype(profile_list)>(sym("WlanGetProfileList"));
        get_profile = reinterpret_cast<decltype(get_profile)>(sym("WlanGetProfile"));
    }
    ~WlanApi() {
        if (lib) FreeLibrary(lib);
    }
    bool ok() const { return lib && open && close && free_memory && enum_interfaces && profile_list && get_profile; }
};

}  // namespace

std::vector<WifiProfile> wifi_profiles() {
    WlanApi api;
    if (!api.ok()) return {};
    HANDLE handle = nullptr;
    DWORD version = 0;
    if (api.open(2, nullptr, &version, &handle) != 0) return {};   // the WLAN service is not running: no Wi-Fi on this PC
    std::vector<WifiProfile> profiles;
    PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
    if (api.enum_interfaces(handle, nullptr, &interfaces) == 0 && interfaces) {
        std::set<std::wstring> seen;
        for (DWORD i = 0; i < interfaces->dwNumberOfItems; ++i) {
            const GUID guid = interfaces->InterfaceInfo[i].InterfaceGuid;
            PWLAN_PROFILE_INFO_LIST names = nullptr;
            if (api.profile_list(handle, &guid, nullptr, &names) != 0 || !names) continue;
            std::vector<std::wstring> profile_names;
            for (DWORD k = 0; k < names->dwNumberOfItems; ++k) profile_names.push_back(names->ProfileInfo[k].strProfileName);
            api.free_memory(names);
            for (const auto& name : profile_names) {
                if (!seen.insert(name).second) continue;
                LPWSTR xml = nullptr;
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY, access = 0;
                if (api.get_profile(handle, &guid, name.c_str(), nullptr, &xml, &flags, &access) != 0) {
                    WifiProfile p;
                    p.name = name;
                    p.readable = false;
                    profiles.push_back(p);
                    continue;
                }
                WifiProfile p;
                try {
                    p = parse_profile_xml(xml);
                } catch (const std::exception&) {
                    p = WifiProfile();
                    p.name = name;
                    p.readable = false;
                }
                api.free_memory(xml);
                if (p.name.empty()) p.name = name;
                profiles.push_back(p);
            }
        }
        api.free_memory(interfaces);
    }
    api.close(handle, nullptr);
    std::sort(profiles.begin(), profiles.end(), [](const WifiProfile& a, const WifiProfile& b) { return lower(a.name) < lower(b.name); });
    return profiles;
}

// endregion

std::wstring windows_firmware_key(const std::function<Json(const std::wstring&)>& run) {
    const std::wstring script = L"ConvertTo-Json -InputObject ([string](Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey) -Compress";
    Json data = run ? run(script) : run_powershell_json(script, 60000);
    std::wstring key = data.is_string() ? trim(data.str()) : L"";
    static const std::wregex shape(LR"(^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$)");
    return std::regex_match(key, shape) ? key : L"";
}

// region Software license keys

namespace {

const std::vector<std::pair<std::wstring, std::wstring>>& license_roots() {
    static const std::vector<std::pair<std::wstring, std::wstring>> v = {
        {L"Office", L"SOFTWARE\\Microsoft\\Office"},           {L"Office (32-bit)", L"SOFTWARE\\WOW6432Node\\Microsoft\\Office"},
        {L"Adobe", L"SOFTWARE\\Adobe"},                        {L"Adobe (32-bit)", L"SOFTWARE\\WOW6432Node\\Adobe"},
        {L"Autodesk", L"SOFTWARE\\Autodesk"},                  {L"Autodesk (32-bit)", L"SOFTWARE\\WOW6432Node\\Autodesk"},
        {L"VMware", L"SOFTWARE\\VMware, Inc."}};
    return v;
}
constexpr int LICENSE_MAX_DEPTH = 6;
constexpr int LICENSE_MAX_KEYS = 20000;

bool looks_like_key(const std::wstring& value) {
    static const std::wregex shape(LR"(^[A-Za-z0-9][A-Za-z0-9.+/=_\-]{4,99}$)");
    std::wstring t = strip(value);
    return t.find(L' ') == std::wstring::npos && std::regex_match(t, shape);
}

void walk_license(const RegistryWalker& walker, const std::wstring& path, const std::wstring& label, int depth, int& counter, std::vector<SecretRecord>& out) {
    static const std::set<std::wstring> names = {L"productid", L"serialnumber", L"licensekey", L"productkey", L"pidkey", L"serial", L"regkey"};
    if (depth > LICENSE_MAX_DEPTH || counter > LICENSE_MAX_KEYS) return;
    ++counter;
    std::vector<std::pair<std::wstring, std::wstring>> values;
    std::vector<std::wstring> subs;
    if (!walker.open(path, values, subs)) return;
    for (const auto& [name, text] : values) {
        if (names.count(lower(name)) && looks_like_key(text)) {
            std::size_t slash = path.rfind(L'\\');
            std::wstring product = slash == std::wstring::npos ? path : path.substr(slash + 1);
            SecretRecord r;
            r.kind = L"License";
            r.name = label;
            r.info = product.empty() ? label : product;
            r.value = strip(text);
            out.push_back(r);
        }
    }
    for (const auto& sub : subs) walk_license(walker, path + L"\\" + sub, label, depth + 1, counter, out);
}

}  // namespace

std::vector<SecretRecord> software_license_keys(const RegistryWalker* walker_in) {
    RegistryWalker real;
    if (!walker_in) {
        real.open = [](const std::wstring& path, std::vector<std::pair<std::wstring, std::wstring>>& values, std::vector<std::wstring>& subs) {
            RegKey key = RegKey::open(L"HKLM", path);
            if (!key.valid()) return false;
            for (const RegValue& v : key.values()) {
                if (v.is_text()) values.emplace_back(v.name, v.text);
            }
            subs = key.subkeys();
            return true;
        };
    }
    const RegistryWalker& walker = walker_in ? *walker_in : real;
    std::set<std::pair<std::wstring, std::wstring>> seen;
    std::vector<SecretRecord> out;
    for (const auto& [label, root] : license_roots()) {
        int counter = 0;   // one budget per vendor root: a large Office tree must not starve Adobe/Autodesk/VMware
        std::vector<SecretRecord> found;
        walk_license(walker, root, label, 0, counter, found);
        for (auto& r : found) {
            if (seen.insert({r.name, r.value}).second) out.push_back(r);
        }
    }
    return out;
}

// endregion

// region Credential Manager

std::vector<StoredCredential> enumerate_credentials() {
    DWORD count = 0;
    PCREDENTIALW* array = nullptr;
    if (!CredEnumerateW(nullptr, 0, &count, &array)) return {};   // ERROR_NOT_FOUND when the vault is empty
    std::vector<StoredCredential> out;
    for (DWORD i = 0; i < count; ++i) {
        const CREDENTIALW& c = *array[i];
        StoredCredential s;
        s.target = c.TargetName ? c.TargetName : L"";
        s.user = c.UserName ? c.UserName : L"";
        s.type = (int)c.Type;
        if (c.CredentialBlobSize) s.blob.assign(reinterpret_cast<const char*>(c.CredentialBlob), c.CredentialBlobSize);
        out.push_back(s);
    }
    CredFree(array);
    return out;
}

namespace {
// A blob of UTF-16-LE text (the usual Credential Manager format) has a zero high byte in most code units
bool looks_utf16(const std::string& blob) {
    if (blob.size() < 2 || blob.size() % 2) return false;
    std::size_t zeros = 0, highs = blob.size() / 2;
    for (std::size_t i = 1; i < blob.size(); i += 2) {
        if (blob[i] == 0) ++zeros;
    }
    return (double)zeros >= (double)highs * 0.6;
}
}  // namespace

DecodedBlob decode_credential_blob(const std::string& blob, int type) {
    DecodedBlob r;
    if (blob.empty()) {
        r.note = L"(no secret stored)";
        return r;
    }
    if (type == 2) {   // CRED_TYPE_DOMAIN_PASSWORD
        r.readable = false;
        r.note = L"domain password (not retrievable in clear)";
        return r;
    }
    std::wstring text;
    if (looks_utf16(blob) && strict_utf16le(blob, text)) {
        while (!text.empty() && text.back() == L'\0') text.pop_back();
        if (!text.empty() && is_printable(text)) {
            r.secret = text;
            return r;
        }
    }
    if (strict_utf8(blob, text) && !text.empty() && is_printable(text)) {
        r.secret = text;
        return r;
    }
    r.readable = false;
    r.note = L"binary secret";
    return r;
}

std::vector<SecretRecord> credential_manager_entries(const std::function<std::vector<StoredCredential>()>& enumerate) {
    std::vector<SecretRecord> out;
    for (const auto& c : enumerate ? enumerate() : enumerate_credentials()) {
        DecodedBlob d = decode_credential_blob(c.blob, c.type);
        SecretRecord r;
        r.kind = L"Windows credential";
        r.name = c.target;
        r.info = c.user;
        r.value = d.secret;
        r.readable = d.readable;
        r.note = d.note;
        out.push_back(r);
    }
    return out;
}

// endregion

// region Chromium

namespace {

const std::vector<std::pair<std::wstring, std::wstring>>& chromium_browsers() {
    static const std::vector<std::pair<std::wstring, std::wstring>> v = {{L"Chrome", L"Google\\Chrome\\User Data"},
                                                                         {L"Edge", L"Microsoft\\Edge\\User Data"},
                                                                         {L"Brave", L"BraveSoftware\\Brave-Browser\\User Data"},
                                                                         {L"Vivaldi", L"Vivaldi\\User Data"}};
    return v;
}

std::string uri_encode(const std::string& s) {
    std::string out;
    char hex[4];
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '/' || c == ':') {
            out.push_back((char)c);
        } else {
            snprintf(hex, sizeof(hex), "%%%02X", c);
            out += hex;
        }
    }
    return out;
}

struct LoginRow {
    std::wstring url, user;
    std::string blob;
};

// Copy the (locked) SQLite file, and any pending -wal/-journal beside it, to a temporary file read only, then delete the copies.
// Throws std::runtime_error when it cannot be read.
std::vector<LoginRow> read_login_rows(const std::wstring& login_data_path) {
    std::wstring temp = join(data_subdir(L"tmp"), L"logins_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()) + L".db");
    std::vector<std::wstring> made;
    std::vector<LoginRow> rows;
    std::string error;
    auto cleanup = [&] {
        for (const auto& p : made) DeleteFileW(p.c_str());
    };
    try {
        if (!CopyFileW(login_data_path.c_str(), temp.c_str(), FALSE)) throw std::runtime_error("the login database could not be copied");
        made.push_back(temp);
        for (const wchar_t* suffix : {L"-wal", L"-journal"}) {
            std::wstring source = login_data_path + suffix;
            if (is_file(source) && CopyFileW(source.c_str(), (temp + suffix).c_str(), FALSE)) made.push_back(temp + suffix);
        }
        std::string uri = "file:///" + uri_encode(utf8(temp)) + "?mode=ro";
        for (auto& c : uri) {
            if (c == '\\') c = '/';
        }
        sqlite3* db = nullptr;
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            error = db ? sqlite3_errmsg(db) : "sqlite3_open failed";
            if (db) sqlite3_close(db);
            throw std::runtime_error(error);
        }
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &st, nullptr) != SQLITE_OK) {
            error = sqlite3_errmsg(db);
            sqlite3_close(db);
            throw std::runtime_error(error);
        }
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            LoginRow r;
            const char* url = (const char*)sqlite3_column_text(st, 0);
            const char* user = (const char*)sqlite3_column_text(st, 1);
            r.url = url ? wide(url) : L"";
            r.user = user ? wide(user) : L"";
            const void* blob = sqlite3_column_blob(st, 2);
            int size = sqlite3_column_bytes(st, 2);
            if (blob && size > 0) r.blob.assign(static_cast<const char*>(blob), (std::size_t)size);
            rows.push_back(std::move(r));
        }
        if (rc != SQLITE_DONE) error = sqlite3_errmsg(db);
        sqlite3_finalize(st);
        sqlite3_close(db);
        if (!error.empty()) throw std::runtime_error(error);
    } catch (...) {
        cleanup();
        throw;
    }
    cleanup();
    return rows;
}

}  // namespace

std::vector<std::pair<std::wstring, std::wstring>> chromium_user_data_dirs(const std::wstring& base_in) {
    std::wstring base = base_in.empty() ? env_var(L"LOCALAPPDATA") : base_in;
    std::vector<std::pair<std::wstring, std::wstring>> out;
    if (base.empty()) return out;
    for (const auto& [name, rel] : chromium_browsers()) {
        if (is_dir(join(base, rel))) out.emplace_back(name, join(base, rel));
    }
    return out;
}

std::string chromium_master_key(const std::wstring& user_data_dir, const Unprotect& unprotect) {
    std::string bytes;
    Json state;
    if (!read_file(join(user_data_dir, L"Local State"), bytes)) throw std::runtime_error("Local State cannot be read");
    if (!try_parse_json(wide(bytes), state)) throw std::runtime_error("Local State is not valid JSON");
    const Json& key = state.get(L"os_crypt").get(L"encrypted_key");
    if (!key.is_string()) throw std::runtime_error("no encrypted_key in Local State");
    bool ok = false;
    std::string encrypted = base64_decode(utf8(key.str()), &ok);
    if (!ok) throw std::runtime_error("encrypted_key is not valid base64");
    if (encrypted.compare(0, 5, "DPAPI") != 0 || encrypted.size() < 5) throw std::runtime_error("unexpected Local State key format");
    std::string wrapped = encrypted.substr(5);
    return unprotect ? unprotect(wrapped) : dpapi_unprotect(wrapped);
}

std::wstring decrypt_chromium_value(const std::string& blob, const std::string& key, const Unprotect& unprotect) {
    if (blob.empty()) return L"";
    if (blob.compare(0, 3, "v20") == 0) throw AppBoundValue();
    if (blob.compare(0, 3, "v10") == 0 || blob.compare(0, 3, "v11") == 0) {
        if (blob.size() < 3 + 12 + 16) throw CryptoError("the encrypted value is too short");
        std::string plain = aes_gcm_decrypt(key, blob.substr(3, 12), blob.substr(15, blob.size() - 15 - 16), blob.substr(blob.size() - 16));
        return wide(plain);
    }
    return wide(unprotect ? unprotect(blob) : dpapi_unprotect(blob));
}

std::vector<SecretRecord> chromium_logins(const std::wstring& name, const std::wstring& user_data_dir, const Unprotect& unprotect) {
    std::string key;
    try {
        key = chromium_master_key(user_data_dir, unprotect);
    } catch (const std::exception&) {
        SecretRecord r;
        r.kind = name;
        r.name = L"(all profiles)";
        r.readable = false;
        r.note = L"encryption key not readable";
        return {r};
    }
    std::vector<std::wstring> profiles;
    std::vector<Entry> entries;
    if (list_dir(user_data_dir, entries)) {
        for (const Entry& e : entries) {
            if (e.is_dir() && is_file(join(e.path, L"Login Data"))) profiles.push_back(e.path);
        }
    }
    std::sort(profiles.begin(), profiles.end());
    std::vector<SecretRecord> records;
    for (const auto& profile : profiles) {
        std::wstring label = base_name(profile);
        std::vector<LoginRow> rows;
        try {
            rows = read_login_rows(join(profile, L"Login Data"));
        } catch (const std::exception&) {
            continue;   // that profile's database is unreadable: the others still count
        }
        for (const auto& row : rows) {
            if (row.user.empty() && row.blob.empty()) continue;
            SecretRecord r;
            r.kind = name;
            r.name = host_of(row.url);
            r.info = row.user;
            if (label != L"Default") r.info = strip(r.info + L"  (" + label + L")");
            try {
                r.value = decrypt_chromium_value(row.blob, key, unprotect);
            } catch (const AppBoundValue&) {
                r.readable = false;
                r.note = L"app-bound encryption (Chrome 127+), not readable";
            } catch (const std::exception&) {
                r.readable = false;
                r.note = L"could not decrypt";
            }
            records.push_back(r);
        }
    }
    return records;
}

// endregion

// region Firefox (NSS)

namespace {

struct SecItem {
    unsigned type;
    void* data;
    unsigned len;
};

std::wstring find_firefox_nss() {
    for (const wchar_t* variable : {L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)"}) {
        std::wstring root = env_var(variable);
        if (!root.empty() && is_file(join(root, L"Mozilla Firefox\\nss3.dll"))) return join(root, L"Mozilla Firefox");
    }
    return L"";
}

std::vector<SecretRecord> undecrypted(const std::wstring& profile, const std::wstring& note) {
    std::vector<SecretRecord> out;
    std::string bytes;
    if (!read_file(join(profile, L"logins.json"), bytes)) return out;
    try {
        for (const auto& l : parse_firefox_logins(wide(bytes))) {
            SecretRecord r;
            r.kind = L"Firefox";
            r.name = l.hostname.empty() ? base_name(profile) : host_of(l.hostname);
            r.readable = false;
            r.note = note;
            out.push_back(r);
        }
    } catch (const std::exception&) {
        out.clear();
    }
    return out;
}

// Firefox's NSS library, loaded from its own (administrator-protected) folder, used to decrypt one profile's logins. A primary
// password, or any native failure, leaves the passwords unreadable.
class Nss {
public:
    explicit Nss(const std::wstring& dir) {
        lib_ = LoadLibraryExW(join(dir, L"nss3.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!lib_) throw std::runtime_error("nss3.dll could not be loaded");
        initialize = sym<int(__cdecl*)(const char*, const char*, const char*, const char*, unsigned)>("NSS_Initialize");
        shutdown = sym<int(__cdecl*)()>("NSS_Shutdown");
        internal_slot = sym<void*(__cdecl*)()>("PK11_GetInternalKeySlot");
        free_slot = sym<void(__cdecl*)(void*)>("PK11_FreeSlot");
        authenticate = sym<int(__cdecl*)(void*, int, void*)>("PK11_Authenticate");
        sdr_decrypt = sym<int(__cdecl*)(SecItem*, SecItem*, void*)>("PK11SDR_Decrypt");
        zfree = reinterpret_cast<void(__cdecl*)(SecItem*, int)>(GetProcAddress(lib_, "SECITEM_ZfreeItem"));   // optional
        if (!initialize || !shutdown || !internal_slot || !free_slot || !authenticate || !sdr_decrypt) {
            FreeLibrary(lib_);
            throw std::runtime_error("nss3.dll does not have the functions needed");
        }
    }
    ~Nss() {
        if (lib_) FreeLibrary(lib_);
    }
    Nss(const Nss&) = delete;
    Nss& operator=(const Nss&) = delete;

    std::vector<SecretRecord> profile_logins(const std::wstring& profile) {
        // read only: Firefox may have the profile open at the same time
        std::string config = "sql:" + utf8(profile);
        if (initialize(config.c_str(), "", "", "secmod.db", 0x1 /* NSS_INIT_READONLY */) != 0) return undecrypted(profile, L"NSS could not open the profile");
        std::vector<SecretRecord> records;
        void* slot = internal_slot();
        bool authenticated = true;
        if (slot) {
            authenticated = authenticate(slot, 1, nullptr) == 0;
            free_slot(slot);
        }
        if (!authenticated) {
            shutdown();
            return undecrypted(profile, L"protected by a primary password");
        }
        std::string bytes;
        std::vector<FirefoxLogin> logins;
        if (read_file(join(profile, L"logins.json"), bytes)) {
            try {
                logins = parse_firefox_logins(wide(bytes));
            } catch (const std::exception&) {
            }
        }
        for (const auto& l : logins) {
            bool user_ok = true, pass_ok = true;
            std::wstring user = decrypt(l.encrypted_user, user_ok), password = decrypt(l.encrypted_password, pass_ok);
            SecretRecord r;
            r.kind = L"Firefox";
            r.name = l.hostname.empty() ? base_name(profile) : host_of(l.hostname);
            r.info = user_ok ? user : L"";
            r.value = pass_ok ? password : L"";
            r.readable = pass_ok;
            r.note = pass_ok ? L"" : L"could not decrypt";
            records.push_back(r);
        }
        shutdown();   // close this profile before the next NSS_Initialize
        return records;
    }

private:
    template <class F>
    F sym(const char* name) {
        return reinterpret_cast<F>(GetProcAddress(lib_, name));
    }
    std::wstring decrypt(const std::wstring& b64, bool& ok) {
        ok = true;
        if (b64.empty()) return L"";
        bool valid = false;
        std::string raw = base64_decode(utf8(b64), &valid);
        if (!valid) {
            ok = false;
            return L"";
        }
        SecItem in{0, raw.data(), (unsigned)raw.size()}, out{0, nullptr, 0};
        if (sdr_decrypt(&in, &out, nullptr) != 0) {
            ok = false;
            return L"";
        }
        std::wstring text = wide(std::string(static_cast<const char*>(out.data), out.len));
        if (zfree) zfree(&out, 0);
        return text;
    }

    HMODULE lib_ = nullptr;
    int(__cdecl* initialize)(const char*, const char*, const char*, const char*, unsigned) = nullptr;
    int(__cdecl* shutdown)() = nullptr;
    void*(__cdecl* internal_slot)() = nullptr;
    void(__cdecl* free_slot)(void*) = nullptr;
    int(__cdecl* authenticate)(void*, int, void*) = nullptr;
    int(__cdecl* sdr_decrypt)(SecItem*, SecItem*, void*) = nullptr;
    void(__cdecl* zfree)(SecItem*, int) = nullptr;
};

}  // namespace

std::vector<std::wstring> firefox_profiles(const std::wstring& base_in) {
    std::wstring base = base_in.empty() ? env_var(L"APPDATA") : base_in;
    std::wstring root = join(base, L"Mozilla\\Firefox\\Profiles");
    std::vector<std::wstring> out;
    std::vector<Entry> entries;
    if (base.empty() || !list_dir(root, entries)) return out;
    for (const Entry& e : entries) {
        if (e.is_dir() && is_file(join(e.path, L"logins.json")) && is_file(join(e.path, L"key4.db"))) out.push_back(e.path);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<FirefoxLogin> parse_firefox_logins(const std::wstring& json_text) {
    Json data;
    if (!try_parse_json(json_text, data)) throw std::runtime_error("logins.json is not valid JSON");
    std::vector<FirefoxLogin> out;
    for (const Json& e : data.get(L"logins").as_list()) {
        if (!e.is_object()) continue;
        out.push_back({e.get(L"hostname").str(), e.get(L"encryptedUsername").str(), e.get(L"encryptedPassword").str()});
    }
    return out;
}

std::vector<SecretRecord> firefox_logins() {
    std::vector<std::wstring> profiles = firefox_profiles();
    if (profiles.empty()) return {};
    auto all = [&](const std::wstring& note) {
        std::vector<SecretRecord> out;
        for (const auto& p : profiles) {
            auto part = undecrypted(p, note);
            out.insert(out.end(), part.begin(), part.end());
        }
        return out;
    };
    std::wstring nss_dir = find_firefox_nss();
    if (nss_dir.empty()) return all(L"Firefox is not installed to decrypt the logins");
    if (!folder_risk(nss_dir).empty()) return all(L"Firefox folder not protected; not decrypted");   // never load a DLL a standard user can replace
    try {
        Nss nss(nss_dir);
        std::vector<SecretRecord> out;
        for (const auto& p : profiles) {
            auto part = nss.profile_logins(p);
            out.insert(out.end(), part.begin(), part.end());
        }
        return out;
    } catch (const std::exception&) {
        return all(L"NSS could not be loaded");
    }
}

std::vector<SecretRecord> browser_logins() {
    std::vector<SecretRecord> records;
    for (const auto& [name, dir] : chromium_user_data_dirs()) {
        try {
            auto part = chromium_logins(name, dir);
            records.insert(records.end(), part.begin(), part.end());
        } catch (const std::exception&) {
        }
    }
    try {
        auto part = firefox_logins();
        records.insert(records.end(), part.begin(), part.end());
    } catch (const std::exception&) {
    }
    return records;
}

// endregion

std::vector<SecretRecord> collect_secrets(const SecretSources& sources) {
    std::vector<SecretRecord> records;
    auto add = [&](const std::vector<SecretRecord>& part) { records.insert(records.end(), part.begin(), part.end()); };
    if (sources.wifi) {
        try {
            for (const auto& p : wifi_profiles()) {
                SecretRecord r;
                r.kind = L"Wi-Fi";
                r.name = p.name;
                r.info = p.authentication;
                if (!p.encryption.empty()) r.info += (r.info.empty() ? L"" : L" / ") + p.encryption;
                r.value = p.password;
                r.readable = p.readable;
                r.note = !p.password.empty() ? L"" : (!p.readable ? L"not readable" : L"open or enterprise network");
                records.push_back(r);
            }
        } catch (const std::exception&) {
        }
    }
    if (sources.windows_key) {
        try {
            std::wstring key = windows_firmware_key();
            if (!key.empty()) {
                SecretRecord r;
                r.kind = L"Windows key";
                r.name = L"Stored in the firmware";
                r.info = L"OEM";
                r.value = key;
                records.push_back(r);
            }
        } catch (const std::exception&) {
        }
    }
    if (sources.licenses) {
        try {
            add(software_license_keys());
        } catch (const std::exception&) {
        }
    }
    if (sources.credentials) {
        try {
            add(credential_manager_entries());
        } catch (const std::exception&) {
        }
    }
    if (sources.browsers) {
        try {
            add(browser_logins());
        } catch (const std::exception&) {
        }
    }
    return records;
}

}  // namespace dd
