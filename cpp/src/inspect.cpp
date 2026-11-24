// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements file classification from magic bytes, the embedded signer lookup and the check of folder write rights.

#include <ddcore/inspect.hpp>

#include <algorithm>
#include <cmath>
#include <cstring>

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wincrypt.h>

#include <ddcore/common.hpp>

namespace dd {

// region Real type and entropy

namespace {

struct Magic {
    const char* bytes;
    std::size_t length;
    const wchar_t* label;
    const wchar_t* kind;
};

#define M(text, label, kind) {text, sizeof(text) - 1, label, kind}
const Magic SIGNATURES[] = {
    M("\x4c\x00\x00\x00\x01\x14\x02\x00", L"Windows shortcut (LNK)", L"shortcut"),
    M("MZ", L"Windows executable (PE)", L"executable"),
    M("\x7f" "ELF", L"ELF executable", L"executable"),
    M("#!", L"script (shebang)", L"script"),
    M("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", L"OLE2 (legacy Office or MSI)", L"document"),
    M("PK\x03\x04", L"ZIP / Office (OOXML) / JAR", L"archive"),
    M("Rar!", L"RAR archive", L"archive"),
    M("7z\xbc\xaf\x27\x1c", L"7-Zip archive", L"archive"),
    M("\x1f\x8b", L"gzip archive", L"archive"),
    M("%PDF", L"PDF document", L"document"),
    M("\x89PNG\r\n\x1a\n", L"PNG image", L"image"),
    M("\xff\xd8\xff", L"JPEG image", L"image"),
    M("GIF8", L"GIF image", L"image"),
    M("BM", L"BMP image", L"image"),
    M("\x00\x00\x01\x00", L"icon (ICO)", L"image"),
    M("II*\x00", L"TIFF image", L"image"),
    M("MM\x00*", L"TIFF image", L"image"),
    M("OggS", L"Ogg media", L"media"),
    M("RIFF", L"RIFF media (WAV / AVI)", L"media"),
    M("\x1a" "E\xdf\xa3", L"Matroska / WebM media", L"media"),
    M("ID3", L"MP3 audio", L"media"),
    M("fLaC", L"FLAC audio", L"media"),
};
#undef M

const std::map<std::wstring, std::wstring>& ext_kind() {
    static const std::map<std::wstring, std::wstring> m = {
        {L"exe", L"executable"}, {L"dll", L"executable"}, {L"sys", L"executable"}, {L"scr", L"executable"},
        {L"com", L"executable"}, {L"ocx", L"executable"}, {L"cpl", L"executable"}, {L"drv", L"executable"},
        {L"efi", L"executable"}, {L"mui", L"executable"}, {L"lnk", L"shortcut"}, {L"zip", L"archive"},
        {L"jar", L"archive"}, {L"apk", L"archive"}, {L"rar", L"archive"}, {L"7z", L"archive"}, {L"gz", L"archive"},
        {L"tgz", L"archive"}, {L"docx", L"archive"}, {L"xlsx", L"archive"}, {L"pptx", L"archive"},
        {L"doc", L"document"}, {L"xls", L"document"}, {L"ppt", L"document"}, {L"msi", L"document"},
        {L"pdf", L"document"}, {L"png", L"image"}, {L"jpg", L"image"}, {L"jpeg", L"image"}, {L"gif", L"image"},
        {L"bmp", L"image"}, {L"ico", L"image"}, {L"tif", L"image"}, {L"tiff", L"image"}, {L"webp", L"image"},
        {L"wav", L"media"}, {L"avi", L"media"}, {L"mp3", L"media"}, {L"mp4", L"media"}, {L"mkv", L"media"},
        {L"webm", L"media"}, {L"flac", L"media"}, {L"ogg", L"media"}};
    return m;
}

bool is_executable_kind(const std::wstring& k) { return k == L"executable" || k == L"script" || k == L"shortcut"; }

}  // namespace

void classify(const std::string& data, std::wstring& label, std::wstring& kind) {
    for (const Magic& m : SIGNATURES) {
        if (data.size() >= m.length && !memcmp(data.data(), m.bytes, m.length)) {
            label = m.label;
            kind = m.kind;
            return;
        }
    }
    std::size_t n = std::min<std::size_t>(data.size(), 1024), printable = 0;
    for (std::size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) ++printable;
    }
    if (n && printable >= n * 0.9) {
        label = kind = L"text";
    } else {
        label = L"Unknown binary";
        kind = L"data";
    }
}

double shannon_entropy(const std::string& data) {
    if (data.empty()) return 0;
    std::uint64_t counts[256] = {0};
    for (unsigned char c : data) ++counts[c];
    double e = 0, total = (double)data.size();
    for (auto c : counts) {
        if (!c) continue;
        double p = c / total;
        e -= p * std::log2(p);
    }
    return std::round(e * 1000) / 1000;
}

FileInspection inspect(const std::wstring& path, std::size_t sample_size) {
    FileInspection r;
    r.path = path;
    std::wstring ext = extension(path);
    r.declared_ext = ext.empty() ? L"" : ext.substr(1);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        r.error = L"cannot open the file";
        return r;
    }
    std::string head(sample_size, '\0');
    DWORD got = 0;
    ReadFile(h, head.data(), (DWORD)sample_size, &got, nullptr);
    CloseHandle(h);
    head.resize(got);
    if (head.empty()) {
        r.error = L"empty file";
        return r;
    }
    classify(head, r.true_type, r.kind);
    r.entropy = shannon_entropy(head);
    r.packed = r.kind == L"executable" && r.entropy >= PACKED_ENTROPY;
    if (!r.declared_ext.empty() && r.kind != L"data" && r.kind != L"text") {
        auto it = ext_kind().find(r.declared_ext);
        if (it == ext_kind().end()) {
            if (is_executable_kind(r.kind)) {
                r.mismatch = r.true_type + L" with an unexpected ." + r.declared_ext + L" name";
                r.dangerous = true;
            }
        } else if (it->second != r.kind) {
            r.dangerous = is_executable_kind(r.kind) && !is_executable_kind(it->second);
            r.mismatch = L"Content is " + r.true_type + L", not a ." + r.declared_ext + L" file";
        }
    }
    return r;
}

// endregion

// region Signature, version, hash

std::wstring sha256_bytes(const std::string& bytes) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::wstring out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(hash, (PUCHAR)bytes.data(), (ULONG)bytes.size(), 0);
            UCHAR digest[32];
            if (BCryptFinishHash(hash, digest, 32, 0) == 0) {
                wchar_t hex[3];
                for (UCHAR b : digest) {
                    swprintf(hex, 3, L"%02X", b);
                    out += hex;
                }
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return out;
}

std::wstring sha256_file(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::wstring out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        std::vector<char> buf(1 << 20);
        bool ok = true;
        for (;;) {
            DWORD got = 0;
            if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr)) {
                ok = false;
                break;
            }
            if (!got) break;
            BCryptHashData(hash, (PUCHAR)buf.data(), got, 0);
        }
        UCHAR digest[32];
        if (ok && BCryptFinishHash(hash, digest, 32, 0) == 0) {
            wchar_t hex[3];
            for (UCHAR b : digest) {
                swprintf(hex, 3, L"%02X", b);
                out += hex;
            }
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    return out;
}

static std::wstring embedded_signer(const std::wstring& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    DWORD encoding = 0, content = 0, format = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format, &store, &msg, nullptr))
        return L"";
    std::wstring name;
    DWORD size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &size) && size) {
        std::vector<BYTE> buf(size);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(), &size)) {
            auto* info = reinterpret_cast<CERT_INFO*>(buf.data());
            PCCERT_CONTEXT cert = CertFindCertificateInStore(store, encoding, 0, CERT_FIND_SUBJECT_CERT, info, nullptr);
            if (cert) {
                wchar_t text[512];
                DWORD n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_COMMON_NAME), text, 512);
                if (n > 1) name = text;
                else if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, text, 512) > 1) name = text;
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (store) CertCloseStore(store, 0);
    if (msg) CryptMsgClose(msg);
    return name;
}

PEInfo inspect_pe(const std::wstring& path) {
    PEInfo info;
    info.path = path;
    if (!is_file(path)) {
        info.error = L"file not found";
        return info;
    }
    info.signer = embedded_signer(path);

    DWORD handle = 0, size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!size) return info;
    std::vector<BYTE> block(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, block.data())) return info;
    void* ptr = nullptr;
    UINT length = 0;
    if (VerQueryValueW(block.data(), L"\\", &ptr, &length) && length >= sizeof(VS_FIXEDFILEINFO)) {
        auto* fixed = static_cast<VS_FIXEDFILEINFO*>(ptr);
        wchar_t v[48];
        swprintf(v, 48, L"%u.%u.%u.%u", (unsigned)(fixed->dwFileVersionMS >> 16), (unsigned)(fixed->dwFileVersionMS & 0xFFFF),
                 (unsigned)(fixed->dwFileVersionLS >> 16), (unsigned)(fixed->dwFileVersionLS & 0xFFFF));
        info.file_version = v;
    }
    std::vector<std::pair<WORD, WORD>> translations;
    if (VerQueryValueW(block.data(), L"\\VarFileInfo\\Translation", &ptr, &length)) {
        auto* t = static_cast<WORD*>(ptr);
        for (UINT i = 0; i + 1 < length / 2; i += 2) translations.emplace_back(t[i], t[i + 1]);
    }
    translations.insert(translations.end(), {{0x0409, 0x04B0}, {0x0409, 0x04E4}, {0x0000, 0x04B0}});
    for (const wchar_t* name : {L"OriginalFilename", L"InternalName", L"ProductName", L"FileDescription"}) {
        for (auto [lang, cp] : translations) {
            wchar_t key[128];
            swprintf(key, 128, L"\\StringFileInfo\\%04x%04x\\%ls", lang, cp, name);
            if (VerQueryValueW(block.data(), key, &ptr, &length) && length) {
                std::wstring value = trim(std::wstring(static_cast<wchar_t*>(ptr)));
                if (!value.empty()) {
                    info.strings[name] = value;
                    break;
                }
            }
        }
    }
    return info;
}

// endregion

// region Folder security

namespace {

const DWORD WRITE_RIGHTS = 0x2 | 0x4 | 0x40 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
// FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE

std::wstring sid_string(PSID sid) {
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return L"";
    std::wstring out = text;
    LocalFree(text);
    return out;
}

}  // namespace

std::wstring current_user_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"";
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buf(size);
    std::wstring out;
    if (size && GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        out = sid_string(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid);
    }
    CloseHandle(token);
    return out;
}

std::vector<std::wstring> unprivileged_writers(const std::wstring& path, bool* ok) {
    std::map<std::wstring, std::wstring> risky = {{L"S-1-1-0", L"Everyone"},
                                                  {L"S-1-5-11", L"Authenticated Users"},
                                                  {L"S-1-5-32-545", L"Users"},
                                                  {L"S-1-5-4", L"Interactive users"},
                                                  {L"S-1-5-32-546", L"Guests"}};
    std::wstring user = current_user_sid();
    if (!user.empty()) risky[user] = L"your account (also when not elevated)";
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD err = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                      &owner, nullptr, &dacl, nullptr, &sd);
    if (ok) *ok = err == 0;
    std::vector<std::wstring> writers;
    if (err != 0) return writers;
    std::wstring owner_sid = sid_string(owner);
    if (risky.count(owner_sid)) writers.push_back(risky[owner_sid] + L" (owner: can change the permissions)");
    if (!dacl) {
        LocalFree(sd);
        return {L"Everyone (the folder has no access control list)"};
    }
    ACL_SIZE_INFORMATION info{};
    GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation);
    for (DWORD i = 0; i < info.AceCount; ++i) {
        void* ace_ptr = nullptr;
        if (!GetAce(dacl, i, &ace_ptr)) continue;
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(ace_ptr);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || (ace->Header.AceFlags & INHERIT_ONLY_ACE)) continue;
        if (!(ace->Mask & WRITE_RIGHTS)) continue;
        std::wstring sid = sid_string(reinterpret_cast<PSID>(&ace->SidStart));
        auto it = risky.find(sid);
        if (it == risky.end()) continue;
        if (std::find(writers.begin(), writers.end(), it->second) == writers.end()) writers.push_back(it->second);
    }
    LocalFree(sd);
    return writers;
}

std::vector<std::wstring> folder_risk(const std::wstring& folder) {
    bool ok = true;
    auto writers = unprivileged_writers(folder, &ok);
    if (!ok) return {L"Permissions of " + folder + L" could not be checked."};
    if (writers.empty()) return {};
    std::wstring joined;
    for (std::size_t i = 0; i < writers.size(); ++i) joined += (i ? L", " : L"") + writers[i];
    return {folder + L" can be modified without administrator rights by: " + joined + L"."};
}

// endregion

}  // namespace dd
