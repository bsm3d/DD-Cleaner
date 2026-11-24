// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the secrets code: DPAPI and AES-GCM, Wi-Fi profiles, license keys, Credential Manager and Chromium password reads.

#include <cstdio>
#include <filesystem>

#include <windows.h>

#include <sqlite3.h>

#include <ddcore/secrets.hpp>

using namespace dd;

static int failures = 0, checks = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        ++checks;                                                                  \
        if (!(cond)) {                                                             \
            ++failures;                                                            \
            std::fprintf(stderr, "FAILED %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

namespace {

std::string from_hex(const std::string& hex) {
    std::string out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back((char)std::stoi(hex.substr(i, 2), nullptr, 16));
    return out;
}
std::string to_hex(const std::string& raw) {
    char two[3];
    std::string out;
    for (unsigned char c : raw) {
        snprintf(two, sizeof(two), "%02x", c);
        out += two;
    }
    return out;
}

std::wstring work(const wchar_t* name) {
    std::wstring dir = join(exe_dir(), std::wstring(name) + L"_" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::remove_all(dir);
    make_dirs(dir);
    return dir;
}

std::string base64_encode(const std::string& in) {
    static const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < in.size(); i += 3) {
        unsigned v = (unsigned char)in[i] << 16;
        if (i + 1 < in.size()) v |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < in.size()) v |= (unsigned char)in[i + 2];
        out.push_back(a[(v >> 18) & 63]);
        out.push_back(a[(v >> 12) & 63]);
        out.push_back(i + 1 < in.size() ? a[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < in.size() ? a[v & 63] : '=');
    }
    return out;
}

void test_crypto() {
    // NIST GCM test case 14: 256-bit zero key, zero nonce, 16 zero bytes
    std::string key(32, '\0'), nonce(12, '\0'), plain(16, '\0');
    auto enc = aes_gcm_encrypt(key, nonce, plain);
    CHECK(to_hex(enc.first) == "cea7403d4d606b6e074ec5d3baf39d18" && to_hex(enc.second) == "d0d1c8a799996bf0265b98b5d48ab919");
    CHECK(aes_gcm_decrypt(key, nonce, enc.first, enc.second) == plain);
    // with associated data and a real message
    std::string k2 = from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    std::string n2 = from_hex("cafebabefacedbaddecaf888");
    auto e2 = aes_gcm_encrypt(k2, n2, "hello, passwords", "header");
    CHECK(aes_gcm_decrypt(k2, n2, e2.first, e2.second, "header") == "hello, passwords");
    bool threw = false;
    try {
        aes_gcm_decrypt(k2, n2, e2.first, e2.second, "other header");
    } catch (const CryptoError&) {
        threw = true;
    }
    CHECK(threw);
    std::string bad_tag = e2.second;
    bad_tag[0] ^= 1;
    threw = false;
    try {
        aes_gcm_decrypt(k2, n2, e2.first, bad_tag, "header");
    } catch (const CryptoError& e) {
        threw = std::string(e.what()).find("authentication failed") != std::string::npos;
    }
    CHECK(threw);
    auto empty = aes_gcm_encrypt(k2, n2, "");
    CHECK(empty.first.empty() && aes_gcm_decrypt(k2, n2, "", empty.second).empty());
    threw = false;
    try {
        aes_gcm_encrypt("short key", n2, "x");
    } catch (const CryptoError&) {
        threw = true;
    }
    CHECK(threw);

    std::string wrapped = dpapi_protect("secret key bytes");
    CHECK(wrapped != "secret key bytes" && dpapi_unprotect(wrapped) == "secret key bytes");
    std::string with_entropy = dpapi_protect("x", "salt");
    CHECK(dpapi_unprotect(with_entropy, "salt") == "x");
    threw = false;
    try {
        dpapi_unprotect(with_entropy, "wrong");
    } catch (const CryptoError&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        dpapi_unprotect("not a dpapi blob");
    } catch (const CryptoError&) {
        threw = true;
    }
    CHECK(threw);

    bool ok = false;
    CHECK(base64_decode("aGVsbG8=", &ok) == "hello" && ok);
    CHECK(base64_decode("aGVsbG8", &ok) == "hello" && !ok);   // padding missing
    CHECK(base64_decode("aGVs\nbG8=", &ok) == "hello" && ok);
    CHECK(base64_decode("", &ok).empty() && ok);
}

void test_wifi_xml() {
    std::wstring xml =
        L"<?xml version=\"1.0\"?><WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>Home Net</name>"
        L"<SSIDConfig><SSID><name>HomeSSID</name></SSID></SSIDConfig><MSM><security><authEncryption><authentication>WPA2PSK</authentication>"
        L"<encryption>AES</encryption></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected>"
        L"<keyMaterial>correct horse</keyMaterial></sharedKey></security></MSM></WLANProfile>";
    WifiProfile p = parse_profile_xml(xml);
    CHECK(p.name == L"Home Net" && p.authentication == L"WPA2PSK" && p.encryption == L"AES" && p.password == L"correct horse" && p.readable);
    std::wstring prot = xml;
    prot.replace(prot.find(L"<protected>false"), 16, L"<protected>true");
    WifiProfile q = parse_profile_xml(prot);
    CHECK(!q.readable && q.password.empty());   // not elevated: Windows hides the key
    WifiProfile open = parse_profile_xml(L"<WLANProfile xmlns=\"x\"><SSIDConfig><SSID><name>Cafe</name></SSID></SSIDConfig></WLANProfile>");
    CHECK(open.name == L"Cafe" && open.password.empty() && open.readable);   // no sharedKey: an open network
    bool threw = false;
    try {
        parse_profile_xml(L"<!DOCTYPE x [<!ENTITY a \"b\">]><WLANProfile/>");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        parse_profile_xml(L"<WLANProfile><name>x</WLANProfile>");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

void test_firmware_key() {
    auto answer = [](const wchar_t* text) { return [text](const std::wstring&) { return Json::string(text); }; };
    CHECK(windows_firmware_key(answer(L"ABCDE-12345-FGHIJ-67890-KLMNO")) == L"ABCDE-12345-FGHIJ-67890-KLMNO");
    CHECK(windows_firmware_key(answer(L"  ABCDE-12345-FGHIJ-67890-KLMNO\n")) == L"ABCDE-12345-FGHIJ-67890-KLMNO");
    CHECK(windows_firmware_key(answer(L"")).empty());
    CHECK(windows_firmware_key(answer(L"abcde-12345-fghij-67890-klmno")).empty());   // lower case is not a key
    CHECK(windows_firmware_key(answer(L"ABCDE-12345")).empty());
    CHECK(windows_firmware_key([](const std::wstring&) { return Json(); }).empty());
}

void test_licenses() {
    std::map<std::wstring, std::pair<std::vector<std::pair<std::wstring, std::wstring>>, std::vector<std::wstring>>> tree;
    tree[L"SOFTWARE\\Microsoft\\Office"] = {{}, {L"16.0"}};
    tree[L"SOFTWARE\\Microsoft\\Office\\16.0"] = {{{L"ProductID", L"12345-67890-ABCDE"}, {L"Name", L"Word"}, {L"SerialNumber", L"two words here"}}, {L"Registration"}};
    tree[L"SOFTWARE\\Microsoft\\Office\\16.0\\Registration"] = {{{L"DigitalProductID", L"XXXXX-XXXXX"}, {L"PIDKEY", L" ABCDEFGHIJ "}}, {}};
    tree[L"SOFTWARE\\WOW6432Node\\Microsoft\\Office"] = {{{L"ProductID", L"12345-67890-ABCDE"}}, {}};   // same key under another label
    tree[L"SOFTWARE\\Adobe"] = {{{L"serial", L"1234-5678-9012"}, {L"regkey", L"x"}}, {}};            // "x" is too short to be a key
    RegistryWalker walker;
    walker.open = [&](const std::wstring& path, std::vector<std::pair<std::wstring, std::wstring>>& values, std::vector<std::wstring>& subs) {
        auto it = tree.find(path);
        if (it == tree.end()) return false;
        values = it->second.first;
        subs = it->second.second;
        return true;
    };
    auto found = software_license_keys(&walker);
    CHECK(found.size() == 4);
    bool office = false, adobe = false, trimmed = false, wow = false;
    for (const auto& r : found) {
        if (r.name == L"Office" && r.value == L"12345-67890-ABCDE" && r.info == L"16.0") office = true;
        if (r.name == L"Adobe" && r.value == L"1234-5678-9012" && r.info == L"Adobe") adobe = true;
        if (r.value == L"ABCDEFGHIJ" && r.info == L"Registration") trimmed = true;
        if (r.name == L"Office (32-bit)") wow = true;
    }
    CHECK(office && adobe && trimmed && wow);

    // a very deep tree stops at the depth limit
    RegistryWalker deep;
    int opened = 0;
    deep.open = [&](const std::wstring&, std::vector<std::pair<std::wstring, std::wstring>>& values, std::vector<std::wstring>& subs) {
        ++opened;
        values.clear();
        subs = {L"d"};
        return true;
    };
    software_license_keys(&deep);
    CHECK(opened == 7 * 7);   // 7 roots, each opened down to depth 6
}

void test_credentials() {
    auto utf16 = [](const std::wstring& s) { return std::string(reinterpret_cast<const char*>(s.data()), s.size() * 2); };
    DecodedBlob d = decode_credential_blob(utf16(L"pässw0rd!"), 1);
    CHECK(d.readable && d.secret == L"pässw0rd!");
    d = decode_credential_blob(utf16(std::wstring(L"abc") + L'\0' + L'\0'), 1);
    CHECK(d.secret == L"abc");   // trailing NULs removed
    d = decode_credential_blob("plain utf-8 \xc3\xa9", 1);
    CHECK(d.readable && d.secret == L"plain utf-8 é");
    d = decode_credential_blob(std::string("\x01\x02\xff\xfe\x00\x80", 6), 1);
    CHECK(!d.readable && d.secret.empty() && d.note == L"binary secret");
    d = decode_credential_blob("", 1);
    CHECK(d.readable && d.note == L"(no secret stored)");
    d = decode_credential_blob(utf16(L"secret"), 2);
    CHECK(!d.readable && d.secret.empty());   // a domain password is never shown
    d = decode_credential_blob(std::string("ab\0cd", 5), 1);
    CHECK(!d.readable);   // an embedded NUL is not text

    auto records = credential_manager_entries([&] {
        std::vector<StoredCredential> v;
        v.push_back({L"git:https://github.com", L"me", 1, utf16(L"token123")});
        v.push_back({L"TERMSRV/host", L"admin", 2, utf16(L"x")});
        return v;
    });
    CHECK(records.size() == 2 && records[0].kind == L"Windows credential" && records[0].value == L"token123" && records[0].info == L"me");
    CHECK(!records[1].readable && records[1].value.empty());
}

void make_login_db(const std::wstring& path, const std::vector<std::tuple<std::string, std::string, std::string>>& rows) {
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(utf8(path).c_str(), &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)", nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& [url, user, blob] : rows) {
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(db, "INSERT INTO logins VALUES (?, ?, ?)", -1, &st, nullptr);
        sqlite3_bind_text(st, 1, url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, user.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, blob.data(), (int)blob.size(), SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
}

std::string v10(const std::string& key, const std::string& password) {
    std::string nonce = "123456789012";
    auto e = aes_gcm_encrypt(key, nonce, password);
    return "v10" + nonce + e.first + e.second;
}

void test_chromium() {
    std::wstring home = work(L"secrets_home");
    SetEnvironmentVariableW(L"DDCLEANER_HOME", home.c_str());
    std::wstring base = work(L"secrets_local");
    std::wstring chrome = join(base, L"Google\\Chrome\\User Data");
    make_dirs(join(chrome, L"Default"));
    make_dirs(join(chrome, L"Profile 1"));
    make_dirs(join(chrome, L"Crashpad"));   // no Login Data: not a profile
    std::string master(32, 'K');
    std::string wrapped = dpapi_protect(master);
    CHECK(write_file(join(chrome, L"Local State"), "{\"os_crypt\":{\"encrypted_key\":\"" + base64_encode("DPAPI" + wrapped) + "\"}}"));
    std::string old_style = dpapi_protect("old password");   // entries from before AES: a DPAPI blob
    make_login_db(join(chrome, L"Default\\Login Data"),
                  {{"https://example.com/login", "alice", v10(master, "s3cret!")},
                   {"https://shop.example.org:8443/a?b=c", "", old_style},
                   {"https://v20.example.net/", "carol", "v20" + std::string(40, 'x')},
                   {"https://broken.example.net/", "dave", "v10" + std::string(12, 'n') + std::string(20, 'z') + std::string(16, 't')},
                   {"https://empty.example.net/", "", ""},   // nothing at all: skipped
                   {"android://hash@com.app/", "erin", v10(master, "from phone")}});
    make_login_db(join(chrome, L"Profile 1\\Login Data"), {{"https://work.example.com", "frank", v10(master, "work pw")}});
    CHECK(chromium_master_key(chrome) == master);

    auto dirs = chromium_user_data_dirs(base);
    CHECK(dirs.size() == 1 && dirs[0].first == L"Chrome" && dirs[0].second == chrome);
    CHECK(chromium_user_data_dirs(join(base, L"nowhere")).empty());

    auto records = chromium_logins(L"Chrome", chrome);
    CHECK(records.size() == 6);
    auto find = [&](const std::wstring& name) -> const SecretRecord* {
        for (const auto& r : records) {
            if (r.name == name) return &r;
        }
        return nullptr;
    };
    const SecretRecord* a = find(L"example.com");
    CHECK(a && a->kind == L"Chrome" && a->info == L"alice" && a->value == L"s3cret!" && a->readable);
    const SecretRecord* b = find(L"shop.example.org:8443");
    CHECK(b && b->value == L"old password" && b->info.empty());
    const SecretRecord* c = find(L"v20.example.net");
    CHECK(c && !c->readable && c->value.empty() && c->note.find(L"app-bound") != std::wstring::npos);
    const SecretRecord* d = find(L"broken.example.net");
    CHECK(d && !d->readable && d->note == L"could not decrypt");
    const SecretRecord* e = find(L"hash@com.app");
    CHECK(e && e->value == L"from phone");   // the network location, as urlsplit gives it
    const SecretRecord* f = find(L"work.example.com");
    CHECK(f && f->info == L"frank  (Profile 1)" && f->value == L"work pw");
    CHECK(!find(L"empty.example.net"));

    // the temporary copies are gone
    std::vector<Entry> left;
    list_dir(join(home, L"tmp"), left);
    CHECK(left.empty());

    // a wrong master key makes each value unreadable, not the whole page
    std::wstring other = join(base, L"Microsoft\\Edge\\User Data");
    make_dirs(join(other, L"Default"));
    CHECK(write_file(join(other, L"Local State"), "{\"os_crypt\":{\"encrypted_key\":\"" + base64_encode("DPAPI" + dpapi_protect(std::string(32, 'Z'))) + "\"}}"));
    make_login_db(join(other, L"Default\\Login Data"), {{"https://example.com", "alice", v10(master, "s3cret!")}});
    auto wrong = chromium_logins(L"Edge", other);
    CHECK(wrong.size() == 1 && !wrong[0].readable && wrong[0].note == L"could not decrypt");

    // no usable Local State: one record says so
    std::wstring broken = join(base, L"Vivaldi\\User Data");
    make_dirs(broken);
    auto none = chromium_logins(L"Vivaldi", broken);
    CHECK(none.size() == 1 && !none[0].readable && none[0].note == L"encryption key not readable" && none[0].name == L"(all profiles)");
    CHECK(write_file(join(broken, L"Local State"), "{\"os_crypt\":{\"encrypted_key\":\"" + base64_encode("v10xxxx") + "\"}}"));
    bool threw = false;
    try {
        chromium_master_key(broken);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        decrypt_chromium_value("v20abc", master);
    } catch (const AppBoundValue&) {
        threw = true;
    }
    CHECK(threw);
    // the DPAPI step can be replaced (tests, other users)
    CHECK(decrypt_chromium_value("raw", master, [](const std::string& s) { return s + "!"; }) == L"raw!");

    // a database that is not SQLite is skipped
    make_dirs(join(chrome, L"Profile 2"));
    CHECK(write_file(join(chrome, L"Profile 2\\Login Data"), "this is not a database"));
    CHECK(chromium_logins(L"Chrome", chrome).size() == 6);

    std::filesystem::remove_all(base);
    std::filesystem::remove_all(home);
}

void test_firefox() {
    std::wstring base = work(L"secrets_ff");
    std::wstring profiles = join(base, L"Mozilla\\Firefox\\Profiles");
    make_dirs(join(profiles, L"abc.default"));
    make_dirs(join(profiles, L"zzz.old"));
    make_dirs(join(profiles, L"nokey.profile"));
    CHECK(write_file(join(profiles, L"abc.default\\logins.json"), "{}") && write_file(join(profiles, L"abc.default\\key4.db"), "x"));
    CHECK(write_file(join(profiles, L"zzz.old\\logins.json"), "{}") && write_file(join(profiles, L"zzz.old\\key4.db"), "x"));
    CHECK(write_file(join(profiles, L"nokey.profile\\logins.json"), "{}"));   // no key database: cannot hold readable logins
    auto found = firefox_profiles(base);
    CHECK(found.size() == 2 && base_name(found[0]) == L"abc.default" && base_name(found[1]) == L"zzz.old");
    CHECK(firefox_profiles(join(base, L"missing")).empty());

    auto logins = parse_firefox_logins(L"{\"logins\":[{\"hostname\":\"https://a.example\",\"encryptedUsername\":\"AAA\",\"encryptedPassword\":\"BBB\"},"
                                       L"\"junk\",{\"hostname\":\"https://b.example\"}]}");
    CHECK(logins.size() == 2 && logins[0].hostname == L"https://a.example" && logins[0].encrypted_password == L"BBB" && logins[1].encrypted_user.empty());
    CHECK(parse_firefox_logins(L"{}").empty());
    bool threw = false;
    try {
        parse_firefox_logins(L"{ nope");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    std::filesystem::remove_all(base);
}

void test_collect_nothing() {
    SecretSources none;
    none.wifi = none.windows_key = none.licenses = none.credentials = none.browsers = false;
    CHECK(collect_secrets(none).empty());
}

}  // namespace

int run_secrets_tests() {
    int start_checks = checks, start_failures = failures;
    test_crypto();
    test_wifi_xml();
    test_firmware_key();
    test_licenses();
    test_credentials();
    test_chromium();
    test_firefox();
    test_collect_nothing();
    std::printf("secrets: %d checks, %d failed\n", checks - start_checks, failures - start_failures);
    return failures;
}
