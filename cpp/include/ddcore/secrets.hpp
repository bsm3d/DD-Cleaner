// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the reading of the user's own saved secrets (Wi-Fi keys, Credential Manager, browser passwords) for on-screen display.

// The user's own secrets (Wi-Fi keys, firmware key, licence keys, Credential Manager, browser passwords), returned only to be shown on screen.
// Nothing is written to disk except a short-lived copy of a browser database, deleted at once. Logs hold counts only.
#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>

namespace dd {

// region Windows cryptography (DPAPI and AES-256-GCM through CNG)
struct CryptoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string dpapi_unprotect(const std::string& data, const std::string& entropy = "");   // throws CryptoError
std::string dpapi_protect(const std::string& data, const std::string& entropy = "");     // here so round trips can be tested
// 256-bit key. Throws CryptoError (also when the tag does not match).
std::string aes_gcm_decrypt(const std::string& key, const std::string& nonce, const std::string& ciphertext, const std::string& tag, const std::string& aad = "");
std::pair<std::string, std::string> aes_gcm_encrypt(const std::string& key, const std::string& nonce, const std::string& plaintext, const std::string& aad = "");
std::string base64_decode(const std::string& text, bool* ok = nullptr);
// endregion

struct SecretRecord {
    std::wstring kind;    // Wi-Fi | Windows key | License | Windows credential | Chrome | Edge | Brave | Vivaldi | Firefox
    std::wstring name;    // SSID, software, credential target, site
    std::wstring info;    // security, product, user name
    std::wstring value;   // the secret ("" when there is none or it cannot be read)
    bool readable = true; // false: it exists but Windows or the browser would not give it
    std::wstring note;    // why the value is empty
};

// region Wi-Fi
struct WifiProfile {
    std::wstring name, authentication, encryption;
    std::wstring password;   // "" = open network, enterprise login, or not readable
    bool readable = true;
};
// One WLAN profile XML. DTDs are refused. Throws std::runtime_error.
WifiProfile parse_profile_xml(const std::wstring& xml);
std::vector<WifiProfile> wifi_profiles();   // needs administrator rights for the passwords; empty without a Wi-Fi adapter
// endregion

// The Windows key written in the firmware (OEM PCs), or "". `run` returns the parsed JSON of a PowerShell script.
std::wstring windows_firmware_key(const std::function<Json(const std::wstring&)>& run = nullptr);

// region Software license keys
struct RegistryWalker {   // what the license search needs from the registry
    // string values (name, text) and subkey names of HKLM\path; false when the key cannot be opened
    std::function<bool(const std::wstring& path, std::vector<std::pair<std::wstring, std::wstring>>& values, std::vector<std::wstring>& subkeys)> open;
};
std::vector<SecretRecord> software_license_keys(const RegistryWalker* walker = nullptr);
// endregion

// region Credential Manager
struct StoredCredential {
    std::wstring target, user;
    int type = 0;
    std::string blob;
};
std::vector<StoredCredential> enumerate_credentials();
// (secret, readable, note). Domain passwords are never returned in clear.
struct DecodedBlob {
    std::wstring secret, note;
    bool readable = true;
};
DecodedBlob decode_credential_blob(const std::string& blob, int type);
std::vector<SecretRecord> credential_manager_entries(const std::function<std::vector<StoredCredential>()>& enumerate = nullptr);
// endregion

// region Browsers
struct AppBoundValue : std::runtime_error {   // Chrome 127+ "v20" values: not decryptable here
    AppBoundValue() : std::runtime_error("app-bound encryption (Chrome 127+)") {}
};
using Unprotect = std::function<std::string(const std::string&)>;

std::vector<std::pair<std::wstring, std::wstring>> chromium_user_data_dirs(const std::wstring& base = L"");   // (browser, folder)
std::string chromium_master_key(const std::wstring& user_data_dir, const Unprotect& unprotect = nullptr);       // throws
std::wstring decrypt_chromium_value(const std::string& blob, const std::string& key, const Unprotect& unprotect = nullptr);
std::vector<SecretRecord> chromium_logins(const std::wstring& name, const std::wstring& user_data_dir, const Unprotect& unprotect = nullptr);

struct FirefoxLogin {
    std::wstring hostname, encrypted_user, encrypted_password;
};
std::vector<std::wstring> firefox_profiles(const std::wstring& base = L"");
std::vector<FirefoxLogin> parse_firefox_logins(const std::wstring& json_text);   // throws std::runtime_error
std::vector<SecretRecord> firefox_logins();
std::vector<SecretRecord> browser_logins();
// endregion

struct SecretSources {
    bool wifi = true, windows_key = true, licenses = true, credentials = true, browsers = true;
};
// One source failing never hides the others.
std::vector<SecretRecord> collect_secrets(const SecretSources& sources = {});

}  // namespace dd
