// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests zip and XML parsing, URL helpers, versions, HTTP and the driver blocklist policy.

#include <cstdint>
#include <cstdio>
#include <stdexcept>

#include <windows.h>

#include <ddcore/blocklist.hpp>
#include <ddcore/net.hpp>
#include <ddcore/pe.hpp>

#include "zip_blob.inc"

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

static void test_zip_and_xml() {
    std::string zip(reinterpret_cast<const char*>(ZIP_BLOB), ZIP_BLOB_SIZE), out;
    std::wstring error;
    CHECK(zip_extract(zip, "DriverPolicy_Enforced.xml", out, error));   // a deflated member in a sub folder (backslash path)
    CHECK(out.size() == ZIP_MEMBER_SIZE && out.find("<VersionEx>10.0.1.0</VersionEx>") != std::string::npos);
    CHECK(zip_extract(zip, "stored.txt", out, error) && out == "plain stored bytes");
    CHECK(!zip_extract(zip, "missing.xml", out, error) && error.find(L"not found") != std::wstring::npos);
    CHECK(!zip_extract(zip, "DriverPolicy_Enforced.xml", out, error, 100));      // larger than the limit
    CHECK(!zip_extract("not a zip at all, just text of some length", "x", out, error));
    std::string damaged = zip;
    damaged[60] ^= 0x55;   // inside the deflated data
    bool survived = zip_extract(damaged, "DriverPolicy_Enforced.xml", out, error) ? out.size() == ZIP_MEMBER_SIZE : true;
    CHECK(survived);   // a damaged archive never crashes; it either fails or (rarely) yields the right size

    XmlNode root = parse_xml("\xEF\xBB\xBF<?xml version=\"1.0\"?><!DOCTYPE x><!-- c --><a:Root xmlns:a=\"u\" id=\"1\"><Item k='v &amp; w'>text &lt;1&gt;</Item><Item/><![CDATA[raw <b>]]></a:Root>");
    CHECK(root.name == L"Root" && root.attr(L"id") == L"1" && root.children.size() == 2);
    CHECK(root.children[0].attr(L"k") == L"v & w" && root.children[0].text == L"text <1>");
    CHECK(root.text == L"raw <b>");
    CHECK(root.all(L"Item").size() == 2 && root.child(L"Nope") == nullptr);
    bool threw = false;
    try {
        parse_xml("<a><b></a>");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        parse_xml("not xml");
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
    const wchar_t utf16[] = L"\ufeff<r v=\"\u00e9\"/>";
    XmlNode wide_root = parse_xml(std::string(reinterpret_cast<const char*>(utf16), sizeof(utf16) - 2));
    CHECK(wide_root.name == L"r" && wide_root.attr(L"v") == L"\u00e9");
}

static void test_url_helpers() {
    CHECK(url_host(L"https://go.Microsoft.com/fwlink/?x=1") == L"go.microsoft.com");
    CHECK(url_host_in(L"https://download.microsoft.com/a", {L"microsoft.com"}));
    CHECK(url_host_in(L"https://microsoft.com/", {L"microsoft.com"}));
    CHECK(!url_host_in(L"https://evilmicrosoft.com/", {L"microsoft.com"}));
    CHECK(!url_host_in(L"https://microsoft.com.evil.net/", {L"microsoft.com"}));
    CHECK(!url_host_in(L"http://microsoft.com/", {L"microsoft.com"}));
    CHECK(url_encode(L"a b/c?\u00e9") == L"a%20b%2Fc%3F%C3%A9");
    HttpResponse refused = http_get(L"http://example.com/");
    CHECK(!refused.ok && refused.error.find(L"https") != std::wstring::npos);   // plain http is never used
}

static void test_versions_and_rules() {
    CHECK((parse_version(L"1.2") == Version4{1, 2, 0, 0}));
    CHECK((parse_version(L"10.0.19041.1") == Version4{10, 0, 19041, 1}));
    CHECK(parse_version(L"x.y").empty() && parse_version(L"").empty());

    PeDetails info;
    info.strings = {{L"OriginalFilename", L"Vuln.SYS"}};
    info.version = {1, 5, 0, 0};
    FileAttribute any{L"OriginalFilename", L"vuln.sys", {}, {}, L"Vuln"};
    CHECK(any.matches(info));
    FileAttribute min_only{L"OriginalFilename", L"vuln.sys", {1, 4, 0, 0}, {}, L""};   // that version AND OLDER
    CHECK(!min_only.matches(info));
    info.version = {1, 3, 0, 0};
    CHECK(min_only.matches(info));
    FileAttribute max_only{L"OriginalFilename", L"vuln.sys", {}, {2, 0, 0, 0}, L""};   // that version and newer
    CHECK(!max_only.matches(info));
    info.version = {2, 1, 0, 0};
    CHECK(max_only.matches(info));
    FileAttribute range{L"OriginalFilename", L"vuln.sys", {1, 0, 0, 0}, {3, 0, 0, 0}, L""};
    CHECK(range.matches(info));
    info.version = {4, 0, 0, 0};
    CHECK(!range.matches(info));
    info.version.clear();
    CHECK(!range.matches(info) && any.matches(info));   // no version resource: a range cannot match
    info.strings.clear();
    CHECK(!any.matches(info));
}

static const char* POLICY_XML = R"J(<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.7.1</VersionEx>
  <FileRules>
    <Deny ID="ID_DENY_A" FriendlyName="Bad hash" Hash="AABBCCDD00112233"/>
    <Deny ID="ID_DENY_B" FriendlyName="Old driver" FileName="Vuln.sys" MaximumFileVersion="1.9.0.0"/>
    <Deny ID="ID_DENY_C" FriendlyName="Not in the kernel scenario" Hash="DEADBEEF"/>
    <FileAttrib ID="ID_FA_1" FriendlyName="Only this product" ProductName="Acme Tool"/>
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_1" Name="Acme signer">
      <CertRoot Type="TBS" Value="0123456789ABCDEF"/>
      <CertPublisher Value="Acme Corp"/>
      <FileAttribRef RuleID="ID_FA_1"/>
    </Signer>
    <Signer ID="ID_SIGNER_2" Name="Allowed signer"><CertRoot Type="TBS" Value="FEDCBA"/></Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SCENARIO_DRIVERS">
      <ProductSigners>
        <FileRulesRef><FileRuleRef RuleID="ID_DENY_A"/><FileRuleRef RuleID="ID_DENY_B"/></FileRulesRef>
        <DeniedSigners><DeniedSigner SignerId="ID_SIGNER_1"/></DeniedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SCENARIO_USER"><ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_DENY_C"/></FileRulesRef></ProductSigners></SigningScenario>
  </SigningScenarios>
</SiPolicy>)J";

static void test_policy() {
    BlocklistPolicy p = parse_policy(POLICY_XML);
    CHECK(p.version == L"10.0.7.1");
    CHECK(p.hashes.size() == 1 && p.hashes.count(L"AABBCCDD00112233") == 1);   // the user-mode rule is ignored
    CHECK(p.file_rules.size() == 1 && p.file_rules[0].value == L"Vuln.sys" && p.file_rules[0].maximum == (Version4{1, 9, 0, 0}));
    CHECK(p.signers.size() == 1 && p.signers[0].name == L"Acme signer" && p.signers[0].publisher == L"Acme Corp");
    CHECK(p.signers[0].file_attributes.size() == 1 && p.signers[0].file_attributes[0].value == L"Acme Tool");
    CHECK(p.rule_count() == 3);

    PeDetails by_hash;
    by_hash.hashes = {{L"sha1", L"00"}, {L"sha256", L"AABBCCDD00112233"}};
    auto reasons = p.match(by_hash);
    CHECK(reasons.size() == 1 && reasons[0] == L"Hash (SHA256): Bad hash");
    PeDetails old_driver;
    old_driver.strings = {{L"OriginalFilename", L"vuln.sys"}};
    old_driver.version = {2, 0, 0, 0};
    CHECK(p.match(old_driver).size() == 1 && p.match(old_driver)[0] == L"File rule: Old driver");
    old_driver.version = {1, 0, 0, 0};
    CHECK(p.match(old_driver).empty());
    CHECK(p.match(PeDetails{}).empty());

    auto bad = [](const char* text) {
        try {
            parse_policy(text);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    CHECK(bad("<nope/>"));
    CHECK(bad("<SiPolicy xmlns=\"urn:schemas-microsoft-com:sipolicy\"><FileRules/></SiPolicy>"));   // no kernel scenario
    CHECK(bad("<SiPolicy><SigningScenarios><SigningScenario Value=\"131\"/></SigningScenarios></SiPolicy>"));   // no rule
    CHECK(bad("<SiPolicy>"));
}

static void test_blocklist_storage() {
    std::wstring folder = temp_dir() + L"\\ddcore_blocklist_" + std::to_wstring(GetCurrentProcessId());
    // a download that ends outside microsoft.com is refused; so is one that is not a zip or not a policy
    auto fetch_from = [&](const std::wstring& final_url, const std::string& body, int status = 200) {
        return [=](const std::wstring&) {
            HttpResponse r;
            r.ok = true;
            r.status = status;
            r.final_url = final_url;
            r.body = body;
            return r;
        };
    };
    std::string zip(reinterpret_cast<const char*>(ZIP_BLOB), ZIP_BLOB_SIZE);
    auto throws = [&](const Fetch& f) {
        try {
            download_blocklist(folder, f);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    CHECK(throws(fetch_from(L"https://evil.example.net/x.zip", zip)));
    CHECK(throws(fetch_from(L"https://download.microsoft.com/x.zip", "garbage")));
    CHECK(throws(fetch_from(L"https://download.microsoft.com/x.zip", zip)));   // a zip whose policy has no rule
    CHECK(throws(fetch_from(L"https://download.microsoft.com/x.zip", zip, 404)));
    CHECK(!is_file(join(folder, POLICY_MEMBER)));   // nothing stored from a refused download

    // a good archive: build one around the test policy with a stored member
    std::string good_zip;
    {
        // minimal zip with one stored member
        std::string name = "DriverPolicy_Enforced.xml", data = POLICY_XML;
        auto le32 = [](std::uint32_t v) { return std::string{(char)v, (char)(v >> 8), (char)(v >> 16), (char)(v >> 24)}; };
        auto le16 = [](std::uint16_t v) { return std::string{(char)v, (char)(v >> 8)}; };
        std::string local = le32(0x04034b50) + le16(20) + le16(0) + le16(0) + le16(0) + le16(0) + le32(0) + le32((std::uint32_t)data.size()) +
                            le32((std::uint32_t)data.size()) + le16((std::uint16_t)name.size()) + le16(0) + name + data;
        std::string central = le32(0x02014b50) + le16(20) + le16(20) + le16(0) + le16(0) + le16(0) + le16(0) + le32(0) +
                              le32((std::uint32_t)data.size()) + le32((std::uint32_t)data.size()) + le16((std::uint16_t)name.size()) +
                              le16(0) + le16(0) + le16(0) + le16(0) + le32(0) + le32(0) + name;
        std::string end = le32(0x06054b50) + le16(0) + le16(0) + le16(1) + le16(1) + le32((std::uint32_t)central.size()) +
                          le32((std::uint32_t)local.size()) + le16(0);
        good_zip = local + central + end;
    }
    BlocklistPolicy stored;
    try {
        stored = download_blocklist(folder, fetch_from(L"https://download.microsoft.com/x.zip", good_zip));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "download failed: %s\n", e.what());
    }
    CHECK(stored.version == L"10.0.7.1" && stored.rule_count() == 3);
    BlocklistPolicy loaded;
    std::map<std::wstring, std::wstring> meta;
    CHECK(load_policy(loaded, meta, folder) && loaded.rule_count() == 3);
    CHECK(meta[L"version"] == L"10.0.7.1" && meta[L"source"] == L"https://download.microsoft.com/x.zip");
    BlocklistPolicy none;
    CHECK(!load_policy(none, meta, folder + L"_nothing"));
    delete_file(join(folder, POLICY_MEMBER));
    delete_file(join(folder, L"blocklist.json"));
    RemoveDirectoryW(folder.c_str());
}

static void test_driver_paths_and_state() {
    CHECK(normalize_driver_path(L"\\SystemRoot\\System32\\drivers\\a.sys") == join(system_root(), L"System32\\drivers\\a.sys"));
    CHECK(normalize_driver_path(L"\\??\\C:\\x\\b.sys") == L"C:\\x\\b.sys");
    CHECK(normalize_driver_path(L"System32\\drivers\\c.sys") == join(system_root(), L"System32\\drivers\\c.sys"));
    CHECK(normalize_driver_path(L"\\Windows\\System32\\d.sys") == system_root().substr(0, 2) + L"\\Windows\\System32\\d.sys");
    CHECK(normalize_driver_path(L"").empty() && normalize_driver_path(L"relative.sys").empty());
    CHECK(normalize_driver_path(L"\\Device\\NoSuchVolume99\\x.sys").empty());

    ProtectionState s;
    s.blocklist_setting = 0;
    s.hvci_enabled = true;
    CHECK(!s.enforced());
    s.blocklist_setting = -1;
    CHECK(s.enforced());
    s.hvci_enabled = false;
    s.build = 19045;
    CHECK(!s.enforced());
    s.build = 22631;
    CHECK(s.enforced());
    CHECK(s.summary().find(L"not set (Windows default)") != std::wstring::npos);

    auto files = collect_driver_files();
    CHECK(files.size() > 50);
    bool loaded = false;
    for (const auto& f : files) loaded |= f.loaded;
    CHECK(loaded);
    CHECK(!loaded_driver_paths().empty() && !driver_services().empty());
}

// An embedded signature taken from a real driver on this machine: build a policy that denies it and check that the match
// follows the signer rules (TBS hash, publisher, OEM id).
static void test_signer_matching() {
    std::vector<Entry> sys;
    list_dir(join(system32(), L"drivers"), sys);
    PeDetails signed_file;
    for (const Entry& e : sys) {
        if (!ends_with(lower(e.name), L".sys")) continue;
        PeDetails d = analyze_pe(e.path);
        if (d.error.empty() && !d.signatures.empty() && d.signatures[0].leaf() && !d.signer().empty()) {
            signed_file = d;
            break;
        }
    }
    if (signed_file.path.empty()) {
        std::printf("  (no embedded signature found in System32\\drivers: signer matching not exercised)\n");
        return;
    }
    const Signature& sig = signed_file.signatures[0];
    CHECK(signed_file.hashes.count(L"sha1") && signed_file.hashes[L"sha256"].size() == 64);
    CHECK(!sig.chain.empty() && !sig.certificates.empty());
    std::wstring tbs = *sig.chain[0].tbs_hashes().begin();
    std::wstring tbs256;
    for (const auto& h : sig.chain[0].tbs_hashes()) {
        if (h.size() == 64) tbs256 = h;
    }
    CHECK(!tbs256.empty());

    BlocklistPolicy p;
    DeniedSigner s;
    s.name = L"Test signer";
    s.tbs = {tbs256};
    p.signers.push_back(s);
    CHECK(p.match(signed_file).size() == 1);                            // any file signed with that certificate
    p.signers[0].publisher = signed_file.signer();
    CHECK(p.match(signed_file).size() == 1);                            // publisher equals the leaf's CN
    p.signers[0].publisher = L"Somebody Else Ltd";
    CHECK(p.match(signed_file).empty());
    p.signers[0].publisher.clear();
    p.signers[0].oem_id = L"definitely-not-the-program-name";
    CHECK(p.match(signed_file).empty());
    p.signers[0].oem_id.clear();
    p.signers[0].tbs = {L"0000"};
    CHECK(p.match(signed_file).empty());                                // another certificate
    // the hash rule built from the file's own Authenticode hash
    BlocklistPolicy by_hash;
    by_hash.hashes[signed_file.hashes[L"sha256"]] = L"This very file";
    CHECK(by_hash.match(signed_file).size() == 1);
    std::printf("  checked against %ls (%zu signature(s), signer %ls)\n", base_name(signed_file.path).c_str(), signed_file.signatures.size(),
                signed_file.signer().c_str());
}

static void test_real_blocklist() {
    BlocklistPolicy policy;
    try {
        policy = download_blocklist(temp_dir() + L"\\ddcore_realblocklist_" + std::to_wstring(GetCurrentProcessId()));
    } catch (const std::exception& e) {
        std::printf("  (the real blocklist could not be downloaded: %s)\n", e.what());
        return;
    }
    CHECK(policy.rule_count() > 100 && !policy.version.empty());
    auto drivers = collect_driver_files();
    auto results = check_drivers(policy, drivers);
    std::size_t flagged = 0, errors = 0;
    for (const auto& r : results) {
        flagged += r.flagged();
        errors += !r.info.error.empty();
    }
    std::printf("  real blocklist %ls: %zu rules (%zu hashes, %zu file rules, %zu signers); %zu drivers checked, %zu flagged, %zu unreadable\n",
                policy.version.c_str(), policy.rule_count(), policy.hashes.size(), policy.file_rules.size(), policy.signers.size(),
                results.size(), flagged, errors);
    std::wstring dir = temp_dir() + L"\\ddcore_realblocklist_" + std::to_wstring(GetCurrentProcessId());
    delete_file(join(dir, POLICY_MEMBER));
    delete_file(join(dir, L"blocklist.json"));
    RemoveDirectoryW(dir.c_str());
}

int run_blocklist_tests() {
    test_zip_and_xml();
    test_url_helpers();
    test_versions_and_rules();
    test_policy();
    test_blocklist_storage();
    test_driver_paths_and_state();
    test_signer_matching();
    test_real_blocklist();
    std::printf("blocklist: %d checks, %d failed\n", checks, failures);
    return failures;
}
