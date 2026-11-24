// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the PE file facts that code integrity policies need: Authenticode hashes, embedded certificates and the OEM ID.

// Facts a WDAC code integrity policy needs, read-only: Authenticode hashes, embedded certificate chain, SpcSpOpusInfo name (the OEM ID), version.
// Catalog-signed files have no embedded signature: only their hash and version can be checked.
#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace dd {

struct Certificate {
    std::string der, tbs, serial, issuer, subject;   // issuer and subject: the raw DER Name, compared byte for byte
    std::set<std::wstring> tbs_hashes() const;       // SHA1, SHA256 and SHA384 of the TBS part (upper-case hex)
    std::wstring common_name() const;
};

struct Signature {
    std::vector<Certificate> chain;          // the signer chain, leaf first
    std::wstring opus_program;
    std::vector<Certificate> certificates;   // every certificate shipped in the same SignedData
    const Certificate* leaf() const { return chain.empty() ? nullptr : &chain[0]; }
};

// Parsing from bytes (so it can be tested without files). Throws std::runtime_error on malformed DER.
Certificate parse_certificate(const std::string& der);
std::vector<Signature> parse_pkcs7(const std::string& buf, int depth = 0);   // includes nested (dual) signatures
std::wstring name_attribute(const std::string& name_der, const std::string& oid_dotted);

struct PeLayout {
    std::size_t checksum_offset = 0, cert_dir_offset = 0, cert_offset = 0, cert_size = 0;
};
PeLayout pe_layout(const std::string& data);   // throws std::runtime_error when it is not a PE file
std::map<std::wstring, std::wstring> authenticode_hashes(const std::string& data, const PeLayout& layout);   // "sha1", "sha256"
std::vector<Signature> embedded_signatures(const std::string& data, const PeLayout& layout);

struct PeDetails {
    std::wstring path;
    std::map<std::wstring, std::wstring> hashes;    // sha1, sha256 -> upper-case hex
    std::vector<Signature> signatures;
    std::vector<unsigned> version;                  // 4 numbers, empty when none
    std::map<std::wstring, std::wstring> strings;   // OriginalFilename, InternalName, ProductName, FileDescription
    std::wstring error;
    std::wstring signer() const;                    // common name of the first signature's leaf
};
PeDetails analyze_pe(const std::wstring& path, std::size_t max_size = 256u * 1024 * 1024);

std::wstring hash_hex(const wchar_t* algorithm, const std::string& bytes);   // BCRYPT_SHA1_ALGORITHM ... upper-case hex
}  // namespace dd
