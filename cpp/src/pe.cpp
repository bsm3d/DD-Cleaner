// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the PE reader: the TLV parsing of embedded signatures and the Authenticode hash facts of a file.

#include <ddcore/pe.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <windows.h>
#include <bcrypt.h>

#include <ddcore/common.hpp>
#include <ddcore/inspect.hpp>

namespace dd {

namespace {

const char* const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const char* const OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
const char* const OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12";
const std::size_t MAX_SIGNATURE_SIZE = 2 * 1024 * 1024;
const int MAX_NESTING = 4;
const std::size_t MAX_CERTIFICATES = 64, MAX_SIGNERS = 16, MAX_OID_BYTES = 64;

[[noreturn]] void bad(const char* why) { throw std::runtime_error(why); }

struct Tlv {
    int tag;
    std::size_t start, cs, ce;   // whole element start, content start and end
};

Tlv der_read(const std::string& buf, std::size_t off) {
    if (off + 2 > buf.size()) bad("truncated DER");
    int tag = (unsigned char)buf[off];
    std::size_t length = (unsigned char)buf[off + 1], pos = off + 2;
    if (length & 0x80) {
        std::size_t n = length & 0x7F;
        if (n == 0 || n > 4 || pos + n > buf.size()) bad("unsupported DER length");   // indefinite (BER) or absurd
        length = 0;
        for (std::size_t k = 0; k < n; ++k) length = (length << 8) | (unsigned char)buf[pos + k];
        pos += n;
    }
    std::size_t end = pos + length;
    if (end > buf.size() || end < pos) bad("DER length past end");
    return {tag, off, pos, end};
}

std::vector<Tlv> der_children(const std::string& buf, std::size_t start, std::size_t end) {
    std::vector<Tlv> out;
    std::size_t off = start;
    while (off < end) {
        Tlv t = der_read(buf, off);
        out.push_back(t);
        off = t.ce;
    }
    return out;
}

std::string der_oid(const std::string& buf, std::size_t cs, std::size_t ce) {
    if (cs >= ce) return "";
    if (ce - cs > MAX_OID_BYTES) bad("OID too long");
    unsigned char first = (unsigned char)buf[cs];
    std::string out = std::to_string(first / 40) + "." + std::to_string(first % 40);
    unsigned long long value = 0;
    for (std::size_t k = cs + 1; k < ce; ++k) {
        unsigned char b = (unsigned char)buf[k];
        value = (value << 7) | (b & 0x7F);
        if (!(b & 0x80)) {
            out += "." + std::to_string(value);
            value = 0;
        }
    }
    return out;
}

std::wstring der_string(int tag, const std::string& buf, std::size_t cs, std::size_t ce) {
    std::wstring out;
    if (tag == 0x1E) {   // BMPString
        for (std::size_t k = cs; k + 1 < ce; k += 2) out.push_back((wchar_t)(((unsigned char)buf[k] << 8) | (unsigned char)buf[k + 1]));
    } else if (tag == 0x1C) {   // UniversalString
        for (std::size_t k = cs; k + 3 < ce; k += 4) out.push_back((wchar_t)(((unsigned char)buf[k + 2] << 8) | (unsigned char)buf[k + 3]));
    } else if (tag == 0x13 || tag == 0x16 || tag == 0x14) {   // Printable, IA5, Teletex
        for (std::size_t k = cs; k < ce; ++k) out.push_back((wchar_t)(unsigned char)buf[k]);
    } else {
        out = wide(buf.substr(cs, ce - cs));
    }
    return out;
}

std::wstring opus_program(const std::string& buf, std::size_t attrs_cs, std::size_t attrs_ce) {
    for (const Tlv& attr : der_children(buf, attrs_cs, attrs_ce)) {
        auto parts = der_children(buf, attr.cs, attr.ce);
        if (parts.size() < 2 || der_oid(buf, parts[0].cs, parts[0].ce) != OID_SPC_SP_OPUS_INFO) continue;
        for (const Tlv& value : der_children(buf, parts[1].cs, parts[1].ce)) {
            for (const Tlv& p : der_children(buf, value.cs, value.ce)) {
                if (p.tag != 0xA0) continue;   // programName [0] EXPLICIT SpcString
                Tlv s = der_read(buf, p.cs);
                return der_string(s.tag == 0x80 ? 0x1E : 0x16, buf, s.cs, s.ce);
            }
        }
    }
    return L"";
}

std::vector<Certificate> chain_of(const Certificate& leaf, const std::vector<Certificate>& certs) {
    std::vector<Certificate> chain = {leaf};
    Certificate current = leaf;
    while (chain.size() < 10 && current.issuer != current.subject) {
        const Certificate* parent = nullptr;
        for (const auto& c : certs) {
            if (c.subject != current.issuer) continue;
            bool seen = false;
            for (const auto& k : chain) seen |= k.der == c.der;
            if (!seen) {
                parent = &c;
                break;
            }
        }
        if (!parent) break;
        chain.push_back(*parent);
        current = *parent;
    }
    return chain;
}

std::vector<Signature> nested_signatures(const std::string& buf, std::size_t cs, std::size_t ce, int depth) {
    std::vector<Signature> out;
    try {
        for (const Tlv& attr : der_children(buf, cs, ce)) {
            auto parts = der_children(buf, attr.cs, attr.ce);
            if (parts.size() < 2 || der_oid(buf, parts[0].cs, parts[0].ce) != OID_NESTED_SIGNATURE) continue;
            for (const Tlv& n : der_children(buf, parts[1].cs, parts[1].ce)) {
                try {
                    for (auto& s : parse_pkcs7(buf.substr(n.start, n.ce - n.start), depth + 1)) out.push_back(std::move(s));
                } catch (const std::exception&) {
                }
            }
        }
    } catch (const std::exception&) {
    }
    return out;
}

}  // namespace

std::wstring hash_hex(const wchar_t* algorithm, const std::string& bytes) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::wstring out;
    if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) == 0) {
        DWORD length = 0, got = 0;
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &got, 0);
        if (length && BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(hash, (PUCHAR)bytes.data(), (ULONG)bytes.size(), 0);
            std::vector<UCHAR> digest(length);
            if (BCryptFinishHash(hash, digest.data(), length, 0) == 0) {
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

std::set<std::wstring> Certificate::tbs_hashes() const {
    return {hash_hex(BCRYPT_SHA1_ALGORITHM, tbs), hash_hex(BCRYPT_SHA256_ALGORITHM, tbs), hash_hex(BCRYPT_SHA384_ALGORITHM, tbs)};
}

std::wstring Certificate::common_name() const { return name_attribute(subject, "2.5.4.3"); }

std::wstring name_attribute(const std::string& name, const std::string& oid) {
    try {
        Tlv root = der_read(name, 0);
        for (const Tlv& rdn : der_children(name, root.cs, root.ce)) {
            for (const Tlv& attr : der_children(name, rdn.cs, rdn.ce)) {
                auto parts = der_children(name, attr.cs, attr.ce);
                if (parts.size() < 2) continue;
                if (der_oid(name, parts[0].cs, parts[0].ce) == oid) return der_string(parts[1].tag, name, parts[1].cs, parts[1].ce);
            }
        }
    } catch (const std::exception&) {
    }
    return L"";
}

Certificate parse_certificate(const std::string& der) {
    Tlv root = der_read(der, 0);
    auto top = der_children(der, root.cs, root.ce);
    if (top.empty()) bad("bad certificate");
    const Tlv& tbs = top[0];
    auto fields = der_children(der, tbs.cs, tbs.ce);
    if (!fields.empty() && fields[0].tag == 0xA0) fields.erase(fields.begin());   // [0] version
    if (fields.size() < 5) bad("bad certificate");
    Certificate c;
    c.der = der;
    c.tbs = der.substr(tbs.start, tbs.ce - tbs.start);
    c.serial = der.substr(fields[0].cs, fields[0].ce - fields[0].cs);
    c.issuer = der.substr(fields[2].start, fields[2].ce - fields[2].start);
    c.subject = der.substr(fields[4].start, fields[4].ce - fields[4].start);
    return c;
}

std::vector<Signature> parse_pkcs7(const std::string& buf, int depth) {
    if (depth > MAX_NESTING) return {};
    Tlv root = der_read(buf, 0);
    auto top = der_children(buf, root.cs, root.ce);
    if (top.size() < 2 || der_oid(buf, top[0].cs, top[0].ce) != OID_SIGNED_DATA) return {};
    Tlv signed_data = der_read(buf, top[1].cs);
    auto parts = der_children(buf, signed_data.cs, signed_data.ce);
    std::vector<Certificate> certs;
    bool have_signers = false;
    std::size_t signers_cs = 0, signers_ce = 0;
    for (std::size_t i = 3; i < parts.size(); ++i) {
        const Tlv& p = parts[i];
        if (p.tag == 0xA0) {   // certificates [0] IMPLICIT
            auto list = der_children(buf, p.cs, p.ce);
            for (std::size_t k = 0; k < list.size() && k < MAX_CERTIFICATES; ++k) {
                try {
                    certs.push_back(parse_certificate(buf.substr(list[k].start, list[k].ce - list[k].start)));
                } catch (const std::exception&) {
                }   // attribute certificates etc.
            }
        } else if (p.tag == 0x31) {
            have_signers = true;
            signers_cs = p.cs;
            signers_ce = p.ce;
        }
    }
    if (!have_signers) return {};
    std::map<std::pair<std::string, std::string>, const Certificate*> by_issuer_serial;
    for (const auto& c : certs) by_issuer_serial[{c.issuer, c.serial}] = &c;

    std::vector<Signature> signatures, nested;
    auto infos = der_children(buf, signers_cs, signers_ce);
    for (std::size_t n = 0; n < infos.size() && n < MAX_SIGNERS; ++n) {
        // one broken SignerInfo (or nested signature, which is NOT covered by the signature and can be edited by anyone)
        // must never erase the signatures already parsed
        const Certificate* leaf = nullptr;
        std::wstring opus;
        bool has_unauth = false;
        std::size_t unauth_cs = 0, unauth_ce = 0;
        try {
            auto fields = der_children(buf, infos[n].cs, infos[n].ce);
            if (fields.size() < 2) continue;
            const Tlv& sid = fields[1];
            if (sid.tag == 0x30) {   // IssuerAndSerialNumber
                auto ids = der_children(buf, sid.cs, sid.ce);
                if (ids.size() >= 2) {
                    auto it = by_issuer_serial.find({buf.substr(ids[0].start, ids[0].ce - ids[0].start), buf.substr(ids[1].cs, ids[1].ce - ids[1].cs)});
                    if (it != by_issuer_serial.end()) leaf = it->second;
                }
            }
            for (std::size_t k = 3; k < fields.size(); ++k) {
                if (fields[k].tag == 0xA0) {
                    opus = opus_program(buf, fields[k].cs, fields[k].ce);
                } else if (fields[k].tag == 0xA1) {
                    has_unauth = true;
                    unauth_cs = fields[k].cs;
                    unauth_ce = fields[k].ce;
                }
            }
        } catch (const std::exception&) {
            continue;
        }
        if (leaf) signatures.push_back({chain_of(*leaf, certs), opus, certs});
        if (has_unauth) {
            for (auto& s : nested_signatures(buf, unauth_cs, unauth_ce, depth)) nested.push_back(std::move(s));
        }
    }
    for (auto& s : nested) signatures.push_back(std::move(s));
    return signatures;
}

PeLayout pe_layout(const std::string& data) {
    if (data.size() < 64 || data[0] != 'M' || data[1] != 'Z') bad("not a PE file");
    std::uint32_t pe;
    memcpy(&pe, data.data() + 0x3C, 4);
    if ((std::size_t)pe + 24 > data.size() || memcmp(data.data() + pe, "PE\0\0", 4) != 0) bad("bad PE signature");
    std::size_t opt = pe + 24;
    if (opt + 2 > data.size()) bad("truncated optional header");
    std::uint16_t magic;
    memcpy(&magic, data.data() + opt, 2);
    std::size_t dirs;
    if (magic == 0x10B) dirs = opt + 96;
    else if (magic == 0x20B) dirs = opt + 112;
    else bad("unknown optional header");
    std::size_t cert_dir = dirs + 4 * 8;   // the certificate table is directory number 4
    if (cert_dir + 8 > data.size()) bad("truncated optional header");
    std::uint32_t offset, size;
    memcpy(&offset, data.data() + cert_dir, 4);
    memcpy(&size, data.data() + cert_dir + 4, 4);
    if (offset == 0 || size == 0 || (std::uint64_t)offset + size > data.size()) {
        offset = (std::uint32_t)data.size();
        size = 0;
    }
    return {opt + 64, cert_dir, offset, size};
}

std::map<std::wstring, std::wstring> authenticode_hashes(const std::string& data, const PeLayout& l) {
    // whole file minus the checksum, the certificate directory entry and the certificate table
    std::string flat;
    flat.reserve(data.size());
    flat.append(data, 0, l.checksum_offset);
    flat.append(data, l.checksum_offset + 4, l.cert_dir_offset - (l.checksum_offset + 4));
    flat.append(data, l.cert_dir_offset + 8, l.cert_offset - (l.cert_dir_offset + 8));
    flat.append(data, l.cert_offset + l.cert_size, std::string::npos);
    return {{L"sha1", hash_hex(BCRYPT_SHA1_ALGORITHM, flat)}, {L"sha256", hash_hex(BCRYPT_SHA256_ALGORITHM, flat)}};
}

std::vector<Signature> embedded_signatures(const std::string& data, const PeLayout& l) {
    std::vector<Signature> signatures;
    std::size_t off = l.cert_offset, end = l.cert_offset + std::min(l.cert_size, MAX_SIGNATURE_SIZE);
    while (off + 8 <= end) {
        std::uint32_t length;
        std::uint16_t type;
        memcpy(&length, data.data() + off, 4);
        memcpy(&type, data.data() + off + 6, 2);
        if (length < 8 || off + length > end) break;
        if (type == 0x0002) {   // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            try {
                for (auto& s : parse_pkcs7(data.substr(off + 8, length - 8))) signatures.push_back(std::move(s));
            } catch (const std::exception&) {
            }   // unparsable signature: hash and version rules still apply
        }
        off += (length + 7) & ~7u;
    }
    return signatures;
}

std::wstring PeDetails::signer() const {
    if (signatures.empty() || !signatures[0].leaf()) return L"";
    return signatures[0].leaf()->common_name();
}

PeDetails analyze_pe(const std::wstring& path, std::size_t max_size) {
    PeDetails info;
    info.path = path;
    std::string data;
    if (!read_file(path, data, max_size)) {
        info.error = is_file(path) ? L"file too large" : L"cannot open the file";
        return info;
    }
    try {
        PeLayout layout = pe_layout(data);
        info.hashes = authenticode_hashes(data, layout);
        info.signatures = embedded_signatures(data, layout);
    } catch (const std::exception& e) {
        info.error = wide(e.what());
        return info;
    }
    PEInfo v = inspect_pe(path);
    info.strings = v.strings;
    if (!v.file_version.empty()) {
        unsigned a, b, c, d;
        if (swscanf(v.file_version.c_str(), L"%u.%u.%u.%u", &a, &b, &c, &d) == 4) info.version = {a, b, c, d};
    }
    return info;
}

}  // namespace dd
