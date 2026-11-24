// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements IP parsing, the IPv4 mapped form and the classification against the private and special network lists.

#include <ddcore/ip.hpp>

#include <algorithm>
#include <cstring>

#include <ddcore/common.hpp>

namespace dd {

typedef unsigned __int128 u128;

u128 IpAddress::value() const {
    u128 v = 0;
    for (int i = 0; i < (v6 ? 16 : 4); ++i) v = (v << 8) | bytes[i];
    return v;
}

IpAddress IpAddress::from_value(u128 v, bool is_v6) {
    IpAddress a;
    a.v6 = is_v6;
    int n = is_v6 ? 16 : 4;
    for (int i = n - 1; i >= 0; --i) {
        a.bytes[i] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
    return a;
}

// ::ffff:a.b.c.d: an IPv4 address in an IPv6 socket
static bool mapped_v4(const IpAddress& a, IpAddress& v4) {
    if (!a.v6) return false;
    for (int i = 0; i < 10; ++i) {
        if (a.bytes[i]) return false;
    }
    if (a.bytes[10] != 0xFF || a.bytes[11] != 0xFF) return false;
    v4 = IpAddress();
    std::memcpy(v4.bytes, a.bytes + 12, 4);
    return true;
}

std::wstring IpAddress::str() const {
    wchar_t buf[64];
    IpAddress mapped;
    if (mapped_v4(*this, mapped)) return L"::ffff:" + mapped.str();
    if (!v6) {
        swprintf(buf, 64, L"%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
        return buf;
    }
    unsigned groups[8];
    for (int i = 0; i < 8; ++i) groups[i] = (bytes[2 * i] << 8) | bytes[2 * i + 1];
    // the longest run of zero groups (two or more) becomes "::"
    int best_start = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (groups[i]) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && !groups[j]) ++j;
        if (j - i > best_len) {
            best_len = j - i;
            best_start = i;
        }
        i = j;
    }
    if (best_len < 2) best_start = -1;
    std::wstring out;
    for (int i = 0; i < 8; ++i) {
        if (i == best_start) {
            out += L"::";
            i += best_len - 1;
            continue;
        }
        if (!out.empty() && out.back() != L':') out += L":";
        swprintf(buf, 64, L"%x", groups[i]);
        out += buf;
    }
    return out;
}

static bool in_net(const IpAddress& ip, const char* cidr);

// An IPv4 address carried in an IPv6 one is judged as the IPv4 address it holds (as Python 3.13 does).
bool IpAddress::is_unspecified() const {
    IpAddress m;
    return mapped_v4(*this, m) ? m.is_unspecified() : value() == 0;
}
bool IpAddress::is_loopback() const {
    IpAddress m;
    if (mapped_v4(*this, m)) return m.is_loopback();
    return v6 ? value() == 1 : bytes[0] == 127;
}
bool IpAddress::is_link_local() const {
    IpAddress m;
    if (mapped_v4(*this, m)) return m.is_link_local();
    return v6 ? (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) : (bytes[0] == 169 && bytes[1] == 254);
}
bool IpAddress::is_multicast() const {
    IpAddress m;
    if (mapped_v4(*this, m)) return m.is_multicast();
    return v6 ? bytes[0] == 0xFF : (bytes[0] & 0xF0) == 0xE0;
}

bool IpAddress::is_private() const {
    static const char* v4_private[] = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29",
                                       "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
                                       "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32"};
    static const char* v4_global[] = {"192.0.0.9/32", "192.0.0.10/32"};
    static const char* v6_private[] = {"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
                                       "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10"};
    static const char* v6_global[] = {"2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28"};
    IpAddress m;
    if (mapped_v4(*this, m)) return m.is_private();
    if (v6) {
        for (const char* g : v6_global) {
            if (in_net(*this, g)) return false;
        }
        for (const char* p : v6_private) {
            if (in_net(*this, p)) return true;
        }
        return false;
    }
    for (const char* g : v4_global) {
        if (in_net(*this, g)) return false;
    }
    for (const char* p : v4_private) {
        if (in_net(*this, p)) return true;
    }
    return false;
}

bool IpAddress::is_global() const {
    IpAddress m;
    if (mapped_v4(*this, m)) return m.is_global();
    if (!v6 && in_net(*this, "100.64.0.0/10")) return false;   // shared address space: neither private nor global
    return !is_private();
}

bool parse_ip(const std::wstring& text_in, IpAddress& out) {
    std::wstring text = trim(text_in.substr(0, text_in.find(L'%')));
    if (text.empty()) return false;
    IpAddress a;
    if (text.find(L':') == std::wstring::npos) {
        auto parts = split(text, L'.');
        if (parts.size() != 4) return false;
        for (int i = 0; i < 4; ++i) {
            if (parts[i].empty() || parts[i].size() > 3) return false;
            unsigned v = 0;
            for (wchar_t c : parts[i]) {
                if (c < L'0' || c > L'9') return false;
                v = v * 10 + (unsigned)(c - L'0');
            }
            if (v > 255) return false;
            a.bytes[i] = (unsigned char)v;
        }
        out = a;
        return true;
    }
    a.v6 = true;
    // an IPv4 tail ("::ffff:1.2.3.4") counts for two groups
    std::wstring body = text;
    std::vector<unsigned> tail_v4;
    std::size_t last_colon = body.find_last_of(L':');
    if (body.find(L'.', last_colon) != std::wstring::npos) {
        IpAddress v4;
        if (!parse_ip(body.substr(last_colon + 1), v4) || v4.v6) return false;
        char hex[16];
        snprintf(hex, sizeof(hex), "%x:%x", (v4.bytes[0] << 8) | v4.bytes[1], (v4.bytes[2] << 8) | v4.bytes[3]);
        body = body.substr(0, last_colon + 1) + wide(hex);
    }
    auto parse_groups = [](const std::wstring& t, std::vector<unsigned>& groups) {
        if (t.empty()) return true;
        for (const auto& g : split(t, L':')) {
            if (g.empty() || g.size() > 4) return false;
            unsigned v = 0;
            for (wchar_t c : g) {
                unsigned d;
                if (c >= L'0' && c <= L'9') d = (unsigned)(c - L'0');
                else if (c >= L'a' && c <= L'f') d = (unsigned)(c - L'a' + 10);
                else if (c >= L'A' && c <= L'F') d = (unsigned)(c - L'A' + 10);
                else return false;
                v = v * 16 + d;
            }
            groups.push_back(v);
        }
        return true;
    };
    std::vector<unsigned> head, tail;
    std::size_t dc = body.find(L"::");
    std::vector<unsigned> all;
    if (dc != std::wstring::npos) {
        if (body.find(L"::", dc + 1) != std::wstring::npos) return false;
        if (!parse_groups(body.substr(0, dc), head) || !parse_groups(body.substr(dc + 2), tail) || head.size() + tail.size() > 7) return false;
        all = head;
        all.insert(all.end(), 8 - head.size() - tail.size(), 0u);
        all.insert(all.end(), tail.begin(), tail.end());
    } else {
        if (!parse_groups(body, all) || all.size() != 8) return false;
    }
    for (int i = 0; i < 8; ++i) {
        a.bytes[2 * i] = (unsigned char)(all[i] >> 8);
        a.bytes[2 * i + 1] = (unsigned char)(all[i] & 0xFF);
    }
    out = a;
    return true;
}

bool IpNetwork::contains(const IpAddress& ip) const {
    if (ip.v6 != base.v6) return false;
    int total = bits();
    if (prefix == 0) return true;
    u128 mask = ((total == 128 ? ~(u128)0 : (((u128)1 << total) - 1)) >> (total - prefix)) << (total - prefix);
    return (ip.value() & mask) == (base.value() & mask);
}

bool parse_network(const std::wstring& cidr, IpNetwork& out) {
    std::size_t slash = cidr.find(L'/');
    IpAddress base;
    if (!parse_ip(slash == std::wstring::npos ? cidr : cidr.substr(0, slash), base)) return false;
    int max = base.v6 ? 128 : 32, prefix = max;
    if (slash != std::wstring::npos) {
        std::wstring p = cidr.substr(slash + 1);
        if (p.empty() || p.size() > 3) return false;
        prefix = 0;
        for (wchar_t c : p) {
            if (c < L'0' || c > L'9') return false;
            prefix = prefix * 10 + (c - L'0');
        }
        if (prefix > max) return false;
    }
    u128 mask = prefix == 0 ? 0 : (((max == 128 ? ~(u128)0 : (((u128)1 << max) - 1)) >> (max - prefix)) << (max - prefix));
    out.base = IpAddress::from_value(base.value() & mask, base.v6);
    out.prefix = prefix;
    return true;
}

static bool in_net(const IpAddress& ip, const char* cidr) {
    IpNetwork n;
    if (!parse_network(wide(cidr), n)) return false;
    return n.contains(ip);
}

std::vector<IpNetwork> summarize_range(const IpAddress& start, const IpAddress& end) {
    std::vector<IpNetwork> out;
    if (start.v6 != end.v6) return out;
    int bits = start.v6 ? 128 : 32;
    u128 first = start.value(), last = end.value();
    while (first <= last) {
        // the biggest block that starts at `first` (aligned) and does not go past `last`
        int host_bits = 0;
        while (host_bits < bits) {
            if (host_bits + 1 >= 128) break;   // the whole IPv6 space is never summarised here
            u128 size = (u128)1 << (host_bits + 1);
            bool aligned = host_bits + 1 <= bits && (first & (size - 1)) == 0;
            if (!aligned || first + size - 1 > last || first + size - 1 < first) break;
            ++host_bits;
        }
        IpNetwork n;
        n.base = IpAddress::from_value(first, start.v6);
        n.prefix = bits - host_bits;
        out.push_back(n);
        u128 next = first + (((u128)1 << host_bits));
        if (next <= first) break;   // wrapped around the end of the space
        first = next;
        if (out.size() > 4096) break;   // an absurd range: the caller refuses it anyway
    }
    return out;
}

}  // namespace dd
