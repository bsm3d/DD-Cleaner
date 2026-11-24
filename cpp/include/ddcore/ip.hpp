// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares IP address parsing, text output and the private and special range classification used by the traffic views.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dd {

struct IpAddress {
    bool v6 = false;
    unsigned char bytes[16] = {0};   // IPv4: the first 4 bytes

    int version() const { return v6 ? 6 : 4; }
    unsigned __int128 value() const;                       // the address as a number
    static IpAddress from_value(unsigned __int128 v, bool v6);
    std::wstring str() const;                              // IPv4 dotted, IPv6 compressed lower-case (RFC 5952)

    bool is_unspecified() const;
    bool is_loopback() const;
    bool is_link_local() const;
    bool is_multicast() const;
    bool is_private() const;   // the "not routable on the Internet" lists, as in ipaddress.is_private
    bool is_global() const;    // reachable on the Internet
};

// Text such as "192.168.1.1", "fe80::1%12" (the zone is dropped), "::ffff:1.2.3.4". False for anything else.
bool parse_ip(const std::wstring& text, IpAddress& out);

struct IpNetwork {
    IpAddress base;
    int prefix = 0;
    bool contains(const IpAddress& ip) const;
    int bits() const { return base.v6 ? 128 : 32; }
};
bool parse_network(const std::wstring& cidr, IpNetwork& out);   // "10.0.0.0/8", strict = false: host bits are cleared
// The smallest list of networks covering start..end (ipaddress.summarize_address_range).
std::vector<IpNetwork> summarize_range(const IpAddress& start, const IpAddress& end);

}  // namespace dd
