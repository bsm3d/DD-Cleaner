// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the small HTTPS client, zip extraction and XML reader used by the pages that read from the Internet.

#pragma once

#include <map>
#include <string>
#include <vector>

#include <ddcore/common.hpp>

namespace dd {

// region HTTP
struct HttpRequest {
    std::wstring url;
    std::wstring method = L"GET";
    std::map<std::wstring, std::wstring> headers;
    std::string body;
    unsigned long timeout_ms = 60000;
    std::size_t max_bytes = 20 * 1024 * 1024;   // the answer is refused beyond this
    // https only, unless allow_http: a download that could be tampered with in transit is not read
    bool allow_http = false;
    Stop stop;                                   // polled between chunks
    std::function<void(std::uint64_t done, std::uint64_t total)> on_progress;
};

struct HttpResponse {
    bool ok = false;           // a complete answer arrived (any status)
    int status = 0;
    std::string body;
    std::wstring final_url;    // after redirects
    std::wstring error;
    std::map<std::wstring, std::wstring> headers;   // lower-case names
    bool too_large = false;
    bool stopped = false;
};

HttpResponse http_request(const HttpRequest& request);
HttpResponse http_get(const std::wstring& url, unsigned long timeout_ms = 60000, std::size_t max_bytes = 20 * 1024 * 1024);
// "https://host/..." with a host that is exactly, or a sub-domain of, one of the given domains.
bool url_host_in(const std::wstring& url, const std::vector<std::wstring>& domains);
std::wstring url_host(const std::wstring& url);
std::wstring url_encode(const std::wstring& text);   // percent-encoding of the UTF-8 bytes
// endregion

// region Zip
// The content of one member of a zip archive held in memory (stored or deflated). The member is chosen by its file name
// (the part after the last slash, compared case-sensitively). False with an error when absent or damaged.
bool zip_extract(const std::string& zip, const std::string& member_name, std::string& out, std::wstring& error,
                 std::size_t max_size = 20 * 1024 * 1024);
// Raw DEFLATE (RFC 1951).
bool inflate(const unsigned char* data, std::size_t size, std::string& out, std::size_t max_size, std::wstring& error);
// endregion

// region XML
struct XmlNode {
    std::wstring name;   // local name: any "prefix:" is dropped
    std::map<std::wstring, std::wstring> attributes;
    std::wstring text;
    std::vector<XmlNode> children;
    std::wstring attr(const std::wstring& key, const std::wstring& fallback = L"") const;
    bool has_attr(const std::wstring& key) const { return attributes.count(key) > 0; }
    const XmlNode* child(const std::wstring& name) const;
    std::vector<const XmlNode*> all(const std::wstring& name) const;   // direct children with this name
    std::vector<const XmlNode*> descendants(const std::wstring& name) const;
};
// A document in UTF-8 or UTF-16 (BOM) or declared encoding; throws std::runtime_error on malformed input.
XmlNode parse_xml(const std::string& bytes);
// endregion

}  // namespace dd
