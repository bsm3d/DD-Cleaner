// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the HTTPS client on WinHTTP, the zip extraction and the XML reader used by the Internet pages.

#include <ddcore/net.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <windows.h>
#include <winhttp.h>

namespace dd {

// region HTTP

std::wstring url_host(const std::wstring& url) {
    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256] = {0};
    parts.lpszHostName = host;
    parts.dwHostNameLength = 255;
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &parts)) return L"";
    return lower(std::wstring(parts.lpszHostName, parts.dwHostNameLength));
}

bool url_host_in(const std::wstring& url, const std::vector<std::wstring>& domains) {
    if (!starts_with(lower(url), L"https://")) return false;
    std::wstring host = url_host(url);
    for (const auto& d : domains) {
        if (host == d || ends_with(host, L"." + d)) return true;
    }
    return false;
}

std::wstring url_encode(const std::wstring& text) {
    std::string utf = utf8(text);
    std::wstring out;
    wchar_t buf[4];
    for (unsigned char c : utf) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((wchar_t)c);
        } else {
            swprintf(buf, 4, L"%%%02X", c);
            out += buf;
        }
    }
    return out;
}

namespace {

struct Handle {
    HINTERNET h = nullptr;
    ~Handle() {
        if (h) WinHttpCloseHandle(h);
    }
};

std::wstring last_error(const wchar_t* what) {
    wchar_t buf[64];
    swprintf(buf, 64, L" (error %lu)", GetLastError());
    return std::wstring(what) + buf;
}

}  // namespace

HttpResponse http_request(const HttpRequest& req) {
    HttpResponse res;
    std::wstring low = lower(req.url);
    bool secure = starts_with(low, L"https://");
    if (!secure && !(req.allow_http && starts_with(low, L"http://"))) {
        res.error = L"Only https addresses are used";
        return res;
    }
    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256] = {0}, path[4096] = {0}, extra[4096] = {0};
    parts.lpszHostName = host;
    parts.dwHostNameLength = 255;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 4095;
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = 4095;
    if (!WinHttpCrackUrl(req.url.c_str(), (DWORD)req.url.size(), 0, &parts)) {
        res.error = L"Invalid address";
        return res;
    }
    Handle session;
    session.h = WinHttpOpen(L"DDCleaner", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session.h) {
        res.error = last_error(L"WinHTTP could not start");
        return res;
    }
    int t = (int)req.timeout_ms;
    WinHttpSetTimeouts(session.h, t, t, t, t);
    Handle connection;
    connection.h = WinHttpConnect(session.h, std::wstring(parts.lpszHostName, parts.dwHostNameLength).c_str(), parts.nPort, 0);
    if (!connection.h) {
        res.error = last_error(L"Could not connect");
        return res;
    }
    std::wstring target = std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength) + std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    Handle request;
    request.h = WinHttpOpenRequest(connection.h, req.method.c_str(), target.empty() ? L"/" : target.c_str(), nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!request.h) {
        res.error = last_error(L"Could not build the request");
        return res;
    }
    std::wstring headers;
    for (const auto& [k, v] : req.headers) headers += k + L": " + v + L"\r\n";
    BOOL sent = WinHttpSendRequest(request.h, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(), (DWORD)headers.size(),
                                   req.body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)req.body.data(), (DWORD)req.body.size(),
                                   (DWORD)req.body.size(), 0);
    if (!sent || !WinHttpReceiveResponse(request.h, nullptr)) {
        res.error = last_error(L"No answer");
        return res;
    }
    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                        WINHTTP_NO_HEADER_INDEX);
    res.status = (int)status;
    DWORD url_size = 0;
    WinHttpQueryOption(request.h, WINHTTP_OPTION_URL, nullptr, &url_size);
    if (url_size) {
        std::wstring final_url(url_size / sizeof(wchar_t), L'\0');
        if (WinHttpQueryOption(request.h, WINHTTP_OPTION_URL, final_url.data(), &url_size)) {
            final_url.resize(url_size / sizeof(wchar_t));
            while (!final_url.empty() && final_url.back() == L'\0') final_url.pop_back();
            res.final_url = final_url;
        }
    }
    DWORD raw_size = 0;
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &raw_size, WINHTTP_NO_HEADER_INDEX);
    if (raw_size) {
        std::wstring raw(raw_size / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &raw_size,
                                WINHTTP_NO_HEADER_INDEX)) {
            for (const auto& line : split(raw, L'\n')) {
                std::size_t colon = line.find(L':');
                if (colon != std::wstring::npos && colon > 0) res.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
            }
        }
    }
    std::uint64_t total = 0;
    if (res.headers.count(L"content-length")) total = (std::uint64_t)wcstoull(res.headers[L"content-length"].c_str(), nullptr, 10);
    if (total > req.max_bytes) {
        res.too_large = true;
        res.error = L"The answer is too large";
        return res;
    }
    for (;;) {
        if (req.stop && req.stop()) {
            res.stopped = true;
            return res;
        }
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available)) {
            res.error = last_error(L"The download was interrupted");
            return res;
        }
        if (!available) break;
        std::string chunk(available, '\0');
        DWORD got = 0;
        if (!WinHttpReadData(request.h, chunk.data(), available, &got)) {
            res.error = last_error(L"The download was interrupted");
            return res;
        }
        res.body.append(chunk.data(), got);
        if (res.body.size() > req.max_bytes) {
            res.too_large = true;
            res.error = L"The answer is too large";
            res.body.clear();
            return res;
        }
        if (req.on_progress) req.on_progress(res.body.size(), total);
    }
    res.ok = true;
    return res;
}

HttpResponse http_get(const std::wstring& url, unsigned long timeout_ms, std::size_t max_bytes) {
    HttpRequest r;
    r.url = url;
    r.timeout_ms = timeout_ms;
    r.max_bytes = max_bytes;
    return http_request(r);
}

// endregion

// region Inflate (RFC 1951)

namespace {

struct Bits {
    const unsigned char* data;
    std::size_t size, pos = 0;
    unsigned long bitbuf = 0;
    int bitcnt = 0;
    bool error = false;

    int get(int need) {
        long val = (long)bitbuf;
        while (bitcnt < need) {
            if (pos >= size) {
                error = true;
                return 0;
            }
            val |= (long)data[pos++] << bitcnt;
            bitcnt += 8;
        }
        bitbuf = (unsigned long)(val >> need);
        bitcnt -= need;
        return (int)(val & ((1L << need) - 1));
    }
};

struct Huffman {
    short count[16];
    short symbol[320];
};

int build(Huffman& h, const short* length, int n) {
    for (int i = 0; i <= 15; ++i) h.count[i] = 0;
    for (int s = 0; s < n; ++s) ++h.count[length[s]];
    if (h.count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= 15; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return left;
    }
    short offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len) offs[len + 1] = (short)(offs[len] + h.count[len]);
    for (int s = 0; s < n; ++s) {
        if (length[s]) h.symbol[offs[length[s]]++] = (short)s;
    }
    return left;
}

int decode(Bits& b, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; ++len) {
        code |= b.get(1);
        if (b.error) return -1;
        int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const short LENS[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const short LEXT[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const short DISTS[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const short DEXT[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool codes(Bits& b, std::string& out, std::size_t max_size, const Huffman& lencode, const Huffman& distcode) {
    for (;;) {
        int symbol = decode(b, lencode);
        if (symbol < 0) return false;
        if (symbol < 256) {
            if (out.size() >= max_size) return false;
            out.push_back((char)symbol);
        } else if (symbol == 256) {
            return true;
        } else {
            symbol -= 257;
            if (symbol >= 29) return false;
            int len = LENS[symbol] + b.get(LEXT[symbol]);
            int dsym = decode(b, distcode);
            if (dsym < 0 || dsym >= 30) return false;
            std::size_t dist = (std::size_t)DISTS[dsym] + (std::size_t)b.get(DEXT[dsym]);
            if (b.error || dist > out.size() || out.size() + (std::size_t)len > max_size) return false;
            for (int i = 0; i < len; ++i) out.push_back(out[out.size() - dist]);
        }
    }
}

}  // namespace

bool inflate(const unsigned char* data, std::size_t size, std::string& out, std::size_t max_size, std::wstring& error) {
    Bits b{data, size};
    out.clear();
    int last;
    do {
        last = b.get(1);
        int type = b.get(2);
        if (b.error) {
            error = L"Truncated data";
            return false;
        }
        if (type == 0) {
            b.bitbuf = 0;
            b.bitcnt = 0;
            if (b.pos + 4 > size) {
                error = L"Truncated data";
                return false;
            }
            unsigned len = data[b.pos] | (data[b.pos + 1] << 8), nlen = data[b.pos + 2] | (data[b.pos + 3] << 8);
            b.pos += 4;
            if (len != (~nlen & 0xFFFF) || b.pos + len > size || out.size() + len > max_size) {
                error = L"Damaged data";
                return false;
            }
            out.append(reinterpret_cast<const char*>(data + b.pos), len);
            b.pos += len;
        } else if (type == 1 || type == 2) {
            Huffman lencode, distcode;
            if (type == 1) {
                short lengths[320];
                int s = 0;
                for (; s < 144; ++s) lengths[s] = 8;
                for (; s < 256; ++s) lengths[s] = 9;
                for (; s < 280; ++s) lengths[s] = 7;
                for (; s < 288; ++s) lengths[s] = 8;
                build(lencode, lengths, 288);
                for (s = 0; s < 30; ++s) lengths[s] = 5;
                build(distcode, lengths, 30);
            } else {
                static const short order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
                int nlen = b.get(5) + 257, ndist = b.get(5) + 1, ncode = b.get(4) + 4;
                if (b.error || nlen > 286 || ndist > 30) {
                    error = L"Damaged data";
                    return false;
                }
                short lengths[320];
                int index = 0;
                for (; index < ncode; ++index) lengths[order[index]] = (short)b.get(3);
                for (; index < 19; ++index) lengths[order[index]] = 0;
                Huffman lencode_codes;
                if (build(lencode_codes, lengths, 19) != 0) {
                    error = L"Damaged data";
                    return false;
                }
                index = 0;
                while (index < nlen + ndist) {
                    int symbol = decode(b, lencode_codes);
                    if (symbol < 0) {
                        error = L"Damaged data";
                        return false;
                    }
                    if (symbol < 16) {
                        lengths[index++] = (short)symbol;
                    } else {
                        int len = 0, rep;
                        if (symbol == 16) {
                            if (index == 0) {
                                error = L"Damaged data";
                                return false;
                            }
                            len = lengths[index - 1];
                            rep = 3 + b.get(2);
                        } else if (symbol == 17) {
                            rep = 3 + b.get(3);
                        } else {
                            rep = 11 + b.get(7);
                        }
                        if (index + rep > nlen + ndist) {
                            error = L"Damaged data";
                            return false;
                        }
                        while (rep--) lengths[index++] = (short)len;
                    }
                }
                if (lengths[256] == 0 || build(lencode, lengths, nlen) < 0 || build(distcode, lengths + nlen, ndist) < 0) {
                    error = L"Damaged data";
                    return false;
                }
            }
            if (!codes(b, out, max_size, lencode, distcode)) {
                error = b.error ? L"Truncated data" : L"Damaged or too large data";
                return false;
            }
        } else {
            error = L"Damaged data";
            return false;
        }
    } while (!last);
    return true;
}

// endregion

// region Zip

namespace {

std::uint32_t u32(const std::string& s, std::size_t at) {
    return (unsigned char)s[at] | ((unsigned char)s[at + 1] << 8) | ((unsigned char)s[at + 2] << 16) | ((std::uint32_t)(unsigned char)s[at + 3] << 24);
}
std::uint16_t u16(const std::string& s, std::size_t at) { return (std::uint16_t)((unsigned char)s[at] | ((unsigned char)s[at + 1] << 8)); }

}  // namespace

bool zip_extract(const std::string& zip, const std::string& member_name, std::string& out, std::wstring& error, std::size_t max_size) {
    if (zip.size() < 22) {
        error = L"Not a zip file";
        return false;
    }
    std::size_t eocd = std::string::npos;
    for (std::size_t i = zip.size() - 22 + 1; i-- > 0 && zip.size() - i <= 22 + 65535;) {
        if (u32(zip, i) == 0x06054b50) {
            eocd = i;
            break;
        }
    }
    if (eocd == std::string::npos) {
        error = L"Not a zip file";
        return false;
    }
    std::size_t entries = u16(zip, eocd + 10), dir = u32(zip, eocd + 16);
    std::size_t pos = dir;
    for (std::size_t n = 0; n < entries; ++n) {
        if (pos + 46 > zip.size() || u32(zip, pos) != 0x02014b50) break;
        std::uint16_t method = u16(zip, pos + 10);
        std::uint32_t csize = u32(zip, pos + 20), usize = u32(zip, pos + 24);
        std::size_t name_len = u16(zip, pos + 28), extra_len = u16(zip, pos + 30), comment_len = u16(zip, pos + 32), local = u32(zip, pos + 42);
        if (pos + 46 + name_len > zip.size()) break;
        std::string name = zip.substr(pos + 46, name_len);
        std::replace(name.begin(), name.end(), '\\', '/');
        std::size_t slash = name.find_last_of('/');
        std::string leaf = slash == std::string::npos ? name : name.substr(slash + 1);
        pos += 46 + name_len + extra_len + comment_len;
        if (leaf != member_name) continue;
        if (usize > max_size) {
            error = L"The file inside the archive is too large";
            return false;
        }
        if (local + 30 > zip.size() || u32(zip, local) != 0x04034b50) {
            error = L"Damaged archive";
            return false;
        }
        std::size_t data = local + 30 + u16(zip, local + 26) + u16(zip, local + 28);
        if (data + csize > zip.size()) {
            error = L"Damaged archive";
            return false;
        }
        if (method == 0) {
            out = zip.substr(data, csize);
        } else if (method == 8) {
            if (!inflate(reinterpret_cast<const unsigned char*>(zip.data()) + data, csize, out, max_size, error)) return false;
        } else {
            error = L"Unsupported compression";
            return false;
        }
        if (out.size() != usize) {
            error = L"Damaged archive";
            return false;
        }
        return true;
    }
    error = wide(member_name) + L" not found in the archive";
    return false;
}

// endregion

// region XML

std::wstring XmlNode::attr(const std::wstring& key, const std::wstring& fallback) const {
    auto it = attributes.find(key);
    return it == attributes.end() ? fallback : it->second;
}

const XmlNode* XmlNode::child(const std::wstring& n) const {
    for (const auto& c : children) {
        if (c.name == n) return &c;
    }
    return nullptr;
}

std::vector<const XmlNode*> XmlNode::all(const std::wstring& n) const {
    std::vector<const XmlNode*> out;
    for (const auto& c : children) {
        if (c.name == n) out.push_back(&c);
    }
    return out;
}

static void collect(const XmlNode& node, const std::wstring& name, std::vector<const XmlNode*>& out) {
    for (const auto& c : node.children) {
        if (c.name == name) out.push_back(&c);
        collect(c, name, out);
    }
}

std::vector<const XmlNode*> XmlNode::descendants(const std::wstring& n) const {
    std::vector<const XmlNode*> out;
    collect(*this, n, out);
    return out;
}

namespace {

struct XmlParser {
    const std::wstring& s;
    std::size_t i = 0;

    [[noreturn]] void fail(const char* why) const { throw std::runtime_error(std::string("XML: ") + why); }
    bool at(const wchar_t* t) const { return s.compare(i, wcslen(t), t) == 0; }
    void skip_space() {
        while (i < s.size() && iswspace(s[i])) ++i;
    }
    void skip_to(const wchar_t* end) {
        std::size_t at_end = s.find(end, i);
        if (at_end == std::wstring::npos) fail("unterminated construct");
        i = at_end + wcslen(end);
    }
    static std::wstring decode_entities(const std::wstring& t) {
        if (t.find(L'&') == std::wstring::npos) return t;
        std::wstring out;
        for (std::size_t k = 0; k < t.size(); ++k) {
            if (t[k] != L'&') {
                out.push_back(t[k]);
                continue;
            }
            std::size_t semi = t.find(L';', k);
            if (semi == std::wstring::npos) {
                out.push_back(t[k]);
                continue;
            }
            std::wstring ent = t.substr(k + 1, semi - k - 1);
            if (ent == L"amp") out.push_back(L'&');
            else if (ent == L"lt") out.push_back(L'<');
            else if (ent == L"gt") out.push_back(L'>');
            else if (ent == L"quot") out.push_back(L'"');
            else if (ent == L"apos") out.push_back(L'\'');
            else if (!ent.empty() && ent[0] == L'#') {
                long v = ent.size() > 1 && (ent[1] == L'x' || ent[1] == L'X') ? wcstol(ent.c_str() + 2, nullptr, 16) : wcstol(ent.c_str() + 1, nullptr, 10);
                if (v > 0 && v < 0x10000) out.push_back((wchar_t)v);
            } else {
                out += t.substr(k, semi - k + 1);
            }
            k = semi;
        }
        return out;
    }
    static std::wstring local_name(const std::wstring& n) {
        std::size_t colon = n.find(L':');
        return colon == std::wstring::npos ? n : n.substr(colon + 1);
    }
    std::wstring parse_name() {
        std::size_t start = i;
        while (i < s.size() && !iswspace(s[i]) && s[i] != L'>' && s[i] != L'/' && s[i] != L'=') ++i;
        if (i == start) fail("name expected");
        return s.substr(start, i - start);
    }

    // after "<": the element up to and including its end tag
    XmlNode element(int depth) {
        if (depth > 200) fail("too deep");
        XmlNode node;
        node.name = local_name(parse_name());
        for (;;) {
            skip_space();
            if (i >= s.size()) fail("unexpected end");
            if (s[i] == L'/') {
                ++i;
                if (i >= s.size() || s[i] != L'>') fail("'>' expected");
                ++i;
                return node;
            }
            if (s[i] == L'>') {
                ++i;
                break;
            }
            std::wstring key = local_name(parse_name());
            skip_space();
            if (i >= s.size() || s[i] != L'=') fail("'=' expected");
            ++i;
            skip_space();
            if (i >= s.size() || (s[i] != L'"' && s[i] != L'\'')) fail("quote expected");
            wchar_t quote = s[i++];
            std::size_t end = s.find(quote, i);
            if (end == std::wstring::npos) fail("unterminated attribute");
            if (!starts_with(key, L"xmlns")) node.attributes[key] = decode_entities(s.substr(i, end - i));
            i = end + 1;
        }
        while (i < s.size()) {
            if (at(L"<!--")) {
                skip_to(L"-->");
            } else if (at(L"<![CDATA[")) {
                std::size_t end = s.find(L"]]>", i);
                if (end == std::wstring::npos) fail("unterminated CDATA");
                node.text += s.substr(i + 9, end - i - 9);
                i = end + 3;
            } else if (at(L"<?")) {
                skip_to(L"?>");
            } else if (at(L"</")) {
                i += 2;
                std::wstring name = local_name(parse_name());
                skip_space();
                if (i >= s.size() || s[i] != L'>') fail("'>' expected");
                ++i;
                if (name != node.name) fail("mismatched end tag");
                return node;
            } else if (s[i] == L'<') {
                ++i;
                node.children.push_back(element(depth + 1));
            } else {
                std::size_t end = s.find(L'<', i);
                if (end == std::wstring::npos) fail("unterminated element");
                node.text += decode_entities(s.substr(i, end - i));
                i = end;
            }
        }
        fail("unterminated element");
    }
};

}  // namespace

XmlNode parse_xml(const std::string& bytes) {
    std::wstring text;
    if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0xFF && (unsigned char)bytes[1] == 0xFE) {
        text.assign(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / 2);
    } else if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0xFE && (unsigned char)bytes[1] == 0xFF) {
        text.resize((bytes.size() - 2) / 2);
        for (std::size_t k = 0; k < text.size(); ++k) text[k] = (wchar_t)(((unsigned char)bytes[2 + 2 * k] << 8) | (unsigned char)bytes[3 + 2 * k]);
    } else {
        std::size_t skip = (bytes.size() >= 3 && (unsigned char)bytes[0] == 0xEF && (unsigned char)bytes[1] == 0xBB && (unsigned char)bytes[2] == 0xBF) ? 3 : 0;
        text = wide(bytes.substr(skip));
    }
    XmlParser p{text};
    for (;;) {
        p.skip_space();
        if (p.at(L"<?")) p.skip_to(L"?>");
        else if (p.at(L"<!--")) p.skip_to(L"-->");
        else if (p.at(L"<!DOCTYPE")) p.skip_to(L">");
        else break;
    }
    if (p.i >= text.size() || text[p.i] != L'<') throw std::runtime_error("XML: no root element");
    ++p.i;
    XmlNode root = p.element(0);
    return root;
}

// endregion

}  // namespace dd
