// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the world map data and the country outlines, loaded from a file or from JSON text.

#include <ddcore/geoip.hpp>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <functional>
#include <stdexcept>

#include <windows.h>

namespace dd {

// region Countries

namespace {

std::wstring g_world_file;
std::string g_world_json;
bool g_world_loaded = false;
World g_world;
std::mutex g_world_lock;

const std::map<std::wstring, std::wstring>& aliases() {
    // Spellings registries use that Natural Earth does not
    static const std::map<std::wstring, std::wstring> a = {
        {L"UNITED STATES", L"US"}, {L"UNITED STATES OF AMERICA", L"US"}, {L"USA", L"US"}, {L"UK", L"GB"}, {L"UNITED KINGDOM", L"GB"},
        {L"GREAT BRITAIN", L"GB"}, {L"RUSSIAN FEDERATION", L"RU"}, {L"KOREA, REPUBLIC OF", L"KR"}, {L"REPUBLIC OF KOREA", L"KR"},
        {L"SOUTH KOREA", L"KR"}, {L"VIET NAM", L"VN"}, {L"IRAN, ISLAMIC REPUBLIC OF", L"IR"}, {L"TAIWAN, PROVINCE OF CHINA", L"TW"},
        {L"CZECHIA", L"CZ"}, {L"THE NETHERLANDS", L"NL"}, {L"HOLLAND", L"NL"}, {L"EU", L""}, {L"EUROPEAN UNION", L""}, {L"AP", L""}, {L"ZZ", L""}};
    return a;
}

std::wstring upper(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towupper(c);
    return s;
}

std::string load_resource() {
    HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(2), RT_RCDATA);
    if (!res) return "";
    HGLOBAL mem = LoadResource(nullptr, res);
    DWORD size = SizeofResource(nullptr, res);
    if (!mem || !size) return "";
    return std::string(static_cast<const char*>(LockResource(mem)), size);
}

void build_world(const std::string& json_utf8) {
    Json data = parse_json(wide(json_utf8));
    World w;
    w.lookup = aliases();
    for (const Json& c : data.get(L"countries").as_list()) {
        Country country;
        country.code = c.get(L"code").str();
        country.name = c.get(L"name").str();
        country.lon = c.get(L"label").at(0).num();
        country.lat = c.get(L"label").at(1).num();
        for (const Json& ring : c.get(L"rings").as_list()) {
            std::vector<std::pair<double, double>> points;
            for (const Json& p : ring.items()) points.emplace_back(p.at(0).num(), p.at(1).num());
            country.rings.push_back(std::move(points));
        }
        if (!country.code.empty()) {
            std::vector<std::wstring> keys = {country.code, c.get(L"iso3").str()};
            for (const Json& n : c.get(L"names").as_list()) keys.push_back(n.str());
            for (const auto& k : keys) {
                if (!k.empty()) w.lookup.emplace(upper(k), country.code);
            }
        }
        w.countries.push_back(std::move(country));
    }
    g_world = std::move(w);
    g_world_loaded = true;
}

}  // namespace

void set_world_data_file(const std::wstring& path) {
    std::lock_guard<std::mutex> g(g_world_lock);
    g_world_file = path;
    g_world_loaded = false;
}

void set_world_data(const std::string& json_utf8) {
    std::lock_guard<std::mutex> g(g_world_lock);
    g_world_json = json_utf8;
    g_world_loaded = false;
}

const World& world() {
    std::lock_guard<std::mutex> g(g_world_lock);
    if (g_world_loaded) return g_world;
    std::string json = g_world_json;
    if (json.empty() && !g_world_file.empty()) read_file(g_world_file, json);
    if (json.empty()) json = load_resource();
    if (json.empty()) read_file(join(join(exe_dir(), L"data"), L"world_countries.json"), json);
    if (json.empty()) throw std::runtime_error("The world map data is missing (world_countries.json)");
    build_world(json);
    return g_world;
}

std::wstring country_code(const std::wstring& text) {
    std::wstring key = upper(trim(text));
    if (key.empty()) return L"";
    const World& w = world();
    auto it = w.lookup.find(key);
    return it == w.lookup.end() ? L"" : it->second;
}

const Country* find_country(const std::wstring& code) {
    for (const Country& c : world().countries) {
        if (c.code == code) return &c;
    }
    return nullptr;
}

std::wstring home_country() {
    GEOID id = GetUserGeoID(GEOCLASS_NATION);
    wchar_t buf[8] = {0};
    if (GetGeoInfoW(id, GEO_ISO2, buf, 8, 0)) return country_code(buf);
    return L"";
}

// endregion

// region MaxMind DB

namespace {

const char METADATA_MARKER[] = "\xab\xcd\xef" "MaxMind.com";
const std::size_t MARKER_LENGTH = sizeof(METADATA_MARKER) - 1;
const int MAX_DEPTH = 32;
const long MAX_DECODED_ITEMS = 100000;   // one DB-IP record is a few dozen items

}  // namespace

MmdbReader::MmdbReader(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw MmdbError("cannot open the database file");
    file_ = file;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
        close();
        throw MmdbError("empty database file");
    }
    size_ = (std::size_t)size.QuadPart;
    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping) {
        close();
        throw MmdbError("cannot map the database file");
    }
    mapping_ = mapping;
    buf_ = static_cast<const unsigned char*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!buf_) {
        close();
        throw MmdbError("cannot map the database file");
    }
    // the metadata marker is searched in the last 128 KB
    std::size_t from = size_ > 128 * 1024 ? size_ - 128 * 1024 : 0, start = std::string::npos;
    for (std::size_t i = size_ - MARKER_LENGTH + 1; i-- > from;) {
        if (!memcmp(buf_ + i, METADATA_MARKER, MARKER_LENGTH)) {
            start = i;
            break;
        }
    }
    if (start == std::string::npos) {
        close();
        throw MmdbError("not a MaxMind DB file");
    }
    data_end_ = start;   // the data section ends where the metadata marker starts
    std::size_t meta_start = start + MARKER_LENGTH;
    try {
        std::size_t pos = meta_start;
        long budget = MAX_DECODED_ITEMS;
        metadata_ = decode(pos, meta_start, size_, 0, budget);
        node_count_ = (std::size_t)metadata_.get(L"node_count").integer();
        record_size_ = (int)metadata_.get(L"record_size").integer();
        ip_version_ = (int)metadata_.get(L"ip_version").integer();
    } catch (const std::exception& e) {
        close();
        throw MmdbError(std::string("invalid metadata (") + e.what() + ")");
    }
    if ((record_size_ != 24 && record_size_ != 28 && record_size_ != 32) || (ip_version_ != 4 && ip_version_ != 6)) {
        close();
        throw MmdbError("unsupported record size / IP version");
    }
    node_bytes_ = (std::size_t)record_size_ / 4;
    std::size_t tree_size = node_bytes_ * node_count_;
    data_start_ = tree_size + 16;
    if (node_count_ == 0 || data_start_ > data_end_) {
        close();
        throw MmdbError("search tree larger than the file");
    }
    ipv4_start_ = 0;
    if (ip_version_ == 6) {
        std::size_t node = 0;
        for (int i = 0; i < 96 && node < node_count_; ++i) node = read_node(node, 0);
        ipv4_start_ = node;
    }
}

MmdbReader::~MmdbReader() { close(); }

void MmdbReader::close() {
    if (buf_) UnmapViewOfFile(buf_);
    buf_ = nullptr;
    if (mapping_) CloseHandle(mapping_);
    mapping_ = nullptr;
    if (file_ && file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    file_ = nullptr;
}

std::uint32_t MmdbReader::read_node(std::size_t node, int bit) const {
    const unsigned char* b = buf_ + node * node_bytes_;
    if (record_size_ == 24) {
        const unsigned char* p = b + (bit ? 3 : 0);
        return (p[0] << 16) | (p[1] << 8) | p[2];
    }
    if (record_size_ == 28) {
        if (bit) return ((b[3] & 0x0Fu) << 24) | (b[4] << 16) | (b[5] << 8) | b[6];
        return ((b[3] & 0xF0u) << 20) | (b[0] << 16) | (b[1] << 8) | b[2];
    }
    const unsigned char* p = b + (bit ? 4 : 0);
    return ((std::uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

Json MmdbReader::lookup(const std::wstring& addr_in) {
    std::wstring addr = addr_in.substr(0, addr_in.find(L'%'));
    unsigned char packed[16] = {0};
    int bits;
    bool v6 = addr.find(L':') != std::wstring::npos;
    if (v6) {
        // inet_pton through the system resolver would pull in winsock: parse by hand
        std::vector<std::wstring> groups;
        std::wstring left = addr, right;
        std::size_t dc = addr.find(L"::");
        std::vector<unsigned> head, tail;
        auto parse = [&](const std::wstring& text, std::vector<unsigned>& out) {
            if (text.empty()) return true;
            for (const auto& g : split(text, L':')) {
                if (g.empty() || g.size() > 4) return false;
                wchar_t* end = nullptr;
                unsigned long v = wcstoul(g.c_str(), &end, 16);
                if (!end || *end) return false;
                out.push_back((unsigned)v);
            }
            return true;
        };
        bool ok;
        if (dc != std::wstring::npos) {
            ok = parse(addr.substr(0, dc), head) && parse(addr.substr(dc + 2), tail) && head.size() + tail.size() <= 7;
        } else {
            ok = parse(addr, head) && head.size() == 8;
        }
        if (!ok) throw MmdbError("invalid IP address");
        std::vector<unsigned> all = head;
        if (dc != std::wstring::npos) all.insert(all.end(), 8 - head.size() - tail.size(), 0u);
        all.insert(all.end(), tail.begin(), tail.end());
        for (int i = 0; i < 8; ++i) {
            packed[2 * i] = (unsigned char)(all[i] >> 8);
            packed[2 * i + 1] = (unsigned char)(all[i] & 0xFF);
        }
        bits = 128;
        if (ip_version_ == 4) return Json();
    } else {
        auto parts = split(addr, L'.');
        if (parts.size() != 4) throw MmdbError("invalid IP address");
        for (int i = 0; i < 4; ++i) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(parts[i].c_str(), &end, 10);
            if (parts[i].empty() || !end || *end || v > 255) throw MmdbError("invalid IP address");
            packed[i] = (unsigned char)v;
        }
        bits = 32;
    }
    std::size_t node = (!v6 && ip_version_ == 6) ? ipv4_start_ : 0;
    for (int i = 0; i < bits; ++i) {
        if (node >= node_count_) break;
        int bit = (packed[i >> 3] >> (7 - (i & 7))) & 1;
        node = read_node(node, bit);
    }
    if (node == node_count_) return Json();   // no data for this address
    if (node < node_count_) throw MmdbError("invalid search tree");
    std::size_t offset = node - node_count_ - 16;
    long budget = MAX_DECODED_ITEMS;
    std::size_t pos = data_start_ + offset;
    return decode(pos, data_start_, data_end_, 0, budget);
}

// The file may have been tampered with: every read is bounded, pointers may not point to pointers (spec) and nesting / total
// decoded items are capped (pointer fan-out, loops).
Json MmdbReader::decode(std::size_t& pos, std::size_t base, std::size_t end, int depth, long& budget) const {
    if (--budget < 0 || depth > MAX_DEPTH) throw MmdbError("data section too deep or too large");
    auto take = [&](std::size_t n) {
        if (pos + n > end) throw MmdbError("value past the end of its section");
        return buf_ + pos;
    };
    if (!(base <= pos && pos < end)) throw MmdbError("offset outside its section");
    unsigned ctrl = buf_[pos++];
    unsigned kind = ctrl >> 5;
    if (kind == 1) {   // pointer
        unsigned ss = (ctrl >> 3) & 3, vvv = ctrl & 7;
        const unsigned char* raw = take(ss + 1);
        std::size_t ptr;
        auto be = [&](unsigned n) {
            std::size_t v = 0;
            for (unsigned i = 0; i < n; ++i) v = (v << 8) | raw[i];
            return v;
        };
        if (ss == 0) ptr = ((std::size_t)vvv << 8) | raw[0];
        else if (ss == 1) ptr = ((((std::size_t)vvv << 16) | be(2))) + 2048;
        else if (ss == 2) ptr = (((std::size_t)vvv << 24) | be(3)) + 526336;
        else ptr = be(4);
        pos += ss + 1;
        std::size_t target = base + ptr;
        if (!(base <= target && target < end) || (buf_[target] >> 5) == 1) throw MmdbError("invalid pointer");
        return decode(target, base, end, depth + 1, budget);
    }
    if (kind == 0) {   // extended type
        kind = 7 + take(1)[0];
        ++pos;
    }
    std::size_t size = ctrl & 0x1F;
    if (size >= 29) {
        std::size_t extra = size - 28;
        const unsigned char* raw = take(extra);
        std::size_t v = 0;
        for (std::size_t i = 0; i < extra; ++i) v = (v << 8) | raw[i];
        static const std::size_t add[3] = {29, 285, 65821};
        size = add[extra - 1] + v;
        pos += extra;
    }
    switch (kind) {
        case 2: {
            const unsigned char* p = take(size);
            std::string s(reinterpret_cast<const char*>(p), size);
            pos += size;
            return Json::string(wide(s));
        }
        case 3: {
            const unsigned char* p = take(8);
            unsigned char swapped[8];
            for (int i = 0; i < 8; ++i) swapped[i] = p[7 - i];
            double d;
            memcpy(&d, swapped, 8);
            pos += 8;
            return Json::number(d);
        }
        case 4: take(size); pos += size; return Json();   // bytes: not needed here
        case 5:
        case 6:
        case 9:
        case 10: {
            if (size > 16) throw MmdbError("integer too long");
            const unsigned char* p = take(size);
            double v = 0;
            for (std::size_t i = 0; i < size; ++i) v = v * 256 + p[i];
            pos += size;
            return Json::number(v);
        }
        case 8: {
            if (size > 4) throw MmdbError("int32 too long");
            const unsigned char* p = take(size);
            std::uint32_t v = 0;
            for (std::size_t i = 0; i < size; ++i) v = (v << 8) | p[i];
            pos += size;
            return Json::number((double)(std::int32_t)v);
        }
        case 7: {
            Json out = Json::object();
            for (std::size_t i = 0; i < size; ++i) {
                Json key = decode(pos, base, end, depth + 1, budget);
                Json value = decode(pos, base, end, depth + 1, budget);
                out.set(key.str(), value);
            }
            return out;
        }
        case 11: {
            Json out = Json::array();
            for (std::size_t i = 0; i < size; ++i) out.push(decode(pos, base, end, depth + 1, budget));
            return out;
        }
        case 14: return Json::boolean(size != 0);
        case 15: {
            const unsigned char* p = take(4);
            unsigned char swapped[4] = {p[3], p[2], p[1], p[0]};
            float f;
            memcpy(&f, swapped, 4);
            pos += 4;
            return Json::number(f);
        }
        case 12:
        case 13: return Json();
    }
    throw MmdbError("unknown data type " + std::to_string(kind));
}

// endregion

// region Locations

std::wstring Location::label() const {
    if (city.empty()) return country;
    return country.empty() ? city : city + L", " + country;
}

std::optional<Location> location_from_record(const Json& record) {
    if (!record.is_object() || !record.has(L"location")) return std::nullopt;
    const Json& loc = record.get(L"location");
    if (!loc.get(L"latitude").is_number() || !loc.get(L"longitude").is_number()) return std::nullopt;
    Location l;
    l.lat = loc.get(L"latitude").num();
    l.lon = loc.get(L"longitude").num();
    l.country = record.get(L"country").get(L"iso_code").str();
    l.city = record.get(L"city").get(L"names").get(L"en").str();
    l.region = record.get(L"subdivisions").at(0).get(L"names").get(L"en").str();
    return l;
}

namespace {
std::mutex g_locators_lock;
std::vector<GeoIP*> g_locators;   // every GeoIP alive: they must let go of the file before an update replaces it
}  // namespace

GeoIP::GeoIP(const std::wstring& folder) : folder_(folder) {
    std::lock_guard<std::mutex> g(g_locators_lock);
    g_locators.push_back(this);
}

GeoIP::~GeoIP() {
    {
        std::lock_guard<std::mutex> g(g_locators_lock);
        g_locators.erase(std::remove(g_locators.begin(), g_locators.end(), this), g_locators.end());
    }
    close();
}

std::wstring GeoIP::path() const { return join(folder_.empty() ? geoip_dir() : folder_, DBIP_FILE_NAME); }

MmdbReader* GeoIP::open() {
    if (suspended_) return nullptr;
    Entry info;
    if (!stat_path(path(), info)) return nullptr;
    if (info.modified != opened_mtime_) {   // first use, or the file was updated
        reader_.reset();
        cache_.clear();
        opened_mtime_ = info.modified;      // also on failure: a broken file is not retried on every lookup
        try {
            reader_ = std::make_unique<MmdbReader>(path());
        } catch (const std::exception&) {   // a corrupted or crafted file must never stop the traffic view
            reader_.reset();
        }
    }
    return reader_.get();
}

bool GeoIP::available() {
    std::lock_guard<std::recursive_mutex> g(lock_);
    return open() != nullptr;
}

std::optional<Location> GeoIP::locate(const std::wstring& addr) {
    std::lock_guard<std::recursive_mutex> g(lock_);
    auto cached = cache_.find(addr);
    if (cached != cache_.end()) return cached->second;
    MmdbReader* reader = open();
    if (!reader) return std::nullopt;
    std::optional<Location> loc;
    try {
        loc = location_from_record(reader->lookup(addr));
    } catch (const std::exception&) {   // corrupted / crafted data section
        loc = std::nullopt;
    }
    cache_[addr] = loc;
    return loc;
}

std::map<std::wstring, std::wstring> GeoIP::info() const {
    std::map<std::wstring, std::wstring> out;
    std::string text;
    Json j;
    if (read_file(join(folder_.empty() ? geoip_dir() : folder_, L"geoip.json"), text) && try_parse_json(wide(text), j) && j.is_object()) {
        for (const auto& [k, v] : j.members()) out[k] = v.str();
    }
    return out;
}

void GeoIP::close() {
    std::lock_guard<std::recursive_mutex> g(lock_);
    reader_.reset();
    cache_.clear();
}

void GeoIP::suspend() {
    std::lock_guard<std::recursive_mutex> g(lock_);
    suspended_ = true;
    close();
}

void GeoIP::resume() {
    std::lock_guard<std::recursive_mutex> g(lock_);
    suspended_ = false;
    opened_mtime_ = -1;   // open the file again at the next lookup
}

// endregion

// region Download

std::wstring geoip_dir() { return join(data_dir(), L"geoip"); }

std::vector<std::wstring> candidate_months(int year, int month) {
    wchar_t cur[16], prev[16];
    swprintf(cur, 16, L"%04d-%02d", year, month);
    swprintf(prev, 16, L"%04d-%02d", month == 1 ? year - 1 : year, month == 1 ? 12 : month - 1);
    return {cur, prev};
}

bool needs_update(const std::map<std::wstring, std::wstring>& info, double now_in) {
    auto it = info.find(L"downloaded");
    if (it == info.end()) return true;
    int y, mo, d, h, mi, s;
    if (swscanf(it->second.c_str(), L"%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) < 3) return true;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    std::time_t downloaded = std::mktime(&tm);
    double now = now_in < 0 ? now_seconds() : now_in;
    return (now - (double)downloaded) / 86400.0 > UPDATE_AFTER_DAYS;
}

bool gunzip(const std::string& data, std::string& out, std::size_t max_size, std::wstring& error) {
    if (data.size() < 18 || (unsigned char)data[0] != 0x1F || (unsigned char)data[1] != 0x8B || data[2] != 8) {
        error = L"Not a gzip file";
        return false;
    }
    unsigned flags = (unsigned char)data[3];
    std::size_t pos = 10;
    if (flags & 4) {   // FEXTRA
        if (pos + 2 > data.size()) {
            error = L"Damaged gzip header";
            return false;
        }
        pos += 2 + ((unsigned char)data[pos] | ((unsigned char)data[pos + 1] << 8));
    }
    for (unsigned bit : {8u, 16u}) {   // FNAME, FCOMMENT: zero-terminated
        if (flags & bit) {
            while (pos < data.size() && data[pos]) ++pos;
            ++pos;
        }
    }
    if (flags & 2) pos += 2;   // FHCRC
    if (pos >= data.size()) {
        error = L"Damaged gzip header";
        return false;
    }
    return inflate(reinterpret_cast<const unsigned char*>(data.data()) + pos, data.size() - pos, out, max_size, error);
}

namespace {

void install(const std::wstring& tmp, const std::wstring& target) {
    // Every reader of this program lets go of the old file first (the live traffic view keeps it memory-mapped, and Windows
    // then answers "Access is denied").
    std::wstring wanted = normcase(absolute(target));
    std::vector<GeoIP*> readers;
    {
        std::lock_guard<std::mutex> g(g_locators_lock);
        for (GeoIP* r : g_locators) {
            if (normcase(absolute(r->path())) == wanted) readers.push_back(r);
        }
    }
    for (GeoIP* r : readers) r->suspend();
    bool done = false;
    DWORD error = 0;
    for (int attempt = 0; attempt < 5 && !done; ++attempt) {
        if (MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            done = true;
        } else {
            error = GetLastError();
            if (attempt < 4) Sleep(500);   // another program (an antivirus) may hold the new file for a moment
        }
    }
    for (GeoIP* r : readers) r->resume();
    if (!done) throw std::runtime_error("the database could not be replaced (error " + std::to_string(error) + ")");
}

}  // namespace

std::map<std::wstring, std::wstring> download_dbip(const std::wstring& folder_in, const std::function<void(std::uint64_t)>& progress,
                                                   const DbFetch& fetch, const Stop& stop) {
    std::wstring folder = folder_in.empty() ? geoip_dir() : folder_in;
    make_dirs(folder);
    std::wstring target = join(folder, DBIP_FILE_NAME), tmp = target + L".download";
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::string last_error = "no month tried";
    for (const auto& month : candidate_months(tm.tm_year + 1900, tm.tm_mon + 1)) {
        std::wstring url = L"https://download.db-ip.com/free/dbip-city-lite-" + month + L".mmdb.gz";
        try {
            auto on_progress = [&](std::uint64_t done, std::uint64_t) {
                if (progress) progress(done);
            };
            HttpResponse r;
            if (fetch) {
                r = fetch(url, on_progress);
            } else {
                HttpRequest req;
                req.url = url;
                req.timeout_ms = 120000;
                req.max_bytes = 400u * 1024 * 1024;
                req.on_progress = on_progress;
                req.stop = stop;
                req.headers[L"User-Agent"] = L"DDCleaner/3.0 (GeoIP update)";
                r = http_request(req);
            }
            if (r.stopped) throw std::runtime_error("stopped");
            if (!r.ok) throw std::runtime_error(utf8(r.error));
            if (r.status != 200) throw std::runtime_error("HTTP " + std::to_string(r.status));
            if (!url_host_in(r.final_url, {L"db-ip.com"})) throw std::runtime_error("unexpected download location: " + utf8(r.final_url));
            std::string raw;
            std::wstring error;
            if (!gunzip(r.body, raw, 600u * 1024 * 1024, error)) throw std::runtime_error(utf8(error));
            r.body.clear();
            r.body.shrink_to_fit();
            if (!write_file(tmp, raw)) throw std::runtime_error("the database could not be written");
            raw.clear();
            raw.shrink_to_fit();
            std::wstring db_type;
            bool probe_ok = false;
            {
                MmdbReader reader(tmp);   // must be a valid city database before replacing the old one
                db_type = reader.metadata().get(L"database_type").str();
                probe_ok = location_from_record(reader.lookup(L"8.8.8.8")).has_value();
            }
            if (lower(db_type).find(L"city") == std::wstring::npos || !probe_ok) {
                throw std::runtime_error("unexpected database content (" + utf8(db_type) + ")");
            }
            install(tmp, target);
            std::map<std::wstring, std::wstring> info = {{L"month", month}, {L"downloaded", L""}, {L"source", r.final_url},
                                                          {L"database_type", db_type}, {L"attribution", DBIP_ATTRIBUTION}};
            wchar_t stamp[32];
            std::wcsftime(stamp, 32, L"%Y-%m-%dT%H:%M:%S", &tm);
            info[L"downloaded"] = stamp;
            Json meta = Json::object();
            for (const auto& [k, v] : info) meta.set(k, Json::string(v));
            write_file(join(folder, L"geoip.json"), utf8(meta.dump(true)));
            return info;
        } catch (const std::exception& e) {   // try the previous month, keep the old database
            last_error = e.what();
            delete_file(tmp);
            if (stop && stop()) break;
        }
    }
    throw std::runtime_error("DB-IP download failed: " + last_error);
}

// endregion

}  // namespace dd
