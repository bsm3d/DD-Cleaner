// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the world map outlines and the server location lookup from a memory-mapped MaxMind DB file.

// Countries for the world map (Natural Earth 1:110m outlines, bundled), and server locations from DB-IP "IP to City Lite"
// (CC BY 4.0, https://db-ip.com): a MaxMind DB (.mmdb) file, downloaded on request and read here with a small reader
// (the file is memory-mapped, lookups are cached).
//
// Attribution required by the license: "IP Geolocation by DB-IP".
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>
#include <ddcore/net.hpp>

namespace dd {

// region Countries
struct Country {
    std::wstring code, name;
    double lon = 0, lat = 0;   // the label point
    std::vector<std::vector<std::pair<double, double>>> rings;   // (lon, lat)
};

struct World {
    std::vector<Country> countries;
    std::map<std::wstring, std::wstring> lookup;   // upper-case code / ISO3 / name -> ISO2 code
};

// The bundled data: the file named by set_world_data_file(), then a world_countries.json resource of the executable, then
// data\world_countries.json next to it. Throws std::runtime_error when none can be read.
void set_world_data_file(const std::wstring& path);
void set_world_data(const std::string& json_utf8);
const World& world();
std::wstring country_code(const std::wstring& text);   // 'FR', 'FRA', 'France', 'United States' -> ISO 3166 alpha-2 ("" when unknown)
const Country* find_country(const std::wstring& code);
std::wstring home_country();                           // from the Windows region setting (offline)
// endregion

// region MaxMind DB
class MmdbError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class MmdbReader {
public:
    explicit MmdbReader(const std::wstring& path);   // throws MmdbError
    ~MmdbReader();
    MmdbReader(const MmdbReader&) = delete;
    MmdbReader& operator=(const MmdbReader&) = delete;
    Json lookup(const std::wstring& addr);          // null when there is no data for this address; throws MmdbError
    const Json& metadata() const { return metadata_; }

private:
    Json decode(std::size_t& pos, std::size_t base, std::size_t end, int depth, long& budget) const;
    std::uint32_t read_node(std::size_t node, int bit) const;
    void close();

    void* file_ = nullptr;
    void* mapping_ = nullptr;
    const unsigned char* buf_ = nullptr;
    std::size_t size_ = 0, data_start_ = 0, data_end_ = 0, node_count_ = 0, node_bytes_ = 0, ipv4_start_ = 0;
    int record_size_ = 0, ip_version_ = 0;
    Json metadata_;
};
// endregion

// region Locations
struct Location {
    std::wstring country;   // ISO code
    std::wstring city, region;
    double lat = 0, lon = 0;
    std::wstring label() const;   // "City, CC"
};
std::optional<Location> location_from_record(const Json& record);

class GeoIP {
public:
    explicit GeoIP(const std::wstring& folder = L"");
    ~GeoIP();
    GeoIP(const GeoIP&) = delete;
    GeoIP& operator=(const GeoIP&) = delete;

    std::wstring path() const;
    bool available();
    std::optional<Location> locate(const std::wstring& addr);   // nullopt when the database is missing or has no data
    std::map<std::wstring, std::wstring> info() const;          // geoip.json
    void close();
    // Let go of the database file and stay away from it: Windows refuses to replace a file that is memory-mapped.
    void suspend();
    void resume();

private:
    MmdbReader* open();   // the lock is held

    std::wstring folder_;
    std::unique_ptr<MmdbReader> reader_;
    double opened_mtime_ = -1;
    std::map<std::wstring, std::optional<Location>> cache_;
    std::recursive_mutex lock_;
    bool suspended_ = false;
};
// endregion

// region Download
constexpr const wchar_t* DBIP_ATTRIBUTION = L"IP Geolocation by DB-IP (db-ip.com, CC BY 4.0)";
constexpr const wchar_t* DBIP_FILE_NAME = L"dbip-city-lite.mmdb";
constexpr int UPDATE_AFTER_DAYS = 40;

std::wstring geoip_dir();
std::vector<std::wstring> candidate_months(int year, int month);   // this month's file, then last month's: "2026-11", "2026-10"
bool needs_update(const std::map<std::wstring, std::wstring>& info, double now = -1);
// gzip (RFC 1952) in memory.
bool gunzip(const std::string& data, std::string& out, std::size_t max_size, std::wstring& error);
using DbFetch = std::function<HttpResponse(const std::wstring& url, const std::function<void(std::uint64_t, std::uint64_t)>& progress)>;
// Download, decompress, validate and install the database (atomic replace). Throws std::runtime_error.
std::map<std::wstring, std::wstring> download_dbip(const std::wstring& folder = L"", const std::function<void(std::uint64_t)>& progress = nullptr,
                                                   const DbFetch& fetch = nullptr, const Stop& stop = never);
// endregion

}  // namespace dd
