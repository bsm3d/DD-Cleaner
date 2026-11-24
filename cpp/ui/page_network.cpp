// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Firewall and Network page group: live traffic, the world map, the firewall report and the network report.

#include "pages.hpp"

#include <algorithm>
#include <cmath>
#include <memory>

#include <shellapi.h>

#include <ddcore/firewall.hpp>
#include <ddcore/geoip.hpp>
#include <ddcore/network.hpp>
#include <ddcore/online.hpp>
#include <ddcore/traffic.hpp>

using namespace dd;

namespace {

// region Shared state

std::shared_ptr<GeoIP> geo = std::make_shared<GeoIP>();
std::shared_ptr<TrafficMonitor> monitor;   // created on the first sample, on the worker thread
TrafficSnapshot snapshot;
bool have_snapshot = false;
FirewallReport fw;
NetworkReport net;
bool analyzed = false;
HWND traffic_pause = nullptr;

std::wstring rate_text(double bytes_per_second, bool available) { return available ? human_bytes(bytes_per_second) + L"/s" : L""; }

// endregion

// region Live traffic

struct TrafficPage {
    ui::Page* page = nullptr;
    HWND list = nullptr, group = nullptr, filter = nullptr, inbound = nullptr, ports = nullptr, local = nullptr, dns = nullptr, owner = nullptr;
    std::vector<std::wstring> app_names;   // by row: the application a row belongs to (for "show only this")
} traffic;

void render_map();

bool row_visible(const ConnectionRow& r, bool only_inbound, bool show_ports, bool show_local) {
    if (only_inbound && r.direction != L"In") return false;
    if (!show_ports && (r.direction == L"Listen" || r.direction == L"UDP")) return false;
    if (!show_local && r.remote_kind == L"This PC") return false;
    return true;
}

std::wstring endpoint(const std::wstring& addr, int port) {
    if (addr.empty()) return L"";
    return (addr.find(L':') != std::wstring::npos ? L"[" + addr + L"]" : addr) + L":" + std::to_wstring(port);
}

std::wstring location_text(const ConnectionRow& r) {
    if (r.location) return r.location->label();
    return r.country;
}

std::vector<std::wstring> connection_cells(const ConnectionRow& r, const std::wstring& first, bool bytes) {
    std::wstring remote = r.conn.remote_addr.empty() ? L"" : endpoint(r.conn.remote_addr, r.conn.remote_port);
    return {first, r.direction, r.conn.protocol, endpoint(r.conn.local_addr, r.conn.local_port), remote, r.site, r.owner, location_text(r), r.conn.state,
            r.received ? human_bytes((double)*r.received) : L"", r.sent ? human_bytes((double)*r.sent) : L"", rate_text(r.rate_in, bytes), rate_text(r.rate_out, bytes)};
}

void render_traffic() {
    if (!have_snapshot || !traffic.page) return;
    bool only_inbound = ui::checked(traffic.inbound), show_ports = ui::checked(traffic.ports), show_local = ui::checked(traffic.local);
    std::wstring needle = lower(ui::trimmed(traffic.filter));
    bool by_destination = ui::combo_index(traffic.group) == 1;
    bool bytes = snapshot.bytes_available;
    std::vector<std::vector<std::wstring>> rows;
    traffic.app_names.clear();
    int connections = 0, inbound_internet = 0;

    auto matches = [&](const std::vector<std::wstring>& cells) {
        if (needle.empty()) return true;
        for (const auto& c : cells) {
            if (lower(c).find(needle) != std::wstring::npos) return true;
        }
        return false;
    };

    if (!by_destination) {
        std::vector<const AppTraffic*> apps;
        for (const auto& [pid, a] : snapshot.apps) apps.push_back(&a);
        std::sort(apps.begin(), apps.end(), [](const AppTraffic* a, const AppTraffic* b) { return a->rate_in + a->rate_out + (double)(a->received + a->sent) / 1e9 > b->rate_in + b->rate_out + (double)(b->received + b->sent) / 1e9; });
        for (const AppTraffic* a : apps) {
            std::vector<std::vector<std::wstring>> children;
            bool app_match = matches({a->process.label(), a->process.name});
            for (const auto& r : a->rows) {
                if (!row_visible(r, only_inbound, show_ports, show_local)) continue;
                auto cells = connection_cells(r, L"    " + (r.site.empty() ? (r.conn.remote_addr.empty() ? endpoint(r.conn.local_addr, r.conn.local_port) : r.conn.remote_addr) : r.site), bytes);
                if (app_match || matches(cells)) children.push_back(cells);
                ++connections;
                if (r.direction == L"In" && r.remote_kind == L"Internet") ++inbound_internet;
            }
            if (children.empty()) continue;
            std::wstring name = a->process.label() + (a->process.pid > 4 ? L"  (PID " + std::to_wstring(a->process.pid) + L")" : L"");
            rows.push_back({name, std::to_wstring(a->count(L"Out")) + L" out, " + std::to_wstring(a->count(L"In")) + L" in", L"", L"", std::to_wstring(a->remote_hosts()) + L" hosts", L"", L"", L"", L"",
                            bytes ? human_bytes((double)a->received) : L"", bytes ? human_bytes((double)a->sent) : L"", rate_text(a->rate_in, bytes), rate_text(a->rate_out, bytes)});
            traffic.app_names.push_back(a->process.name);
            for (auto& c : children) {
                rows.push_back(c);
                traffic.app_names.push_back(a->process.name);
            }
        }
    } else {
        struct Dest {
            std::wstring label, owner, loc;
            std::vector<std::pair<const AppTraffic*, const ConnectionRow*>> list;
            std::uint64_t rec = 0, sent = 0;
            double rin = 0, rout = 0;
        };
        std::map<std::wstring, Dest> dests;
        for (const auto& [pid, a] : snapshot.apps) {
            for (const auto& r : a.rows) {
                if (!row_visible(r, only_inbound, show_ports, show_local) || r.conn.remote_addr.empty()) continue;
                Dest& d = dests[r.conn.remote_addr];
                if (d.label.empty()) {
                    d.label = r.site.empty() ? r.conn.remote_addr : r.site + L"  (" + r.conn.remote_addr + L")";
                    d.owner = r.owner;
                    d.loc = location_text(r);
                }
                d.list.push_back({&a, &r});
                if (r.received) d.rec += *r.received;
                if (r.sent) d.sent += *r.sent;
                d.rin += r.rate_in;
                d.rout += r.rate_out;
                ++connections;
                if (r.direction == L"In" && r.remote_kind == L"Internet") ++inbound_internet;
            }
        }
        std::vector<const Dest*> order;
        for (const auto& [k, d] : dests) order.push_back(&d);
        std::sort(order.begin(), order.end(), [](const Dest* a, const Dest* b) { return a->list.size() > b->list.size(); });
        for (const Dest* d : order) {
            std::vector<std::vector<std::wstring>> children;
            bool dest_match = matches({d->label, d->owner, d->loc});
            for (const auto& [app, r] : d->list) {
                auto cells = connection_cells(*r, L"    " + app->process.label(), bytes);
                if (dest_match || matches(cells)) children.push_back(cells);
            }
            if (children.empty()) continue;
            rows.push_back({d->label, std::to_wstring(d->list.size()) + L" connections", L"", L"", L"", L"", d->owner, d->loc, L"", bytes ? human_bytes((double)d->rec) : L"",
                            bytes ? human_bytes((double)d->sent) : L"", rate_text(d->rin, bytes), rate_text(d->rout, bytes)});
            traffic.app_names.push_back(L"");
            for (auto& c : children) {
                rows.push_back(c);
                traffic.app_names.push_back(L"");
            }
        }
    }
    ui::set_rows(traffic.list, rows);
    std::wstring text = std::to_wstring(snapshot.apps.size()) + L" applications, " + std::to_wstring(connections) + L" connections";
    if (bytes) text += L", download " + rate_text(snapshot.total_rate_in, true) + L", upload " + rate_text(snapshot.total_rate_out, true);
    else text += L" (volumes need administrator rights)";
    if (inbound_internet) text += L"   |   " + std::to_wstring(inbound_internet) + L" INBOUND from the Internet";
    if (ui::checked(traffic_pause)) text += L"  (paused)";
    traffic.page->set_summary(text);
}

void traffic_tick() {
    if (ui::checked(traffic_pause)) return;
    bool resolve = ui::checked(traffic.dns), owners = ui::checked(traffic.owner);
    ui::run_quiet([resolve, owners](const Stop&, const Progress&) {
        if (!monitor) monitor = std::make_shared<TrafficMonitor>(resolve, owners, nullptr, nullptr, geo);
        monitor->resolve_hosts = resolve;
        monitor->lookup_owners = owners;
        TrafficSnapshot snap;
        std::wstring error;
        try {
            snap = monitor->sample();
        } catch (const std::exception& e) {
            error = wide(e.what());
        }
        return [snap, error] {
            if (!error.empty()) {
                if (traffic.page) traffic.page->set_summary(L"Could not read the connection table: " + error);
                return;
            }
            snapshot = snap;
            have_snapshot = true;
            render_traffic();
            render_map();
        };
    });
}

void build_traffic() {
    ui::Page& p = ui::add_page(L"Firewall and Network", L"Live traffic");
    traffic.page = &p;
    traffic_pause = p.check(L"Pause", 70);
    p.label(L"Group by:", 70);
    traffic.group = p.combo({L"Application", L"Destination"}, 0, 130);
    p.label(L"Filter:", 50);
    traffic.filter = p.edit(L"", 0);
    p.button(L"Show only selected app", [] {
        auto rows = ui::selected_rows(traffic.list);
        if (!rows.empty() && rows[0] < (int)traffic.app_names.size() && !traffic.app_names[rows[0]].empty()) {
            SetWindowTextW(traffic.filter, traffic.app_names[rows[0]].c_str());
        }
    }, 190, false);
    p.newline();
    traffic.inbound = p.check(L"Only inbound (who connects to this PC)", 280);
    traffic.ports = p.check(L"Listening ports and UDP", 190, true);
    traffic.local = p.check(L"Connections inside this PC", 220);
    traffic.dns = p.check(L"Resolve host names", 160, true);
    traffic.owner = p.check(L"Look up owners (RDAP)", 190);
    for (HWND h : {traffic_pause, traffic.group, traffic.filter, traffic.inbound, traffic.ports, traffic.local, traffic.dns, traffic.owner}) p.on_change(h, render_traffic);
    ui::ListEvents ev;
    traffic.list = p.list({{L"Application / destination", 250}, {L"Direction", 90}, {L"Proto", 55}, {L"Local", 160}, {L"Remote", 200}, {L"Site / host", 220}, {L"Owner (who)", 220},
                           {L"Location", 160}, {L"State", 85}, {L"Received", 80, true}, {L"Sent", 80, true}, {L"Download", 85, true}, {L"Upload", 85, true}}, 4, false, ev);
    p.tick_ms = 3000;
    p.on_tick = traffic_tick;
    p.on_show = traffic_tick;
    p.on_refresh = traffic_tick;
    p.set_summary(L"Starting...");
}

// endregion

// region Route (tracert) and the world map

struct RoutePoint {
    int hop = 0;
    std::wstring address, label;
    double lat = 0, lon = 0;
};

struct MapState {
    HWND hwnd = nullptr;
    HWND label = nullptr, geo_label = nullptr, geo_button = nullptr;
    double zoom = 1, pan_x = 0, pan_y = 0;
    std::map<std::wstring, CountryTraffic> countries;
    std::map<std::wstring, PlaceTraffic> places;
    std::wstring home;
    int unlocated = 0;
    std::vector<RoutePoint> route;
    std::wstring hover;
    bool dragging = false, moved = false;
    POINT drag_from{};
    ui::Page* page = nullptr;
} map;

constexpr double LAT_TOP = 84, LAT_BOTTOM = -58;

double base_scale(const RECT& rc) { return std::min((rc.right - rc.left) / 360.0, (rc.bottom - rc.top) / (LAT_TOP - LAT_BOTTOM)); }

POINT to_screen(const RECT& rc, double lon, double lat) {
    double s = base_scale(rc) * map.zoom;
    double ox = (rc.right - rc.left - 360 * base_scale(rc)) / 2, oy = (rc.bottom - rc.top - (LAT_TOP - LAT_BOTTOM) * base_scale(rc)) / 2;
    return {(LONG)(ox + (lon + 180) * s + map.pan_x), (LONG)(oy + (LAT_TOP - lat) * s + map.pan_y)};
}

void from_screen(const RECT& rc, POINT p, double& lon, double& lat) {
    double s = base_scale(rc) * map.zoom;
    double ox = (rc.right - rc.left - 360 * base_scale(rc)) / 2, oy = (rc.bottom - rc.top - (LAT_TOP - LAT_BOTTOM) * base_scale(rc)) / 2;
    lon = (p.x - ox - map.pan_x) / s - 180;
    lat = LAT_TOP - (p.y - oy - map.pan_y) / s;
}

bool place_position(const PlaceTraffic& d, double& lon, double& lat) {
    if (d.lat && d.lon) {
        lat = *d.lat;
        lon = *d.lon;
        return true;
    }
    if (const Country* c = find_country(d.country)) {
        lat = c->lat;
        lon = c->lon;
        return true;
    }
    return false;
}

bool point_in_ring(const std::vector<std::pair<double, double>>& ring, double lon, double lat) {
    bool inside = false;
    for (std::size_t i = 0, j = ring.size() - 1; i < ring.size(); j = i++) {
        if (((ring[i].second > lat) != (ring[j].second > lat)) && (lon < (ring[j].first - ring[i].first) * (lat - ring[i].second) / (ring[j].second - ring[i].second) + ring[i].first)) inside = !inside;
    }
    return inside;
}

std::wstring country_at(double lon, double lat) {
    try {
        for (const Country& c : world().countries) {
            for (const auto& ring : c.rings) {
                if (ring.size() > 2 && point_in_ring(ring, lon, lat)) return c.code;
            }
        }
    } catch (const std::exception&) {
    }
    return L"";
}

int radius_of(int count) { return 4 + (int)(2.5 * std::sqrt((double)std::max(1, count))); }

std::wstring describe_place(const PlaceTraffic& d) {
    std::wstring text = d.label + L": " + std::to_wstring(d.outbound) + L" outbound, " + std::to_wstring(d.inbound) + L" inbound";
    if (!d.apps.empty()) {
        text += L"\nApplications: ";
        int n = 0;
        for (const auto& a : d.apps) text += (n++ ? L", " : L"") + a;
    }
    if (!d.hosts.empty()) {
        text += L"\nSites: ";
        int n = 0;
        for (const auto& h : d.hosts) {
            if (n++ >= 8) break;
            text += (n > 1 ? L", " : L"") + h;
        }
    }
    if (!d.addresses.empty()) {
        text += L"\nAddresses: ";
        int n = 0;
        for (const auto& a : d.addresses) {
            if (n++ >= 8) break;
            text += (n > 1 ? L", " : L"") + a;
        }
    }
    if (d.rate_in || d.rate_out) text += L"\nNow: download " + human_bytes(d.rate_in) + L"/s, upload " + human_bytes(d.rate_out) + L"/s";
    return text;
}

std::wstring describe_country(const std::wstring& code) {
    const Country* c = find_country(code);
    std::wstring text = c ? c->name + L" (" + code + L")" : code;
    auto it = map.countries.find(code);
    if (it == map.countries.end()) return text + L": no connection";
    const CountryTraffic& d = it->second;
    text += L": " + std::to_wstring(d.outbound) + L" outbound, " + std::to_wstring(d.inbound) + L" inbound";
    if (!d.apps.empty()) {
        text += L"\nApplications: ";
        int n = 0;
        for (const auto& a : d.apps) text += (n++ ? L", " : L"") + a;
    }
    return text;
}

const PlaceTraffic* place_at(const RECT& rc, POINT p) {
    const PlaceTraffic* best = nullptr;
    double best_d = 1e9;
    for (const auto& [k, d] : map.places) {
        double lon, lat;
        if (!place_position(d, lon, lat)) continue;
        POINT s = to_screen(rc, lon, lat);
        double dist = std::hypot((double)(s.x - p.x), (double)(s.y - p.y));
        if (dist <= radius_of(d.connections()) + 3 && dist < best_d) {
            best = &d;
            best_d = dist;
        }
    }
    return best;
}

void paint_map(HDC dc, const RECT& rc) {
    HBRUSH sea = CreateSolidBrush(RGB(214, 230, 245));
    FillRect(dc, &rc, sea);
    DeleteObject(sea);
    SetBkMode(dc, TRANSPARENT);
    HPEN border = CreatePen(PS_SOLID, 1, RGB(170, 170, 165));
    HGDIOBJ old_pen = SelectObject(dc, border);
    HBRUSH land = CreateSolidBrush(RGB(236, 234, 226)), out_brush = CreateSolidBrush(RGB(255, 205, 140)), in_brush = CreateSolidBrush(RGB(240, 150, 150)), home_brush = CreateSolidBrush(RGB(190, 226, 190));
    try {
        for (const Country& c : world().countries) {
            auto it = map.countries.find(c.code);
            HBRUSH b = c.code == map.home ? home_brush : land;
            if (it != map.countries.end()) b = it->second.inbound ? in_brush : (it->second.outbound ? out_brush : b);
            HGDIOBJ old_brush = SelectObject(dc, b);
            for (const auto& ring : c.rings) {
                if (ring.size() < 3) continue;
                std::vector<POINT> pts;
                pts.reserve(ring.size());
                for (const auto& [lon, lat] : ring) pts.push_back(to_screen(rc, lon, lat));
                Polygon(dc, pts.data(), (int)pts.size());
            }
            SelectObject(dc, old_brush);
        }
    } catch (const std::exception&) {
        SetTextColor(dc, RGB(160, 0, 0));
        TextOutW(dc, 10, 30, L"The world map data is missing.", 30);
    }
    DeleteObject(land);
    DeleteObject(out_brush);
    DeleteObject(in_brush);
    DeleteObject(home_brush);
    SelectObject(dc, old_pen);
    DeleteObject(border);

    double hlon = 0, hlat = 0;
    bool have_home = false;
    if (const Country* hc = find_country(map.home)) {
        hlon = hc->lon;
        hlat = hc->lat;
        have_home = true;
    }
    // links from home to each place
    if (have_home) {
        POINT a = to_screen(rc, hlon, hlat);
        for (const auto& [k, d] : map.places) {
            double lon, lat;
            if (!place_position(d, lon, lat) || !d.outbound) continue;
            POINT b = to_screen(rc, lon, lat);
            int width = 1 + (int)std::min(4.0, std::log2((double)d.outbound + 1) / 2);
            HPEN pen = CreatePen(PS_SOLID, width, RGB(220, 110, 20));
            HGDIOBJ prev = SelectObject(dc, pen);
            std::vector<POINT> curve;
            double dist = std::hypot((double)(b.x - a.x), (double)(b.y - a.y));
            for (int i = 0; i <= 20; ++i) {
                double t = i / 20.0;
                double cx = (a.x + b.x) / 2.0, cy = (a.y + b.y) / 2.0 - dist * 0.25;
                curve.push_back({(LONG)((1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * cx + t * t * b.x), (LONG)((1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * cy + t * t * b.y)});
            }
            Polyline(dc, curve.data(), (int)curve.size());
            SelectObject(dc, prev);
            DeleteObject(pen);
        }
    }
    // markers and labels of the busiest places
    std::vector<const PlaceTraffic*> order;
    for (const auto& [k, d] : map.places) order.push_back(&d);
    std::sort(order.begin(), order.end(), [](const PlaceTraffic* a, const PlaceTraffic* b) { return a->connections() > b->connections(); });
    int labelled = 0;
    for (const PlaceTraffic* d : order) {
        double lon, lat;
        if (!place_position(*d, lon, lat)) continue;
        POINT s = to_screen(rc, lon, lat);
        int r = radius_of(d->connections());
        HBRUSH b = CreateSolidBrush(d->inbound ? RGB(210, 40, 40) : RGB(235, 120, 20));
        HGDIOBJ prev = SelectObject(dc, b);
        HPEN white = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
        HGDIOBJ prev_pen = SelectObject(dc, white);
        Ellipse(dc, s.x - r, s.y - r, s.x + r, s.y + r);
        SelectObject(dc, prev_pen);
        DeleteObject(white);
        SelectObject(dc, prev);
        DeleteObject(b);
        if (labelled++ < 14) {
            SetTextColor(dc, RGB(40, 40, 40));
            std::wstring text = d->label;
            TextOutW(dc, s.x + r + 3, s.y - 7, text.c_str(), (int)text.size());
        }
    }
    // the traced route
    for (std::size_t i = 0; i < map.route.size(); ++i) {
        POINT s = to_screen(rc, map.route[i].lon, map.route[i].lat);
        HBRUSH b = CreateSolidBrush(RGB(40, 90, 200));
        HGDIOBJ prev = SelectObject(dc, b);
        Ellipse(dc, s.x - 5, s.y - 5, s.x + 5, s.y + 5);
        SelectObject(dc, prev);
        DeleteObject(b);
        SetTextColor(dc, RGB(30, 60, 160));
        std::wstring n = std::to_wstring(map.route[i].hop);
        TextOutW(dc, s.x + 6, s.y - 14, n.c_str(), (int)n.size());
        if (i) {
            POINT a = to_screen(rc, map.route[i - 1].lon, map.route[i - 1].lat);
            HPEN pen = CreatePen(PS_DOT, 1, RGB(40, 90, 200));
            HGDIOBJ prev_pen = SelectObject(dc, pen);
            MoveToEx(dc, a.x, a.y, nullptr);
            LineTo(dc, s.x, s.y);
            SelectObject(dc, prev_pen);
            DeleteObject(pen);
        }
    }
    // legend and hover text
    SetTextColor(dc, RGB(60, 60, 60));
    const wchar_t* legend = L"orange: outbound   red: inbound   green: your country   wheel: zoom   drag: move   double-click: whole world";
    TextOutW(dc, 8, 6, legend, (int)wcslen(legend));
    if (!map.hover.empty()) {
        RECT box = {8, rc.bottom - 110, std::min<LONG>(rc.right - 8, 620), rc.bottom - 8};
        HBRUSH white = CreateSolidBrush(RGB(255, 255, 240));
        FillRect(dc, &box, white);
        DeleteObject(white);
        FrameRect(dc, &box, (HBRUSH)GetStockObject(GRAY_BRUSH));
        RECT text_box = {box.left + 6, box.top + 4, box.right - 6, box.bottom - 4};
        SetTextColor(dc, RGB(20, 20, 20));
        DrawTextW(dc, map.hover.c_str(), -1, &text_box, DT_WORDBREAK | DT_NOPREFIX);
    }
}

void choose_and_open_lookup(const PlaceTraffic& d) {
    std::vector<std::pair<std::wstring, std::wstring>> items;   // (label, url)
    for (const auto& h : valid_hosts(std::vector<std::wstring>(d.hosts.begin(), d.hosts.end()))) items.push_back({L"Look up " + h + L" on VirusTotal", reputation_url(h)});
    for (const auto& a : public_addresses(std::vector<std::wstring>(d.addresses.begin(), d.addresses.end()))) items.push_back({L"Look up " + a + L" on VirusTotal", reputation_url(a)});
    if (items.empty()) {
        ui::info(L"No public address or site name is known for this place yet.");
        return;
    }
    std::size_t pick = 0;
    if (items.size() > 1) {
        ui::DialogSpec spec;
        spec.title = L"VirusTotal";
        spec.prompt = L"What do you want to look up? (opened in your browser; the site itself is not contacted)";
        spec.body = ui::DialogSpec::List;
        spec.columns = {{L"Look up", 520}};
        for (const auto& i : items) spec.rows.push_back({i.first});
        spec.buttons = {{L"Open", 1}, {L"Cancel", 0}};
        spec.width = 600;
        spec.height = 400;
        auto r = ui::run_dialog(spec);
        if (r.button != 1 || r.row < 0) return;
        pick = (std::size_t)r.row;
    }
    ui::open_url(items[pick].second);
}

void trace_route(const std::wstring& address) {
    std::vector<std::wstring> argv;
    try {
        argv = build_trace_command(address);
    } catch (const std::exception& e) {
        ui::warn(wide(e.what()));
        return;
    }
    ui::run_async(L"Tracing the route to " + address + L" (up to a minute or two)...", [argv, address](const Stop& stop, const Progress& progress) {
        std::vector<Hop> hops;
        ProcOptions o;
        o.timeout_ms = 240000;
        o.stop = stop;
        o.on_line = [&](const std::wstring& line) {
            Hop h;
            if (parse_hop(line, h)) {
                hops.push_back(h);
                progress(L"Route to " + address + L": hop " + std::to_wstring(h.number));
            }
        };
        run_process(argv, o);
        std::vector<RoutePoint> points;
        std::vector<std::vector<std::wstring>> rows;
        for (const auto& h : hops) {
            std::wstring where;
            if (!h.address.empty()) {
                auto loc = geo->locate(h.address);
                if (loc) {
                    where = loc->label();
                    points.push_back({h.number, h.address, where, loc->lat, loc->lon});
                }
            }
            rows.push_back({std::to_wstring(h.number), h.address.empty() ? L"(no answer)" : h.address, h.summary(), where});
        }
        return [rows, points, address] {
            map.route = points;
            if (map.hwnd) InvalidateRect(map.hwnd, nullptr, FALSE);
            ui::DialogSpec spec;
            spec.title = L"Route to " + address;
            spec.prompt = std::to_wstring(rows.size()) + L" hops. The ones the location database knows are drawn on the world map.";
            spec.body = ui::DialogSpec::List;
            spec.columns = {{L"Hop", 50}, {L"Address", 200}, {L"Times", 230}, {L"Location", 220}};
            spec.rows = rows;
            spec.buttons = {{L"Close", 0}, {L"Clear the map", -2}};
            spec.action = [](HWND, int, HWND) {
                map.route.clear();
                if (map.hwnd) InvalidateRect(map.hwnd, nullptr, FALSE);
            };
            ui::run_dialog(spec);
        };
    });
}

void choose_and_trace(const PlaceTraffic& d) {
    auto addrs = public_addresses(std::vector<std::wstring>(d.addresses.begin(), d.addresses.end()));
    if (addrs.empty()) {
        ui::info(L"No public address is known for this place yet.");
        return;
    }
    if (addrs.size() == 1) {
        trace_route(addrs[0]);
        return;
    }
    ui::DialogSpec spec;
    spec.title = L"Trace the route";
    spec.prompt = L"Which address?";
    spec.body = ui::DialogSpec::List;
    spec.columns = {{L"Address", 360}};
    for (const auto& a : addrs) spec.rows.push_back({a});
    spec.buttons = {{L"Trace", 1}, {L"Cancel", 0}};
    spec.width = 460;
    spec.height = 380;
    auto r = ui::run_dialog(spec);
    if (r.button == 1 && r.row >= 0) trace_route(addrs[(std::size_t)r.row]);
}

LRESULT CALLBACK map_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            HDC mem = CreateCompatibleDC(dc);
            HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
            HGDIOBJ old = SelectObject(mem, bmp);
            SelectObject(mem, ui::font());
            paint_map(mem, rc);
            BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_MOUSEWHEEL: {
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            ScreenToClient(hwnd, &p);
            RECT rc;
            GetClientRect(hwnd, &rc);
            double lon, lat;
            from_screen(rc, p, lon, lat);
            double factor = GET_WHEEL_DELTA_WPARAM(wp) > 0 ? 1.25 : 0.8;
            map.zoom = std::max(1.0, std::min(40.0, map.zoom * factor));
            POINT after = to_screen(rc, lon, lat);   // keep the point under the cursor where it was
            map.pan_x += p.x - after.x;
            map.pan_y += p.y - after.y;
            if (map.zoom == 1.0) map.pan_x = map.pan_y = 0;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_LBUTTONDOWN:
            SetCapture(hwnd);
            map.dragging = true;
            map.moved = false;
            map.drag_from = {GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            return 0;
        case WM_MOUSEMOVE: {
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            RECT rc;
            GetClientRect(hwnd, &rc);
            if (map.dragging && (wp & MK_LBUTTON)) {
                int dx = p.x - map.drag_from.x, dy = p.y - map.drag_from.y;
                if (map.moved || std::abs(dx) + std::abs(dy) > 4) {
                    map.moved = true;
                    map.pan_x += dx;
                    map.pan_y += dy;
                    map.drag_from = p;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            std::wstring text;
            if (const PlaceTraffic* d = place_at(rc, p)) {
                text = describe_place(*d) + L"\nClick: details.  Double-click: look it up on VirusTotal.  Shift+click: trace the route.";
            } else {
                double lon, lat;
                from_screen(rc, p, lon, lat);
                std::wstring code = country_at(lon, lat);
                if (!code.empty() && (map.countries.count(code) || code == map.home)) text = describe_country(code);
            }
            if (text != map.hover) {
                map.hover = text;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_LBUTTONUP: {
            if (!map.dragging) return 0;
            map.dragging = false;
            ReleaseCapture();
            if (map.moved) return 0;
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            RECT rc;
            GetClientRect(hwnd, &rc);
            if (const PlaceTraffic* d = place_at(rc, p)) {
                if (GetKeyState(VK_SHIFT) & 0x8000) choose_and_trace(*d);
                else ui::show_text(d->label, describe_place(*d), 640, 360);
            } else {
                double lon, lat;
                from_screen(rc, p, lon, lat);
                std::wstring code = country_at(lon, lat);
                if (!code.empty() && map.countries.count(code)) ui::show_text(code, describe_country(code), 640, 300);
            }
            return 0;
        }
        case WM_LBUTTONDBLCLK: {
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            RECT rc;
            GetClientRect(hwnd, &rc);
            if (const PlaceTraffic* d = place_at(rc, p)) {
                choose_and_open_lookup(*d);
            } else {
                map.zoom = 1;
                map.pan_x = map.pan_y = 0;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void refresh_geoip_label() {
    auto info = geo->info();
    std::wstring text;
    if (is_file(geo->path()) && !info.empty()) {
        text = L"Server locations: DB-IP City Lite " + (info.count(L"month") ? info[L"month"] : std::wstring(L"?")) + L" (city level). " + DBIP_ATTRIBUTION + L".";
        if (needs_update(info)) {
            text += L" A newer monthly edition is available.";
            SetWindowTextW(map.geo_button, L"Update DB-IP City Lite (60 MB)");
        } else {
            SetWindowTextW(map.geo_button, L"Re-download DB-IP City Lite");
        }
    } else {
        text = L"Server locations: registration country only (the owner's country, often not where the server is). Download the free DB-IP City Lite database to place servers in their real city.";
    }
    SetWindowTextW(map.geo_label, text.c_str());
}

void download_geoip() {
    if (!ui::confirm(L"Download the DB-IP 'IP to City Lite' database (about 60 MB, about 130 MB once unpacked) from download.db-ip.com?\n\n"
                     L"It is free (Creative Commons Attribution 4.0) and updated every month. Lookups then happen on this PC: no address is sent anywhere.", L"DB-IP City Lite"))
        return;
    ui::run_async(L"Downloading DB-IP City Lite...", [](const Stop& stop, const Progress& progress) {
        std::wstring error, month;
        geo->suspend();   // Windows refuses to replace a file that is memory-mapped
        try {
            auto info = download_dbip(L"", [progress](std::uint64_t n) { progress(L"Downloading DB-IP City Lite... " + std::to_wstring(n / (1024 * 1024)) + L" MB unpacked"); }, nullptr, stop);
            month = info.count(L"month") ? info[L"month"] : L"";
        } catch (const std::exception& e) {
            error = wide(e.what());
        }
        geo->resume();
        return [error, month] {
            if (!error.empty()) ui::warn(L"The database could not be downloaded:\n" + error);
            else ui::set_status(L"DB-IP City Lite " + month + L" installed.");
            geo->close();
            refresh_geoip_label();
        };
    });
}

void render_map() {
    if (!have_snapshot || !map.page) return;
    int unlocated = 0;
    map.countries = by_country(snapshot, &unlocated);
    map.places = by_place(snapshot);
    map.unlocated = unlocated;
    if (map.home.empty()) map.home = home_country();
    int outbound = 0;
    std::vector<const CountryTraffic*> dest;
    std::wstring inbound_from;
    for (const auto& [code, d] : map.countries) {
        outbound += d.outbound;
        if (d.outbound) dest.push_back(&d);
        if (d.inbound) inbound_from += (inbound_from.empty() ? L"" : L", ") + code;
    }
    std::sort(dest.begin(), dest.end(), [](const CountryTraffic* a, const CountryTraffic* b) { return a->outbound > b->outbound; });
    std::wstring text = std::to_wstring(outbound) + L" outbound Internet connection(s) to " + std::to_wstring(dest.size()) + L" country(ies)";
    for (std::size_t i = 0; i < dest.size() && i < 5; ++i) text += (i ? L", " : L": ") + dest[i]->code + L" " + std::to_wstring(dest[i]->outbound);
    if (!inbound_from.empty()) text += L"   |   INBOUND from: " + inbound_from;
    if (unlocated) text += L"   |   " + std::to_wstring(unlocated) + L" not placed yet";
    map.page->set_summary(text);
    if (map.hwnd) InvalidateRect(map.hwnd, nullptr, FALSE);
}

void build_map() {
    ui::Page& p = ui::add_page(L"Firewall and Network", L"World map");
    map.page = &p;
    map.geo_label = p.label(L"", ui::FILL);
    map.geo_button = p.button(L"Download DB-IP City Lite (60 MB)", download_geoip, 260);
    p.newline();
    p.label(L"Hover a city, a country or a link for its traffic. Click: details. Double-click a city: VirusTotal. Shift+click a city: trace the route. Wheel: zoom, drag: move.", ui::FILL);
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = map_proc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.style = CS_DBLCLKS;
        wc.lpszClassName = L"DDCleanerWorldMap";
        RegisterClassExW(&wc);
        registered = true;
    }
    map.hwnd = p.custom(L"DDCleanerWorldMap", 1, 0, WS_EX_CLIENTEDGE);
    p.tick_ms = 3000;
    p.on_tick = traffic_tick;
    p.on_show = [] {
        refresh_geoip_label();
        traffic_tick();
        InvalidateRect(map.hwnd, nullptr, FALSE);
    };
    p.on_refresh = traffic_tick;
    p.set_summary(L"Waiting for traffic...");
}

// endregion

// region Firewall and network reports (one analysis feeds both pages)

struct FwPage {
    ui::Page* page = nullptr;
    HWND profiles = nullptr, findings = nullptr, details = nullptr, log = nullptr, log_toggle = nullptr;
} fwp;

struct NetPage {
    ui::Page* page = nullptr;
    HWND items = nullptr, details = nullptr, listeners = nullptr, hide = nullptr;
} netp;

std::wstring join_details(const std::vector<std::wstring>& lines) {
    std::wstring text;
    for (const auto& l : lines) text += l + L"\n";
    return text;
}

void populate_listeners() {
    std::vector<std::vector<std::wstring>> rows;
    bool hide = ui::checked(netp.hide);
    for (const auto& row : net.listeners) {
        const Listener& l = row.listener;
        if (hide && (row.exposure.level == L"local" || row.exposure.level == L"blocked" || l.loopback())) continue;
        std::wstring services;
        for (const auto& s : l.services) services += (services.empty() ? L"" : L", ") + s;
        rows.push_back({l.protocol, l.address, std::to_wstring(l.port), l.process, std::to_wstring(l.pid), services, row.exposure.level + L": " + row.exposure.text, row.exposure.rule});
    }
    ui::set_rows(netp.listeners, rows);
}

void populate_reports() {
    std::vector<std::vector<std::wstring>> rows;
    for (int i = 0; i < 3; ++i) {
        auto it = fw.profiles.find(PROFILE_NAMES[i]);
        if (it == fw.profiles.end()) continue;
        const ProfileState& s = it->second;
        rows.push_back({s.name, fw.active.count(s.name) ? L"yes" : L"", s.enabled ? L"On" : L"OFF", s.inbound, s.outbound, s.log_blocked ? L"yes" : L"no"});
    }
    ui::set_rows(fwp.profiles, rows);
    rows.clear();
    for (const auto& f : fw.findings) rows.push_back({status_label(f.status), f.title});
    ui::set_rows(fwp.findings, rows);
    rows.clear();
    if (fw.has_log) {
        rows.push_back({L"Dropped packets in the log: " + std::to_wstring(fw.log.dropped()) + L"  (" + fw.log.first + L" to " + fw.log.last + L")", L""});
        auto section = [&](const wchar_t* title, const CounterMap& counter, bool ports) {
            auto top = most_common(counter, 8);
            if (top.empty()) return;
            rows.push_back({std::wstring(L"▸ ") + title, L""});
            for (const auto& [k, n] : top) rows.push_back({L"    " + (ports ? describe_port(k) : k), std::to_wstring(n)});
        };
        section(L"Inbound sources", fw.log.inbound_sources, false);
        section(L"Inbound ports", fw.log.inbound_ports, true);
        section(L"Outbound targets", fw.log.outbound_targets, false);
        section(L"Processes", fw.log.processes, false);
    } else {
        rows.push_back({fw.log_enabled ? L"Logging is on but no packet was dropped yet." : L"Dropped-packet logging is off: nothing is recorded.", L""});
    }
    ui::set_rows(fwp.log, rows);
    SetWindowTextW(fwp.log_toggle, fw.log_enabled ? L"Disable dropped-packet logging" : L"Enable dropped-packet logging");
    EnableWindow(fwp.log_toggle, TRUE);
    std::wstring stats;
    for (const auto& [k, n] : fw.stats) stats += (stats.empty() ? L"" : L", ") + k + L": " + std::to_wstring(n);
    rows.clear();
    for (const auto& i : net.items) rows.push_back({status_label(i.status), i.category, i.title});
    ui::set_rows(netp.items, rows);
    populate_listeners();
    int critical = 0, warnings = 0;
    for (const auto& f : fw.findings) {
        critical += f.status == Status::Critical;
        warnings += f.status == Status::Warning;
    }
    for (const auto& i : net.items) {
        critical += i.status == Status::Critical;
        warnings += i.status == Status::Warning;
    }
    std::wstring summary = std::to_wstring(critical) + L" critical, " + std::to_wstring(warnings) + L" warning(s). Rules: " + stats;
    fwp.page->set_summary(summary);
    netp.page->set_summary(summary);
}

void run_analysis() {
    ui::run_async(L"Analyzing the firewall and the network...", [](const Stop&, const Progress& progress) {
        FirewallReport f = run_firewall_analysis(progress);
        NetworkReport n = run_network_analysis(&f, progress);
        return [f, n] {
            fw = f;
            net = n;
            analyzed = true;
            if (!n.error.empty()) ui::warn(L"The network analysis reported a problem:\n" + n.error);
            populate_reports();
            ui::set_status(L"Analysis done.");
        };
    });
}

void toggle_logging() {
    if (!ui::elevated()) {
        ui::warn(L"Changing the firewall log needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    bool enable = !fw.log_enabled;
    if (!ui::confirm(enable ? L"Turn dropped-packet logging ON?\n\nWindows Firewall then writes every blocked packet to its log file (pfirewall.log). This only records, it blocks nothing new."
                            : L"Turn dropped-packet logging OFF?", L"Firewall log"))
        return;
    ui::run_async(L"Changing the firewall log...", [enable](const Stop&, const Progress&) {
        auto result = set_dropped_packet_logging(enable);
        return [result, enable] {
            if (!result.first) ui::warn(L"The change failed:\n" + result.second);
            else {
                fw.log_enabled = enable;
                ui::info(result.second.empty() ? L"Done. Run the analysis again to see the log." : result.second);
            }
            populate_reports();
        };
    });
}

void show_finding() {
    auto rows = ui::selected_rows(fwp.findings);
    if (rows.empty() || rows[0] >= (int)fw.findings.size()) return;
    const Finding& f = fw.findings[rows[0]];
    ui::set_text(fwp.details, f.title + L"\n\n" + join_details(f.details));
}

void show_net_item() {
    auto rows = ui::selected_rows(netp.items);
    if (rows.empty() || rows[0] >= (int)net.items.size()) return;
    const NetItem& i = net.items[rows[0]];
    ui::set_text(netp.details, i.title + L"\n\n" + join_details(i.details));
}

void build_firewall() {
    ui::Page& p = ui::add_page(L"Firewall and Network", L"Firewall");
    fwp.page = &p;
    p.button(L"Analyze firewall and network", run_analysis, 230);
    p.button(L"Open Windows Firewall (advanced)", [] {
        ShellExecuteW(ui::main_window(), L"open", sys_exe(L"mmc.exe").c_str(), L"wf.msc", nullptr, SW_SHOWNORMAL);
    }, 250, false);
    fwp.log_toggle = p.button(L"Enable dropped-packet logging", toggle_logging, 250);
    EnableWindow(fwp.log_toggle, FALSE);
    fwp.profiles = p.list({{L"Profile", 110}, {L"In use", 80}, {L"Firewall", 90}, {L"Inbound default", 130}, {L"Outbound default", 140}, {L"Log dropped packets", 150}}, 1);
    ui::ListEvents ev;
    ev.on_select = show_finding;
    fwp.findings = p.list({{L"Status", 110}, {L"Finding", 900}}, 3, false, ev);
    fwp.details = p.text(2);
    fwp.log = p.list({{L"Blocked traffic (firewall log)", 620}, {L"Count", 90, true}}, 3);
    p.on_refresh = run_analysis;
    p.set_summary(L"Reads the firewall rules, profiles and log, and the network. Nothing is blocked or changed (except the log switch, on request).");
}

void build_network() {
    ui::Page& p = ui::add_page(L"Firewall and Network", L"Network");
    netp.page = &p;
    p.button(L"Analyze firewall and network", run_analysis, 230);
    netp.hide = p.check(L"Hide loopback-only and blocked ports", 300, true);
    p.on_change(netp.hide, populate_listeners);
    ui::ListEvents ev;
    ev.on_select = show_net_item;
    netp.items = p.list({{L"Status", 110}, {L"Category", 130}, {L"Finding", 800}}, 3, false, ev);
    netp.details = p.text(2);
    netp.listeners = p.list({{L"Protocol", 70}, {L"Address", 170}, {L"Port", 60, true}, {L"Process", 150}, {L"PID", 60, true}, {L"Services", 170}, {L"Reachable", 330}, {L"Firewall rule", 250}}, 4);
    p.on_refresh = run_analysis;
    p.set_summary(L"Adapters, errors, TCP/UDP counters and the listening ports with the exposure the firewall gives them.");
}

// endregion

}  // namespace

void build_network_pages() {
    build_traffic();
    build_map();
    build_firewall();
    build_network();
}
