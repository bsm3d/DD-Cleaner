// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests firewall rule parsing, port exposure, findings, the blocked traffic log and the network evaluators.

#include <cstdio>

#include <windows.h>

#include <ddcore/network.hpp>

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

static std::wstring same(const std::wstring& t) { return t; }

static FirewallRule rule(const std::wstring& value, const std::wstring& id = L"{ID}") {
    FirewallRule r;
    bool ok = parse_rule(id, value, r, L"Local", same);
    CHECK(ok);
    return r;
}

static void test_rule_parsing() {
    FirewallRule r = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=80|LPort2_10=443|"
                          L"RA4=10.0.0.0/255.0.0.0|RA6=fe80::/64|App=C:\\Program Files\\X\\.\\app.exe|Svc=*|Name=Web server|Edge=TRUE|");
    CHECK(r.action == L"Allow" && r.direction == L"In" && r.active && r.protocol == L"6" && r.edge);
    CHECK(r.profiles.size() == 2 && r.profiles.count(L"Public") && r.profiles.count(L"Private") && !r.profiles.count(L"Domain"));
    CHECK((r.local_ports == std::vector<std::wstring>{L"80", L"443"}));
    CHECK(r.remote_addresses.size() == 2 && !r.any_remote() && r.scope() == L"10.0.0.0/255.0.0.0, fe80::/64");
    CHECK(r.app == L"c:\\program files\\x\\app.exe");   // normalised and lower-case
    CHECK(r.service == L"*" && r.name == L"Web server");
    CHECK(r.applies_to_profile(L"Public") && !r.applies_to_profile(L"Domain"));

    FirewallRule open = rule(L"v2.30|Action=Block|Active=FALSE|Dir=Out|Name=@firewallapi.dll,-1|");
    CHECK(!open.active && open.profiles.empty() && open.any_remote() && open.applies_to_profile(L"Domain") && open.scope() == L"any address");
    CHECK(open.is_windows_component());   // the name starts with @
    FirewallRule special = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|IFType=Lan|AppPkgId=S-1-15-2|");
    CHECK(special.interface_limited && special.package == L"S-1-15-2" && special.local_scope_limited());

    FirewallRule none;
    CHECK(!parse_rule(L"x", L"v2.30|Active=TRUE|", none));   // no action and no direction: not a rule
    CHECK(!parse_rule(L"x", L"", none));
    FirewallRule system_rule = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=System|");
    CHECK(system_rule.app == L"system" && system_rule.is_windows_component());
    FirewallRule windows_app = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=%SystemRoot%\\system32\\svchost.exe|");
    CHECK(windows_app.is_windows_component());
}

static void test_ports() {
    CHECK(port_matches({}, 1234));
    CHECK(port_matches({L"80"}, 80) && !port_matches({L"80"}, 81));
    CHECK(port_matches({L"1000-2000"}, 1500) && !port_matches({L"1000-2000"}, 2001));
    CHECK(port_matches({L"22, 3389"}, 3389));
    CHECK(port_matches({L"*"}, 5) && port_matches({L"Any"}, 5));
    CHECK(port_matches({L"RPC-EPMap"}, 135) && !port_matches({L"RPC-EPMap"}, 136));
    CHECK(port_matches({L"RPC"}, 50000) && !port_matches({L"RPC"}, 1000));
    CHECK(!port_matches({L"abc", L"10-x"}, 10));   // garbage never matches (and never throws)
}

static std::map<std::wstring, ProfileState> profiles(bool domain = true, bool pub = true, const wchar_t* inbound = L"Block") {
    return {{L"Domain", {L"Domain", domain, inbound, L"Allow", false, L""}},
            {L"Private", {L"Private", true, inbound, L"Allow", false, L""}},
            {L"Public", {L"Public", pub, inbound, L"Allow", true, L"C:\\log.txt"}}};
}

static void test_exposure() {
    Listener web{L"TCP", L"0.0.0.0", 8080, 100, L"web", L"C:\\Tools\\web.exe", {}};
    Listener local{L"TCP", L"127.0.0.1", 8080, 100, L"web", L"", {}};
    FirewallRule allow_any = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name=Web any|");
    FirewallRule allow_lan = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|RA4=LocalSubnet|Name=Web lan|");
    FirewallRule block = rule(L"v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name=Web block|");
    FirewallRule other_port = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9090|Name=Other|");
    FirewallRule disabled = rule(L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=8080|Name=Off|");
    FirewallRule other_app = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\\Tools\\another.exe|Name=Another app|");
    FirewallRule right_app = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=c:\\tools\\WEB.exe|Name=Right app|RA4=1.2.3.4|");
    std::set<std::wstring> active = {L"Private"};

    CHECK(evaluate_exposure(local, {allow_any}, profiles(), active).level == L"local");
    CHECK(evaluate_exposure(web, {}, profiles(), active).level == L"blocked");               // blocked by default
    CHECK(evaluate_exposure(web, {allow_any}, profiles(), active).level == L"open");
    CHECK(evaluate_exposure(web, {allow_any}, profiles(), active).rule == L"Web any");
    CHECK(evaluate_exposure(web, {allow_lan}, profiles(), active).level == L"limited");
    CHECK(evaluate_exposure(web, {allow_lan, allow_any}, profiles(), active).rule == L"Web any");   // the widest allow wins
    CHECK(evaluate_exposure(web, {allow_any, block}, profiles(), active).level == L"blocked");        // a block rule beats an allow
    CHECK(evaluate_exposure(web, {other_port, disabled, other_app}, profiles(), active).level == L"blocked");
    CHECK(evaluate_exposure(web, {right_app}, profiles(), active).level == L"limited");              // matched by the program path
    CHECK(evaluate_exposure(web, {}, profiles(true, true, L"Allow"), active).level == L"open");      // default inbound = Allow
    auto off = profiles();
    off[L"Private"].enabled = false;
    CHECK(evaluate_exposure(web, {}, off, active).text == L"Open: firewall is off (Private)");
    // the most open active profile counts
    FirewallRule public_only = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Profile=Public|Protocol=6|LPort=8080|Name=Public rule|");
    CHECK(evaluate_exposure(web, {public_only}, profiles(), {L"Private", L"Public"}).level == L"open");
    CHECK(evaluate_exposure(web, {public_only}, profiles(), {L"Private"}).level == L"blocked");
    Listener sys{L"TCP", L"0.0.0.0", 445, 4, L"System", L"", {}};
    FirewallRule smb = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=SMB|");
    CHECK(evaluate_exposure(sys, {smb}, profiles(), active).level == L"open");
    CHECK(evaluate_exposure(web, {smb}, profiles(), active).level == L"blocked");                   // "system" only applies to PID 4
    Listener svc{L"TCP", L"0.0.0.0", 5040, 900, L"svchost", L"", {L"CDPSvc"}};
    FirewallRule by_service = rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Svc=cdpsvc|Name=Svc rule|");
    CHECK(evaluate_exposure(svc, {by_service}, profiles(), active).level == L"open");
}

static void test_findings() {
    auto none_exist = [](const std::wstring&) { return false; };
    auto findings = evaluate_firewall({}, {}, {L"Public"}, none_exist);
    CHECK(findings.size() == 1 && findings[0].status == Status::Warning);

    auto good = evaluate_firewall({}, profiles(), {L"Public"}, none_exist);
    CHECK(good.size() == 1 && good[0].status == Status::Ok);

    auto bad = evaluate_firewall({}, profiles(false, true), {L"Domain"}, none_exist);
    CHECK(!bad.empty() && bad[0].status == Status::Critical && bad[0].title == L"Firewall is OFF for the Domain profile (in use now)");
    auto allowing = evaluate_firewall({}, profiles(true, true, L"Allow"), {L"Public"}, none_exist);
    CHECK(allowing[0].status == Status::Critical && allowing[0].title.find(L"allows inbound connections by default") != std::wstring::npos);

    std::vector<FirewallRule> rules = {
        rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Name=Everything|"),
        rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Tools\\a.exe|Name=Public program|"),
        rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|Profile=Private|App=C:\\Tools\\b.exe|Name=Private program|"),
        rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Tools\\c.exe|Edge=TRUE|RA4=LocalSubnet|Name=Edge program|"),
        rule(L"v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Users\\me\\gone.exe|RA4=1.1.1.1|Name=Orphan writable|"),
        rule(L"v2.30|Action=Block|Active=TRUE|Dir=Out|App=C:\\Program Files\\Old\\old.exe|Name=Orphan protected|"),
    };
    auto drive_ok = [](const std::wstring& p) { return p == L"c:\\"; };   // only the C: drive is there, no program file exists
    auto found = evaluate_firewall(rules, profiles(), {L"Public"}, drive_ok);
    auto title_has = [&](Status s, const wchar_t* part) {
        for (const auto& f : found) {
            if (f.status == s && f.title.find(part) != std::wstring::npos) return true;
        }
        return false;
    };
    CHECK(title_has(Status::Critical, L"1 rule(s) allow any inbound traffic"));
    CHECK(title_has(Status::Warning, L"program rule(s) accept connections on public networks"));
    CHECK(title_has(Status::Info, L"edge traversal"));
    CHECK(title_has(Status::Warning, L"missing programs in folders any user can write to"));   // an allow rule: warning
    CHECK(title_has(Status::Info, L"programs that were uninstalled"));
    int public_count = 0;
    for (const auto& f : found) {
        if (f.title.find(L"accept connections on public networks") != std::wstring::npos) public_count = (int)f.details.size() - 1;
    }
    CHECK(public_count == 1);   // only a.exe: the others are private-only, limited to a subnet or an address, or already reported
    auto stats = rule_statistics(rules);
    CHECK(stats[L"total"] == 6 && stats[L"enabled"] == 6 && stats[L"inbound_allow"] == 5 && stats[L"outbound_block"] == 1);
    CHECK(is_protected_path(L"C:\\Windows\\System32\\x.exe") && !is_protected_path(L"C:\\Users\\me\\x.exe"));
}

static void test_log() {
    LogStats stats;
    parse_log_lines({L"#Version: 1.5", L"#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid",
                     L"2026-11-20 10:00:00 DROP TCP 1.2.3.4 10.0.0.2 5000 445 60 S 1 0 8192 - - - RECEIVE 4",
                     L"2026-11-20 10:00:01 DROP TCP 1.2.3.4 10.0.0.2 5001 445 60 S 1 0 8192 - - - RECEIVE 4",
                     L"2026-11-21 09:00:00 DROP UDP 5.6.7.8 10.0.0.2 5353 5353 60 - - - - - - - RECEIVE -",
                     L"2026-11-21 09:00:05 DROP TCP 10.0.0.2 9.9.9.9 4000 443 60 S 1 0 8192 - - - SEND 1234",
                     L"2026-11-21 09:00:06 ALLOW TCP 10.0.0.2 9.9.9.9 4001 443 60 S 1 0 8192 - - - SEND 1234",
                     L"too short", L""},
                    stats);
    CHECK(stats.lines == 5 && stats.first == L"2026-11-20 10:00:00" && stats.last == L"2026-11-21 09:00:06");
    CHECK(stats.dropped() == 4);
    auto drop_in = std::make_pair(std::wstring(L"DROP"), std::wstring(L"RECEIVE")), allow_out = std::make_pair(std::wstring(L"ALLOW"), std::wstring(L"SEND"));
    CHECK(stats.by_action[drop_in] == 3 && stats.by_action[allow_out] == 1);
    CHECK(stats.inbound_sources[L"1.2.3.4"] == 2 && stats.inbound_ports[L"TCP 445"] == 2 && stats.inbound_ports[L"UDP 5353"] == 1);
    CHECK(stats.outbound_targets[L"9.9.9.9 TCP 443"] == 1);
    CHECK(stats.per_day[L"2026-11-20"] == 2 && stats.per_day[L"2026-11-21"] == 2);
    CHECK(stats.processes[L"4"] == 2 && stats.processes[L"1234"] == 1 && stats.processes.count(L"-") == 0);
    auto top = most_common(stats.inbound_ports, 1);
    CHECK(top.size() == 1 && top[0].first == L"TCP 445");
    CHECK(describe_port(L"TCP 445") == L"TCP 445 (SMB file sharing)" && describe_port(L"TCP 9999") == L"TCP 9999");

    std::wstring dir = temp_dir() + L"\\ddcore_fwlog_" + std::to_wstring(GetCurrentProcessId());
    make_dirs(dir);
    std::wstring path = join(dir, L"pfirewall.log");
    LogStats missing;
    CHECK(!read_log(path, missing) && missing.files.empty());
    write_file(path + L".old", "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\r\n"
                               "2026-11-19 08:00:00 DROP TCP 7.7.7.7 10.0.0.2 1 3389 60 S 1 0 1 - - - RECEIVE\r\n");
    write_file(path, "2026-11-21 08:00:00 DROP TCP 8.8.8.8 10.0.0.2 1 22 60 S 1 0 1 - - - RECEIVE\r\n");
    LogStats both;
    CHECK(read_log(path, both) && both.files.size() == 2 && both.lines == 2 && both.first == L"2026-11-19 08:00:00");
    CHECK(both.inbound_ports[L"TCP 3389"] == 1 && both.inbound_ports[L"TCP 22"] == 1);
    delete_file(path + L".old");
    delete_file(path);
    RemoveDirectoryW(dir.c_str());
}

static void test_network_evaluators() {
    CHECK(human_bytes(512) == L"512 B" && human_bytes(2048) == L"2.0 KB" && human_bytes(5.0 * 1024 * 1024 * 1024) == L"5.0 GB");
    auto adapters = parse_json(LR"J([
        {"Name":"Ethernet","Description":"Realtek","Status":"Up","LinkSpeed":"100 Mbps","Virtual":false,"ReceivedBytes":2048,"SentBytes":1024,
         "ReceivedPackets":1000,"SentPackets":1000,"ReceivedErrors":10,"SentErrors":0,"ReceivedDiscards":50,"SentDiscards":0,
         "IPv4":["192.168.1.10/24"],"Gateway":["192.168.1.1"],"DNS":["1.1.1.1","8.8.8.8"]},
        {"Name":"Wi-Fi","Description":"Intel","Status":"Disconnected","LinkSpeed":"0 bps"},
        {"Name":"vEthernet","Description":"Hyper-V","Status":"Up","LinkSpeed":"10 Gbps","Virtual":true,"ReceivedPackets":0,"SentPackets":0,
         "IPv4":"172.20.0.1/20"}])J")
                        .as_list();
    auto items = evaluate_adapters(adapters);
    CHECK(items.size() == 2);   // the disconnected adapter is left out
    CHECK(items[0].status == Status::Warning && items[0].title == L"Ethernet: 100 Mbps");   // 1 % discards >= 1 and error rate 0.5 % >= 0.1
    bool has_errors = false, has_low_speed = false, has_dns = false;
    for (const auto& d : items[0].details) {
        has_errors |= d.find(L"Packet errors: 10 (0.500 %)") == 0;
        has_low_speed |= d.find(L"Low link speed") == 0;
        has_dns |= d == L"DNS servers: 1.1.1.1, 8.8.8.8";
    }
    CHECK(has_errors && has_low_speed && has_dns);
    CHECK(items[1].status == Status::Ok && items[1].details.back() == L"No errors, no discarded packets" && items[1].details[2] == L"IPv4: 172.20.0.1/20");

    Counters c;
    c[L"tcp"] = {{L"OutSegs", 1000}, {L"RetransSegs", 30}, {L"ActiveOpens", 200}, {L"AttemptFails", 10}, {L"EstabResets", 3}, {L"InErrs", 1}};
    c[L"udp"] = {{L"InDatagrams", 500}, {L"InErrors", 10}, {L"NoPorts", 7}};
    auto states = parse_json(LR"J([{"State":"Established","Count":12},{"State":"Listen","Count":30},{"State":"TimeWait","Count":4}])J").as_list();
    auto protocols = evaluate_protocols(c, states);
    CHECK(protocols.size() == 3);
    CHECK(protocols[0].status == Status::Warning && protocols[0].title == L"TCP retransmissions: 3.00 %");   // 2 % <= 3 % < 5 %
    CHECK(protocols[0].details[2] == L"Outgoing connection attempts: 200, failed: 10 (5.0 %)");
    CHECK(protocols[1].status == Status::Warning && protocols[1].title == L"UDP: 500 datagrams received, 10 with errors");
    CHECK(protocols[2].title == L"TCP connections: 12 established, 30 listening" && protocols[2].details[0] == L"Listen: 30");
    c[L"tcp"][L"RetransSegs"] = 60;
    CHECK(evaluate_protocols(c, {})[0].status == Status::Critical);
    CHECK(evaluate_protocols({}, {}).empty());

    auto listeners = parse_listeners(parse_json(LR"J([
        {"Protocol":"TCP","Address":"0.0.0.0","Port":445,"Pid":4,"Owner":{"Name":"","Path":"","Services":[]}},
        {"Protocol":"TCP","Address":"0.0.0.0","Port":445,"Pid":4,"Owner":{"Name":"","Path":"","Services":[]}},
        {"Protocol":"UDP","Address":"127.0.0.1","Port":53,"Pid":10,"Owner":{"Name":"dns","Path":"C:\\dns.exe","Services":["Dnscache"]}},
        {"Protocol":"TCP","Address":"192.168.1.10","Port":80,"Pid":11,"Owner":{"Name":"web","Path":"","Services":"W3SVC"}}])J").as_list());
    CHECK(listeners.size() == 3);   // the duplicate is dropped
    CHECK(listeners[0].port == 80 && listeners[1].port == 445 && listeners[1].process == L"System" && listeners[2].loopback());   // non-loopback first
    CHECK(listeners[0].services.size() == 1 && listeners[0].services[0] == L"W3SVC");

    auto networks = parse_json(LR"J([{"Interface":"Ethernet","Category":"Private"},{"Interface":"Wi-Fi","Category":"DomainAuthenticated"}])J").as_list();
    auto by_address = address_profiles(adapters, networks);
    CHECK(by_address.size() == 1 && by_address[L"192.168.1.10"] == L"Private");
    Listener on_eth{L"TCP", L"192.168.1.10", 80, 1, L"", L"", {}}, wildcard{L"TCP", L"0.0.0.0", 80, 1, L"", L"", {}};
    std::set<std::wstring> both = {L"Public", L"Private"}, only_private = {L"Private"};
    CHECK(listener_profiles(on_eth, by_address, both) == only_private);
    CHECK(listener_profiles(wildcard, by_address, both).size() == 2);
    std::set<std::wstring> priv_domain = {L"Private", L"Domain"}, only_public = {L"Public"};
    CHECK(active_profiles(networks) == priv_domain);
    CHECK(active_profiles({}) == only_public);
}

static void test_profile_parsing() {
    Json data = parse_json(LR"J({"profiles":[
        {"Name":"Domain","Enabled":"True","DefaultInboundAction":"NotConfigured","DefaultOutboundAction":"","LogBlocked":"False","LogFileName":""},
        {"Name":"Public","Enabled":"False","DefaultInboundAction":"Allow","DefaultOutboundAction":"Block","LogBlocked":"True","LogFileName":"C:\\x\\fw.log"},
        {"Name":"Bogus","Enabled":"True"}],
        "networks":{"Interface":"Ethernet","Category":"Public"}})J");
    std::map<std::wstring, ProfileState> p;
    std::vector<Json> nets;
    parse_profiles(data, p, nets);
    CHECK(p.size() == 2 && p[L"Domain"].enabled && p[L"Domain"].inbound == L"Block" && p[L"Domain"].outbound == L"Allow");   // Windows defaults
    CHECK(p[L"Domain"].log_file.find(L"pfirewall.log") != std::wstring::npos && p[L"Domain"].log_file.find(L"%") == std::wstring::npos);
    CHECK(!p[L"Public"].enabled && p[L"Public"].inbound == L"Allow" && p[L"Public"].log_blocked && p[L"Public"].log_file == L"C:\\x\\fw.log");
    CHECK(nets.size() == 1);   // a single object is a list of one
}

static void test_real_machine() {
    auto rules = read_rules();
    FirewallReport fw = run_firewall_analysis();
    CHECK(!rules.empty() && !fw.profiles.empty());
    NetworkReport net = run_network_analysis(&fw);
    CHECK(net.error.empty() && !net.items.empty());
    std::size_t open = 0;
    for (const auto& r : net.listeners) open += r.exposure.level == L"open";
    std::printf("  machine: %zu rules, %zu profiles, active %zu, %zu findings, log %s, %zu listeners (%zu open), %zu network items\n", rules.size(),
                fw.profiles.size(), fw.active.size(), fw.findings.size(), fw.has_log ? "read" : "none", net.listeners.size(), open, net.items.size());
}

int run_firewall_tests() {
    test_rule_parsing();
    test_ports();
    test_exposure();
    test_findings();
    test_log();
    test_network_evaluators();
    test_profile_parsing();
    test_real_machine();
    std::printf("firewall/network: %d checks, %d failed\n", checks, failures);
    return failures;
}
