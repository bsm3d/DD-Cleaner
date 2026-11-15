"""
Who is behind an address: RDAP answers of the different registries, per-network cache, bootstrap choice
of registry, DNS cache names. No network access: fetches are faked.
"""

import pytest

from ddcleaner import ipinfo

ARIN = {
    "name": "AP-2440", "startAddress": "160.79.104.0", "endAddress": "160.79.111.255",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"], ["fn", {}, "text", "Anthropic, PBC"], ["kind", {}, "text", "org"],
        ["adr", {"label": "548 Market St.\nSan Francisco\nCA\n94104\nUnited States"}, "text",
         ["", "", "", "", "", "", ""]]]],
        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]}]}],
    "remarks": [{"description": ["-----BEGIN CERTIFICATE-----xyz"]}],
}
RIPE = {
    "name": "OVH", "country": "FR", "startAddress": "213.186.33.0", "endAddress": "213.186.33.255",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "OVH-MNT"],
                                                                     ["kind", {}, "text", "individual"]]]}],
    "remarks": [{"description": ["OVH SAS", "Dedicated servers"]}],
}
BOOT4 = {"services": [[["160.0.0.0/8"], ["http://insecure.example/", "https://rdap.arin.net/registry/"]],
                      [["213.0.0.0/8"], ["https://rdap.db.ripe.net/"]]]}


def test_parse_arin_organization_and_country():
    owner = ipinfo.parse_rdap(ARIN, "rdap.arin.net")
    assert (owner.organization, owner.country, owner.network) == ("Anthropic, PBC", "US", "AP-2440")
    assert owner.label == "Anthropic, PBC (US)" and owner.range == "160.79.104.0 - 160.79.111.255"


def test_parse_ripe_uses_remarks_not_maintainer():
    owner = ipinfo.parse_rdap(RIPE)
    assert owner.label == "OVH SAS Dedicated servers (FR)"


def test_parse_minimal_answer_falls_back_to_network_name():
    assert ipinfo.parse_rdap({"name": "NET-X"}).label == "NET-X"


class FakeFetch:
    def __init__(self):
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        if url == ipinfo.BOOTSTRAP[4]:
            return BOOT4, url
        if url.startswith("https://rdap.arin.net/registry/ip/"):
            return ARIN, url
        if url.startswith("https://rdap.db.ripe.net/ip/"):
            return RIPE, url
        raise OSError("unreachable")


def test_lookup_uses_bootstrap_https_registry_and_caches_the_block():
    fetch = FakeFetch()
    lookup = ipinfo.OwnerLookup(fetch=fetch)
    try:
        assert lookup.resolve_now("160.79.104.10").label == "Anthropic, PBC (US)"
        assert lookup.resolve_now("160.79.111.200").organization == "Anthropic, PBC"  # same block: no new query
        assert lookup.resolve_now("213.186.33.3").country == "FR"
        assert fetch.urls == [ipinfo.BOOTSTRAP[4], "https://rdap.arin.net/registry/ip/160.79.104.10",
                              "https://rdap.db.ripe.net/ip/213.186.33.3"]
    finally:
        lookup.shutdown()


@pytest.mark.parametrize("addr", ["192.168.1.1", "10.0.0.5", "127.0.0.1", "fe80::1", "not an ip"])
def test_private_addresses_are_never_sent(addr):
    fetch = FakeFetch()
    lookup = ipinfo.OwnerLookup(fetch=fetch)
    try:
        assert lookup.resolve_now(addr) is None and lookup.lookup(addr) is None
        assert fetch.urls == []
    finally:
        lookup.shutdown()


def test_failures_are_not_retried_immediately_and_disabled_sends_nothing():
    fetch = FakeFetch()
    lookup = ipinfo.OwnerLookup(fetch=fetch)
    try:
        assert lookup.resolve_now("8.8.8.8") is None  # no registry in the fake bootstrap
        lookup.lookup("8.8.8.8")
        assert fetch.urls.count(ipinfo.BOOTSTRAP[4]) == 1 and len(fetch.urls) == 1
        lookup.enabled = False
        assert lookup.resolve_now("160.79.104.10") is None and len(fetch.urls) == 1
    finally:
        lookup.shutdown()


def test_fetch_refuses_plain_http():
    with pytest.raises(ValueError):
        ipinfo._fetch_json("http://rdap.example/ip/1.2.3.4")


def test_dns_names_accumulate_and_ignore_other_records():
    batches = [[{"Entry": "api.anthropic.com", "Data": "160.79.104.10"}, {"Entry": "x", "Data": ""}],
               [{"Entry": "claude.ai.", "Data": "160.79.104.10"}]]
    dns = ipinfo.DnsNames(reader=lambda: batches.pop(0))
    dns.refresh(force=True)
    dns.refresh(force=True)
    assert dns.names("160.79.104.10") == ["api.anthropic.com", "claude.ai"]  # kept after leaving the cache
    assert dns.names("1.2.3.4") == []


def test_local_tables_are_readable():
    assert isinstance(ipinfo.arp_table(), dict)
    assert all(g.count(".") == 3 for g in ipinfo.default_gateways())
