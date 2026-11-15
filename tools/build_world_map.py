"""
Builds ddcleaner/data/world_countries.json from Natural Earth 1:110m admin-0 countries (public domain):
https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson

Usage: python tools/build_world_map.py path/to/ne_110m_admin_0_countries.geojson
Keeps ISO code, names, label point and outer rings rounded to 0.1 degree.
"""

import json
import os
import sys

# Countries too small for the 1:110m map but common as server locations: (name, lon, lat)
SMALL = {
    "SG": ("Singapore", 103.8, 1.35), "HK": ("Hong Kong", 114.2, 22.3), "LU": ("Luxembourg", 6.1, 49.8),
    "MT": ("Malta", 14.4, 35.9), "MC": ("Monaco", 7.4, 43.7), "LI": ("Liechtenstein", 9.55, 47.15),
    "AD": ("Andorra", 1.5, 42.5), "SM": ("San Marino", 12.45, 43.95), "BH": ("Bahrain", 50.55, 26.05),
    "MU": ("Mauritius", 57.55, -20.3), "MO": ("Macao", 113.55, 22.2), "GI": ("Gibraltar", -5.35, 36.14),
    "IM": ("Isle of Man", -4.55, 54.2), "JE": ("Jersey", -2.13, 49.21), "GG": ("Guernsey", -2.58, 49.45),
    "BM": ("Bermuda", -64.75, 32.3), "KY": ("Cayman Islands", -81.25, 19.3), "VG": ("British Virgin Islands", -64.6, 18.4),
    "SC": ("Seychelles", 55.45, -4.65), "BB": ("Barbados", -59.55, 13.15), "MV": ("Maldives", 73.5, 4.2),
    "CW": ("Curacao", -68.95, 12.2), "BZ": ("Belize", -88.7, 17.2), "PS": ("Palestine", 35.2, 31.9),
}


def ring(coords):
    out = []
    for lon, lat in coords:
        p = [round(lon, 1), round(lat, 1)]
        if not out or out[-1] != p:
            out.append(p)
    return out if len(out) >= 3 else None


def main(src: str):
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    countries = []
    for feat in data["features"]:
        p = feat["properties"]
        code = p.get("ISO_A2_EH") if p.get("ISO_A2_EH", "-99") != "-99" else p.get("ISO_A2")
        code = "" if code in (None, "-99") else code
        geom = feat["geometry"]
        polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        rings = [r for r in (ring(poly[0]) for poly in polys) if r]
        names = sorted({n for n in (p.get("NAME"), p.get("ADMIN"), p.get("NAME_LONG"), p.get("FORMAL_EN"),
                                    p.get("NAME_EN")) if n})
        countries.append({"code": code, "name": p.get("NAME"), "names": names, "iso3": p.get("ISO_A3"),
                          "label": [round(p["LABEL_X"], 2), round(p["LABEL_Y"], 2)], "rings": rings})
    existing = {c["code"] for c in countries}
    for code, (name, lon, lat) in SMALL.items():
        if code not in existing:
            countries.append({"code": code, "name": name, "names": [name], "iso3": "", "label": [lon, lat],
                              "rings": []})
    out = {"source": "Natural Earth 1:110m admin-0 countries (public domain), simplified", "countries": countries}
    dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ddcleaner", "data",
                        "world_countries.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"), ensure_ascii=False)
    print(f"{len(countries)} countries -> {dest} ({os.path.getsize(dest) // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1])
