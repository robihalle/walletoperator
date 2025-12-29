import re
import time
import gzip
import html
from statistics import median

import requests
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

import maxminddb
import os
import sqlite3
import uuid
import hashlib
import json
import base64
import hmac
from eth_account.messages import encode_defunct
from eth_account import Account
import secrets
from datetime import datetime
from fastapi import Form, UploadFile, File
from fastapi.responses import FileResponse, RedirectResponse

AUTH_SERVER_ALL = "http://49.13.145.234:9230/tor/server/all"
CONSENSUS_MICRODESC = "http://49.13.145.234:9230/tor/status-vote/current/consensus-microdesc"

GEOIP_COUNTRY_DB = "/opt/walletoperator/geoip/GeoLite2-Country.mmdb"

PRIMARY = "#0280AF"
SECONDARY = "#03BDC5"
GRADIENT = f"linear-gradient(90deg, {PRIMARY}, {SECONDARY})"

ANYONE_LOGO_URL = "https://cdn.prod.website-files.com/64940c3f30cff496b018e020/667aeae9fd9a4c3efab1874c_anyone-logo-512x.png"
MONA_SANS_WOFF2 = "https://cdn.jsdelivr.net/gh/github/mona-sans@main/fonts/webfonts/Mona-Sans.woff2"

WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
ANYONE_DOMAIN_RE = re.compile(r"^(?=.{1,128}$)[a-z0-9-]+(?:\.[a-z0-9-]+)*\.anyone$", re.IGNORECASE)

CONTACT_LINE_RE = re.compile(r"^contact\b.*$", re.MULTILINE)
ROUTER_LINE_RE = re.compile(r"^router\s+(\S+)\s+(\S+)\s+(\d+)\s+\d+\s+\d+\s*$", re.MULTILINE)

BANDWIDTH_RE = re.compile(r"\bBandwidth=(\d+)\b")
UPTIME_RE = re.compile(r"^uptime\s+(\d+)\s*$", re.MULTILINE)

app = FastAPI(title="Anyone Wallet Operator Lookup")

_CACHE_TTL_ALL = 30
_cache_all_text = None
_cache_all_ts = 0.0

_geoip_reader = None
_geoip_reader_failed = False

# ---------------------------
# Anyone Domains (.anyone)
# ---------------------------
ANYONE_DOMAINS_API = "https://api.ec.anyone.tech/anyone-domains"

_CACHE_TTL_DOMAINS = 3600  # 1h
_cache_domains_json = None
_cache_domains_ts = 0.0


def normalize_wallet(w: str):
    m = WALLET_RE.search((w or "").strip())
    return m.group(0).lower() if m else None


def normalize_anyone_domain(d: str):
    d = (d or "").strip().lower()
    return d if ANYONE_DOMAIN_RE.match(d) else None


def fetch_anyone_domains_json():
    global _cache_domains_json, _cache_domains_ts
    now = time.time()
    if _cache_domains_json is not None and (now - _cache_domains_ts) < _CACHE_TTL_DOMAINS:
        return _cache_domains_json

    r = requests.get(ANYONE_DOMAINS_API, timeout=30, headers={"User-Agent": "walletoperator/1.0"})
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        data = []

    _cache_domains_json = data
    _cache_domains_ts = now
    return data


def get_anyone_domains_for_owner(owner_wallet: str) -> list[str]:
    ow = (owner_wallet or "").lower()
    if not ow:
        return []

    data = fetch_anyone_domains_json()
    names = []
    for item in data:
        if not isinstance(item, dict):
            continue
        owner = (item.get("owner") or "").lower()
        name = item.get("name")
        tld = (item.get("tld") or "").lower()
        if owner == ow and isinstance(name, str) and name and tld == "anyone":
            names.append(name)

    return sorted(set(names), key=lambda s: (len(s), s.lower()))


def resolve_wallet_or_domain(q: str):
    """
    Accepts either 0x.. wallet or *.anyone domain.
    Returns (wallet_lower, queried_domain_or_none).
    """
    w = normalize_wallet(q)
    if w:
        return (w, None)

    dom = normalize_anyone_domain(q)
    if not dom:
        return (None, None)

    # Lookup owner from cached domains list
    try:
        data = fetch_anyone_domains_json()
    except Exception:
        return (None, dom)

    dom_l = dom.lower()
    for item in data:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").lower()
        owner = item.get("owner")
        tld = (item.get("tld") or "").lower()
        if tld == "anyone" and name == dom_l and isinstance(owner, str) and owner.lower().startswith("0x") and len(owner) == 42:
            return (owner.lower(), dom)
    return (None, dom)

def fetch_server_all() -> str:
    global _cache_all_text, _cache_all_ts
    now = time.time()
    if _cache_all_text is not None and (now - _cache_all_ts) < _CACHE_TTL_ALL:
        return _cache_all_text

    r = requests.get(AUTH_SERVER_ALL, timeout=30)
    r.raise_for_status()
    _cache_all_text = r.text
    _cache_all_ts = now
    return _cache_all_text


def _maybe_decompress(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        try:
            return gzip.decompress(raw)
        except OSError:
            return raw
    return raw


def fetch_consensus_text() -> str:
    r = requests.get(
        CONSENSUS_MICRODESC,
        timeout=30,
        headers={"Accept-Encoding": "identity", "User-Agent": "walletoperator/1.0"},
        allow_redirects=True,
    )
    r.raise_for_status()
    raw = _maybe_decompress(r.content)
    return raw.decode("utf-8", errors="replace")


def split_descriptor_blocks(raw: str):
    parts = raw.split("\nrouter ")
    return ["router " + p for p in parts[1:]]

def wallet_from_descriptor_block(block: str):
    m = CONTACT_LINE_RE.search(block)
    if not m:
        return None
    w = WALLET_RE.search(m.group(0))
    return w.group(0).lower() if w else None


def parse_router_line_from_descriptor(block: str):
    m = ROUTER_LINE_RE.search(block)
    if not m:
        return None
    return {"nickname": m.group(1), "ip": m.group(2), "orport": int(m.group(3))}


def uptime_from_descriptor_block(block: str):
    m = UPTIME_RE.search(block)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _init_geoip():
    global _geoip_reader, _geoip_reader_failed
    if _geoip_reader is not None or _geoip_reader_failed:
        return
    try:
        _geoip_reader = maxminddb.open_database(GEOIP_COUNTRY_DB)
    except Exception:
        _geoip_reader_failed = True
        _geoip_reader = None


def geoip_country_info(ip: str) -> dict | None:
    """
    Returns {"name": "Netherlands", "iso": "NL"} if possible.
    """
    _init_geoip()
    if _geoip_reader is None:
        return None
    try:
        rec = _geoip_reader.get(ip)
        if not isinstance(rec, dict):
            return None

        c = rec.get("country") or {}
        rc = rec.get("registered_country") or {}

        names = (c.get("names") or {})
        rnames = (rc.get("names") or {})

        name = names.get("en") or rnames.get("en")
        iso = c.get("iso_code") or rc.get("iso_code")

        if not name and not iso:
            return None
        return {"name": str(name) if name else None, "iso": str(iso) if iso else None}
    except Exception:
        return None


def geoip_country_name(ip: str) -> str | None:
    gi = geoip_country_info(ip)
    if not gi:
        return None
    return gi.get("name") or gi.get("iso")


def country_flag_emoji(iso2: str | None) -> str:
    if not iso2 or not isinstance(iso2, str):
        return "🏳️"
    iso2 = iso2.strip().upper()
    if len(iso2) != 2 or not iso2.isalpha():
        return "🏳️"
    base = 127397
    return chr(base + ord(iso2[0])) + chr(base + ord(iso2[1]))

def fmt_duration(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _fmt_int(n):
    if n is None:
        return "—"
    try:
        return f"{int(n):,}".replace(",", " ")
    except Exception:
        return str(n)


def _fmt_pct(x: float | None) -> str:
    if x is None:
        return "—"
    try:
        return f"{x:.2f}%"
    except Exception:
        return "—"


def wants_json(request: Request, format: str | None) -> bool:
    if (format or "").lower() == "json":
        return True
    accept = (request.headers.get("accept") or "").lower()
    return "application/json" in accept


def _score_consensus_choice(entry: dict) -> tuple:
    flags = set(entry.get("flags") or [])
    rv = int(("Running" in flags) and ("Valid" in flags))
    bw = entry.get("bandwidth")
    bwv = int(bw) if isinstance(bw, int) else -1
    return (rv, bwv)


def build_consensus_ip_index(cons_text: str):
    best_by_ip = {}
    stats = {"r": 0, "s": 0, "w_with_bw": 0}
    cur = None

    def commit(c):
        if not c:
            return
        ip = c.get("ip")
        if not ip:
            return
        prev = best_by_ip.get(ip)
        if prev is None or _score_consensus_choice(c) > _score_consensus_choice(prev):
            best_by_ip[ip] = dict(c)

    for raw_line in cons_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("r "):
            commit(cur)
            stats["r"] += 1
            parts = line.split()
            if len(parts) < 8:
                cur = None
                continue

            nick = parts[1]
            if len(parts) >= 9:
                ip = parts[6]; op = parts[7]; dp = parts[8]
            else:
                ip = parts[5]; op = parts[6]; dp = parts[7]

            try:
                cur = {
                    "consensus_nickname": nick,
                    "ip": ip,
                    "orport": int(op),
                    "dirport": int(dp),
                    "flags": [],
                    "bandwidth": None,
                }
            except ValueError:
                cur = None
            continue

        if cur is None:
            continue

        if line.startswith("s "):
            stats["s"] += 1
            cur["flags"] = line.split()[1:]
            continue

        if line.startswith("w "):
            m = BANDWIDTH_RE.search(line)
            if m:
                stats["w_with_bw"] += 1
                cur["bandwidth"] = int(m.group(1))
            continue

    commit(cur)
    return best_by_ip, stats

def assess_operator(
    consensus_pct: float | None,
    in_consensus_ips: int,
    unique_ips: int,
    exit_ips: int,
    total_bw: int,
    exit_bw: int,
    median_uptime_s: int | None,
    flag_counts: dict,
    top_country: str | None,
    top_country_share_pct: float | None,
) -> tuple[str, str, str]:
    if consensus_pct is None:
        return ("Unknown", "Not enough data to assess this operator yet.", "warn")

    if consensus_pct < 50.0:
        return (
            "High risk",
            "Less than 50% of this wallet’s relay IPs are currently in consensus. That usually indicates downtime, instability, or stale infrastructure. From a staker perspective, this is a red flag.",
            "bad",
        )

    health_points = 0

    if consensus_pct >= 90:
        health_points += 3
    elif consensus_pct >= 75:
        health_points += 2
    else:
        health_points += 1

    if median_uptime_s is not None:
        if median_uptime_s >= 14 * 86400:
            health_points += 3
        elif median_uptime_s >= 7 * 86400:
            health_points += 2
        elif median_uptime_s >= 2 * 86400:
            health_points += 1

    running = int(flag_counts.get("Running", 0))
    valid = int(flag_counts.get("Valid", 0))
    stable = int(flag_counts.get("Stable", 0))
    fast = int(flag_counts.get("Fast", 0))

    rv_ratio = (min(running, valid) / unique_ips) if unique_ips else 0.0
    if rv_ratio >= 0.9:
        health_points += 2
    elif rv_ratio >= 0.75:
        health_points += 1

    if stable > 0:
        health_points += 1
    if fast > 0:
        health_points += 1

    if exit_ips >= 10:
        health_points += 2
    elif exit_ips >= 1:
        health_points += 1

    if total_bw >= 100000:
        health_points += 2
    elif total_bw >= 30000:
        health_points += 1

    concentration_note = ""
    if top_country and top_country_share_pct is not None:
        if top_country_share_pct >= 80:
            health_points -= 2
            concentration_note = f" Note: heavy country concentration ({top_country_share_pct:.1f}% in {top_country}) increases correlated outage risk."
        elif top_country_share_pct >= 70:
            health_points -= 1
            concentration_note = f" Note: country concentration ({top_country_share_pct:.1f}% in {top_country}) increases correlated outage risk."

    if health_points >= 11:
        label = "Strong contributor"
        css = "ok"
        msg = "This operator looks like a valuable part of the Anyone network: high consensus presence, good uptime, and meaningful bandwidth contribution. Staking on this wallet appears low-risk and utility-positive."
    elif health_points >= 7:
        label = "Solid operator"
        css = "ok"
        msg = "This operator appears reasonably stable and present in consensus. The wallet contributes usable capacity, and staking here looks generally sensible—keep an eye on trends and uptime."
    else:
        label = "Mixed signals"
        css = "warn"
        msg = "This operator is in consensus (above 50%), but the signals are mixed (uptime/bandwidth/flags). Staking might still be fine, but it’s worth monitoring stability over time."

    facts = []
    facts.append(f"{in_consensus_ips}/{unique_ips} IPs in consensus ({consensus_pct:.2f}%).")
    if median_uptime_s is not None:
        facts.append(f"Median descriptor uptime: {fmt_duration(median_uptime_s)}.")
    facts.append(f"Total bandwidth (IP-sum): {_fmt_int(total_bw)}.")
    facts.append(f"Exit bandwidth (IP-sum): {_fmt_int(exit_bw)} across {exit_ips} Exit IPs.")
    if top_country and top_country_share_pct is not None:
        facts.append(f"Top country: {top_country} ({top_country_share_pct:.1f}%).")

    return (label, (msg + concentration_note + " " + " ".join(facts)).strip(), css)

def _nav(active: str = "home") -> str:
    def a(label: str, href: str, key: str, soon: bool = False) -> str:
        cls = "active" if key == active else ""
        if soon:
            cls = (cls + " soon").strip()
            return f"<a class='{cls}' href='{href}' onclick='return false;' title='Coming soon'>{html.escape(label)}</a>"
        return f"<a class='{cls}' href='{href}'>{html.escape(label)}</a>"

    return (
        "<nav class='nav'>"
        + a("Start", "/", "home")
        + a("Wallet Lookup", "/lookup", "lookup")
        + a("Network Overview", "/network", "network")
        + a("Operator Profile", "/operator", "operator")
        + "</nav>"
    )


def render_page(title: str, body_html: str, active: str = "home") -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    @font-face {{
      font-family: "Mona-Sans";
      src: url("{MONA_SANS_WOFF2}") format("woff2");
      font-weight: 200 900;
      font-style: normal;
      font-display: swap;
    }}
    :root {{
      --primary: {PRIMARY};
      --secondary: {SECONDARY};
      --gradient: {GRADIENT};
      --bg: #F6F9FC;
      --card: #FFFFFF;
      --text: #0B1220;
      --muted: rgba(11, 18, 32, 0.62);
      --border: rgba(2, 128, 175, 0.16);
      --shadow: 0 10px 30px rgba(11,18,32,0.10);
      --radius: 18px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: "Mona-Sans", ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(900px 450px at 20% 10%, rgba(3,189,197,0.18), transparent 60%),
        radial-gradient(800px 400px at 85% 15%, rgba(2,128,175,0.18), transparent 55%),
        var(--bg);
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 22px 16px 56px; }}
    .topbar {{
      display:flex; align-items:center; justify-content:space-between; gap:14px;
      padding: 14px 16px;
      background: rgba(255,255,255,0.75);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
      flex-wrap: wrap;
    }}
    .brand {{ display:flex; align-items:center; gap: 12px; min-width: 0; }}
    .logo {{
      width: 40px; height: 40px; border-radius: 12px;
      background: #ffffff;
      border: 1px solid rgba(11,18,32,0.12);
      display:flex; align-items:center; justify-content:center;
      overflow:hidden; flex: 0 0 auto;
    }}
    .logo img {{ width: 40px; height: 40px; object-fit: contain; background: transparent; }}
    .brandtext .name {{ font-weight: 900; font-size: 15px; line-height: 1.1; }}
    .brandtext .tag {{ color: var(--muted); font-size: 12.5px; margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 68vw; }}
    .nav {{ display:flex; align-items:center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; flex: 1 1 auto; }}
    .nav a {{
      text-decoration: none; font-weight: 900; font-size: 13px;
      padding: 8px 10px; border-radius: 999px;
      border: 1px solid rgba(11,18,32,0.12);
      background: rgba(255,255,255,0.70); color: var(--text);
    }}
    .nav a.active {{ border: 0; background: var(--gradient); color: white; box-shadow: 0 10px 25px rgba(2,128,175,0.20); }}
    .nav a.soon {{ opacity: 0.6; cursor: not-allowed; }}

    .hero {{ margin-top: 16px; padding: 22px 18px; border-radius: var(--radius); border: 1px solid var(--border); background: rgba(255,255,255,0.80); box-shadow: var(--shadow); backdrop-filter: blur(10px); }}
    .hero h1 {{ margin: 0 0 8px; font-size: 22px; letter-spacing: -0.2px; }}
    .hero p {{ margin: 0; color: var(--muted); line-height: 1.45; }}

    .card {{ margin-top: 14px; padding: 16px; border-radius: var(--radius); border: 1px solid var(--border); background: rgba(255,255,255,0.82); box-shadow: var(--shadow); backdrop-filter: blur(10px); }}
    .panel-ok {{ border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.08); }}
    .panel-warn {{ border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.09); }}
    .panel-bad {{ border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.09); }}

    .muted {{ color: var(--muted); }}
    .mono {{ font-family: var(--mono); }}

    .form {{ display:flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }}
    input[type="text"], .input {{
      flex: 1 1 420px; min-width: 260px;
      padding: 12px 12px; border-radius: 12px;
      border: 1px solid rgba(11,18,32,0.14);
      background: rgba(255,255,255,0.92);
      font-family: var(--mono); font-size: 13px;
    }}
    button, .btn {{
      padding: 12px 14px; border-radius: 12px; border: 0;
      background: var(--gradient); color: white; font-weight: 900;
      cursor: pointer; box-shadow: 0 10px 25px rgba(2,128,175,0.20);
      text-decoration: none; display:inline-flex; align-items:center; justify-content:center;
    }}
    .btn.secondary {{ background: rgba(255,255,255,0.70); color: var(--text); border: 1px solid rgba(11,18,32,0.12); box-shadow: none; }}
    button:active, .btn:active {{ transform: translateY(1px); }}

    .stats {{ margin-top: 12px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
    @media (max-width: 900px) {{ .stats {{ grid-template-columns: 1fr 1fr; }} }}
    @media (max-width: 560px) {{ .stats {{ grid-template-columns: 1fr; }} }}
    .stat {{ padding: 12px; border-radius: 14px; border: 1px solid rgba(11,18,32,0.10); background: rgba(255,255,255,0.88); }}
    .stat .k {{ font-size: 12px; color: rgba(11,18,32,0.62); margin-bottom: 6px; }}
    .stat .v {{ font-size: 18px; font-weight: 950; letter-spacing: -0.2px; }}

    .tablewrap {{ margin-top: 14px; overflow: auto; border-radius: 16px; border: 1px solid rgba(11,18,32,0.10); background: rgba(255,255,255,0.86); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 12px 12px; border-bottom: 1px solid rgba(11,18,32,0.08); vertical-align: top; }}
    th {{ color: rgba(11,18,32,0.72); font-size: 12px; letter-spacing: 0.25px; text-transform: uppercase; background: rgba(2,128,175,0.06); position: sticky; top: 0; z-index: 1; }}

    .badge {{ display:inline-block; padding: 4px 8px; border: 1px solid rgba(11,18,32,0.14); border-radius: 999px; margin: 0 6px 6px 0; font-size: 12px; background: rgba(255,255,255,0.80); white-space: nowrap; }}
    .okb {{ border-color: rgba(34,197,94,0.40); color: rgba(13,82,36,0.95); }}
    .badb {{ border-color: rgba(239,68,68,0.40); color: rgba(127,29,29,0.95); }}

    .flag {{ font-family: var(--mono); font-weight: 800; }}
    .f-Exit {{ color: #16a34a; border-color: rgba(22,163,74,0.30); }}
    .f-Fast {{ color: #ca8a04; border-color: rgba(202,138,4,0.30); }}
    .f-Guard {{ color: #0284c7; border-color: rgba(2,132,199,0.30); }}
    .f-HSDir {{ color: #a21caf; border-color: rgba(162,28,175,0.28); }}
    .f-Running {{ color: #16a34a; border-color: rgba(22,163,74,0.30); }}
    .f-Stable {{ color: #1d4ed8; border-color: rgba(29,78,216,0.28); }}
    .f-Valid {{ color: #b45309; border-color: rgba(180,83,9,0.28); }}
    .f-V2Dir {{ color: #c2410c; border-color: rgba(194,65,12,0.28); }}
    .f-Authority {{ color: #0b1220; border-color: rgba(11,18,32,0.18); }}
    .f-Unknown {{ color: rgba(11,18,32,0.85); border-color: rgba(11,18,32,0.14); }}

    a.smalllink {{ color: var(--primary); text-decoration: underline; text-underline-offset: 3px; }}
    .foot {{ margin-top: 18px; color: rgba(11,18,32,0.55); font-size: 12px; line-height: 1.4; }}
    select.select {{ padding: 10px 10px; border-radius: 12px; border: 1px solid rgba(11,18,32,0.14); background: rgba(255,255,255,0.92); font-family: var(--sans); font-weight: 800; }}
  

.profile-img{{width:128px;height:128px;border-radius:22px;object-fit:cover;border:1px solid rgba(11,18,32,0.12);background:#fff;}}

</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo">
          <img src="{html.escape(ANYONE_LOGO_URL)}" alt="Anyone" onerror="this.style.display='none';" />
        </div>
        <div class="brandtext">
          <div class="name">Anyone Wallet Operator Lookup</div>
          <div class="tag">Wallet → descriptors → consensus → geo distribution → staking signals</div>
        </div>
      </div>
      {_nav(active)}
    </div>
    
{body_html}

      <!-- DONATION_CTA -->
      <div class="card" style="margin-top:14px;">
        <div style="display:flex; gap:12px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap;">
          <div style="min-width:260px; flex:1;">
            <div style="font-weight:950; font-size:14px; margin-bottom:6px;">Enjoying this site?</div>
            <div style="color: rgba(11,18,32,0.72); line-height:1.45;">
              I'm <b>Robert</b> — I built this to bring a bit more <b>transparency</b> to the Anyone ecosystem and help everyone understand staking & operator signals.
              If it helped you, consider supporting the project: send <b>$ANYONE</b> to
              <span class="mono">0xf331c6c5ae8df163a65aca83e5aa7a459ee17ecf</span>
              and stake to <b>anoncrypto.anyone</b> via the official dashboard.
            </div>
            <div class="foot" style="margin-top:10px;">Built by <b>Robert</b> with ❤️ for the <b>Anyone</b> network.</div>
          </div>
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <a class="btn" href="https://dashboard.anyone.io" target="_blank" rel="noopener noreferrer">Stake in Anyone Dashboard</a>
            <button class="btn secondary" type="button" onclick="navigator.clipboard.writeText('0xf331c6c5ae8df163a65aca83e5aa7a459ee17ecf'); this.innerText='Copied!'">Copy wallet</button>
          </div>
        </div>
      </div>
      <!-- /DONATION_CTA -->

  </div>

  </div>

  </div>
  {wallet_auth_widget_js() if 'wallet_auth_widget_js' in globals() else ''}
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def home():
    body = """
    <div class="hero">
      <h1>What this site does</h1>
      <p>
        This website helps you evaluate <b>Anyone relay operators</b> by analyzing public relay descriptors and the current consensus.
        
      </p>
      <div style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap;">
        <a href="/lookup" class="btn">Start wallet lookup</a>
        <a href="/network" class="btn secondary">Network overview</a>
      </div>
    </div>

    <div class="card panel-warn">
      <h2 style="margin:0 0 6px; font-size: 15px;">Disclaimer</h2>
      <div class="muted" style="line-height:1.45;">
        This is a <b>hobby project</b> by an <b>Anyone Operator</b>. It is <b>not</b> an official ANYONE product, not affiliated with,
        endorsed by, or supported by ANYONE. Results are best-effort and may be incomplete/outdated.
      </div>
    </div>

    <div class="card">
      <div class="muted">Enter a wallet address (0x + 40 hex chars) or a .anyone domain:</div>
      <form class="form" action="/ips" method="get">
        <input type="text" name="wallet" placeholder="0x... or xyz.anyone" />
        <input type="hidden" name="format" value="html" />
        <button type="submit">View dashboard</button>
      </form>
    </div>
    """
    return render_page("Start", body, active="home")


@app.get("/lookup", response_class=HTMLResponse)
def lookup():
    body = """
    <div class="hero">
      <h1>Wallet lookup</h1>
      <p>Paste an operator wallet address (0x…) or a .anyone domain to view the dashboard.</p>
    </div>

    <div class="card">
      <div class="muted">Enter a wallet address (0x + 40 hex chars) or a .anyone domain:</div>
      <form class="form" action="/ips" method="get">
        <input type="text" name="wallet" placeholder="0x... or xyz.anyone" />
        <input type="hidden" name="format" value="html" />
        <button type="submit">View dashboard</button>
      </form>
    </div>
    """
    return render_page("Wallet lookup", body, active="lookup")


@app.get("/operator_placeholder", response_class=HTMLResponse)
def operator_placeholder():
    body = """
    <div class="hero">
      <h1>Operator profile</h1>
      <p class="muted">Coming soon: shareable operator profiles and trend metrics.</p>
      <div style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap;">
        <a href="/lookup" class="btn">Wallet Lookup</a>
        <a href="/network" class="btn secondary">Network Overview</a>
      </div>
    </div>
    """
    return render_page("Operator profile", body, active="operator")

@app.get("/ips", response_class=HTMLResponse)
def ips(
    request: Request,
    wallet: str = Query(...),
    format: str | None = Query(default="html"),
    sort: str | None = Query(default="bandwidth"),   # bandwidth|uptime
    order: str | None = Query(default="desc"),       # desc|asc
):
    wallet_n, queried_domain = resolve_wallet_or_domain(wallet)

    if not wallet_n:
        if wants_json(request, format):
            return JSONResponse({"error": "invalid input (use 0x + 40 hex chars OR name.anyone)"}, status_code=400)
        body = """
        <div class="hero">
          <h1>Invalid input</h1>
          <p>Please enter a wallet (<span class="mono">0x</span> + 40 hex chars) or a <span class="mono">name.anyone</span> domain.</p>
          <p style="margin-top:10px"><a class="smalllink" href="/lookup">Back</a></p>
        </div>
        """
        return HTMLResponse(render_page("Invalid input", body, active="lookup"), status_code=400)

    # .anyone domains for this wallet
    try:
        anyone_domains = get_anyone_domains_for_owner(wallet_n)
    except Exception:
        anyone_domains = []
    primary_anyone_domain = anyone_domains[0] if anyone_domains else None
    domain_line = (
        " ".join([f"<span class='badge'>{html.escape(d)}</span>" for d in anyone_domains])
        if anyone_domains else "<span class='muted'>None found</span>"
    )

    sort = (sort or "bandwidth").lower()
    order = (order or "desc").lower()
    if sort not in ("bandwidth", "uptime"):
        sort = "bandwidth"
    if order not in ("asc", "desc"):
        order = "desc"

    # 1) Scan descriptors for this wallet
    relay_count = 0
    uptime_by_ip = {}
    nickname_by_ip = {}
    seen_ips = set()

    all_text = fetch_server_all()
    for b in split_descriptor_blocks(all_text):
        if wallet_from_descriptor_block(b) != wallet_n:
            continue
        relay_count += 1
        r = parse_router_line_from_descriptor(b)
        if not r:
            continue

        ip = r["ip"]
        nickname_by_ip[ip] = r["nickname"] or "unknown"

        up = uptime_from_descriptor_block(b)
        if isinstance(up, int):
            prev = uptime_by_ip.get(ip)
            if prev is None or up > prev:
                uptime_by_ip[ip] = up

        seen_ips.add(ip)

    entries = []
    for ip in sorted(seen_ips):
        cname = geoip_country_name(ip)
        gi = geoip_country_info(ip) or {}
        entries.append({
            "ip": ip,
            "country": cname,
            "country_iso": gi.get("iso"),
            "descriptor_nickname": nickname_by_ip.get(ip) or "unknown",
            "uptime_seconds": uptime_by_ip.get(ip),
            "flags": [],
            "bandwidth": None,
            "in_consensus": False,
        })

    # 2) Consensus index
    cons_text = fetch_consensus_text()
    ip_index, cons_stats = build_consensus_ip_index(cons_text)

    in_consensus_ips = 0
    total_bandwidth = 0
    exit_bandwidth = 0
    exit_ips = 0
    flag_counts = {}
    country_counts = {}

    for e in entries:
        c = ip_index.get(e["ip"])
        if not c:
            continue

        in_consensus_ips += 1
        e["in_consensus"] = True
        e["flags"] = c.get("flags") or []
        e["bandwidth"] = c.get("bandwidth")

        for f in e["flags"]:
            flag_counts[f] = flag_counts.get(f, 0) + 1

        if isinstance(e["bandwidth"], int):
            total_bandwidth += e["bandwidth"]
            if "Exit" in e["flags"]:
                exit_bandwidth += e["bandwidth"]

        if "Exit" in e["flags"]:
            exit_ips += 1

        cname = e.get("country") or "Unknown"
        country_counts[cname] = country_counts.get(cname, 0) + 1

    unique_ips = len(entries)
    consensus_pct = (in_consensus_ips / unique_ips * 100.0) if unique_ips > 0 else None

    uptime_samples = [e["uptime_seconds"] for e in entries if e.get("in_consensus") and isinstance(e.get("uptime_seconds"), int)]
    median_uptime_s = int(median(uptime_samples)) if uptime_samples else None
    avg_uptime_s = int(sum(uptime_samples) / len(uptime_samples)) if uptime_samples else None
    min_uptime_s = min(uptime_samples) if uptime_samples else None
    max_uptime_s = max(uptime_samples) if uptime_samples else None

    # Uptime buckets
    b0_3 = b4_14 = b14p = 0
    for u in uptime_samples:
        if u <= 3 * 86400:
            b0_3 += 1
        elif u <= 14 * 86400:
            b4_14 += 1
        else:
            b14p += 1
    uptime_bucket_total = len(uptime_samples)
    b0_3_pct = (b0_3 / uptime_bucket_total * 100.0) if uptime_bucket_total else None
    b4_14_pct = (b4_14 / uptime_bucket_total * 100.0) if uptime_bucket_total else None
    b14p_pct = (b14p / uptime_bucket_total * 100.0) if uptime_bucket_total else None

    top_country = None
    top_country_share_pct = None
    if in_consensus_ips > 0 and country_counts:
        top_country = max(country_counts.items(), key=lambda kv: kv[1])[0]
        top_country_share_pct = (country_counts[top_country] / in_consensus_ips) * 100.0

    # 3) Sorting
    reverse = (order == "desc")

    def sort_value(e):
        return e.get("uptime_seconds") if sort == "uptime" else e.get("bandwidth")

    def sort_key(e):
        primary = 0 if e["in_consensus"] else 1
        v = sort_value(e)
        if v is None:
            return (primary, 1, 0)
        return (primary, 0, -v if reverse else v)

    entries.sort(key=sort_key)

    # 4) Assessment
    label, message, css = assess_operator(
        consensus_pct=consensus_pct,
        in_consensus_ips=in_consensus_ips,
        unique_ips=unique_ips,
        exit_ips=exit_ips,
        total_bw=total_bandwidth,
        exit_bw=exit_bandwidth,
        median_uptime_s=median_uptime_s,
        flag_counts=flag_counts,
        top_country=top_country,
        top_country_share_pct=top_country_share_pct,
    )

    payload = {
        "wallet": wallet_n,
        "queried_domain": queried_domain,
        "primary_anyone_domain": primary_anyone_domain,
        "anyone_domains": anyone_domains,
        "relay_count_descriptor_matches": relay_count,
        "unique_ips": unique_ips,
        "in_consensus_ips": in_consensus_ips,
        "in_consensus_percent": consensus_pct,
        "wallet_total_bandwidth": total_bandwidth,
        "wallet_exit_bandwidth": exit_bandwidth,
        "wallet_exit_ips": exit_ips,
        "median_uptime_seconds": median_uptime_s,
        "avg_uptime_seconds": avg_uptime_s,
        "min_uptime_seconds": min_uptime_s,
        "max_uptime_seconds": max_uptime_s,
        "uptime_buckets": {
            "total_with_uptime": uptime_bucket_total,
            "0_3_days": {"count": b0_3, "percent": b0_3_pct},
            "4_14_days": {"count": b4_14, "percent": b4_14_pct},
            "14plus_days": {"count": b14p, "percent": b14p_pct}
        },
        "flag_counts": flag_counts,
        "country_counts_in_consensus": country_counts,
        "top_country": top_country,
        "top_country_share_percent": top_country_share_pct,
        "assessment": {"label": label, "message": message},
        "consensus_stats": cons_stats,
        "sort": {"field": sort, "order": order},
        "ips": entries,
    }

    if wants_json(request, format):
        return JSONResponse(payload)

    def flags_badges(flags):
        if not flags:
            return '<span class="muted">—</span>'
        out = []
        for f in flags:
            cls = re.sub(r"[^A-Za-z0-9]", "", f) or "Unknown"
            out.append(f"<span class='badge flag f-{html.escape(cls)}'>{html.escape(f)}</span>")
        return "".join(out)

    def sort_link(col: str) -> str:
        next_order = "asc" if (sort == col and order == "desc") else "desc"
        return f"/ips?wallet={wallet_n}&sort={col}&order={next_order}"

    bw_arrow = "↓" if (sort == "bandwidth" and order == "desc") else ("↑" if (sort == "bandwidth" and order == "asc") else "")
    up_arrow = "↓" if (sort == "uptime" and order == "desc") else ("↑" if (sort == "uptime" and order == "asc") else "")

    if consensus_pct is None:
        consensus_badge = "<span class='badge'>—</span>"
        consensus_panel_hint = ""
    elif consensus_pct < 50.0:
        consensus_badge = f"<span class='badge badb'>{_fmt_pct(consensus_pct)}</span>"
        consensus_panel_hint = "<div class='muted' style='margin-top:6px'>Below 50% is considered high risk for stakers.</div>"
    else:
        consensus_badge = f"<span class='badge okb'>{_fmt_pct(consensus_pct)}</span>"
        consensus_panel_hint = "<div class='muted' style='margin-top:6px'>Above 50% meets the minimum staker threshold.</div>"

    if country_counts and in_consensus_ips > 0:
        items = sorted(country_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]
        chips = []
        for cname, cnt in items:
            pct = (cnt / in_consensus_ips) * 100.0
            chips.append(f"<span class='badge'>{html.escape(cname)} {_fmt_int(cnt)} ({pct:.1f}%)</span>")
        country_lines = " ".join(chips)
    else:
        country_lines = "<span class='muted'>—</span>"

    flag_stat_cards = ""
    for name in sorted(flag_counts.keys()):
        flag_stat_cards += f"""
        <div class="stat">
          <div class="k">{html.escape(name)} IPs</div>
          <div class="v">{html.escape(_fmt_int(flag_counts[name]))}</div>
        </div>
        """

    rows = []
    for e in entries:
        status = "<span class='badge okb'>In consensus</span>" if e["in_consensus"] else "<span class='badge badb'>Not in consensus</span>"
        cname = e.get("country") or "Unknown"
        rows.append(
            "<tr>"
            f"<td class='mono'>{html.escape(e['descriptor_nickname'])}</td>"
            f"<td class='mono'>{html.escape(e['ip'])}</td>"
            f"<td>{html.escape(cname)}</td>"
            f"<td>{flags_badges(e['flags'])}</td>"
            f"<td class='mono'>{html.escape(_fmt_int(e['bandwidth']))}</td>"
            f"<td class='mono'>{html.escape(fmt_duration(e.get('uptime_seconds')))}</td>"
            f"<td>{status}</td>"
            "</tr>"
        )

    panel_class = "panel-ok" if css == "ok" else ("panel-bad" if css == "bad" else "panel-warn")

    body = f"""
    <div class="hero">
      <h1>Wallet dashboard</h1>
      <p class="muted">
        Wallet:
        <a class="mono smalllink" target="_blank" rel="noopener noreferrer" href="https://etherscan.io/address/{html.escape(wallet_n)}">
          {html.escape(wallet_n)}
        </a>
      </p>
      <p class="muted">.anyone domain(s): {domain_line}</p>

      <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
        <a href="/lookup" class="btn secondary">New lookup</a>
        <a href="/network" class="btn secondary">Network overview</a>
      </div>

      <div class="stats">
        <div class="stat">
          <div class="k">IP consensus presence (must be ≥ 50%)</div>
          <div class="v">{consensus_badge}</div>
          {consensus_panel_hint}
        </div>
        <div class="stat">
          <div class="k">Wallet total bandwidth (IP-sum)</div>
          <div class="v">{html.escape(_fmt_int(total_bandwidth))}</div>
        </div>
        <div class="stat">
          <div class="k">Exit bandwidth (IP-sum)</div>
          <div class="v">{html.escape(_fmt_int(exit_bandwidth))}</div>
        </div>
        <div class="stat">
          <div class="k">Average uptime (descriptor)</div>
          <div class="v">{html.escape(fmt_duration(avg_uptime_s))}</div>
        </div>
        <div class="stat">
          <div class="k">Shortest uptime (descriptor)</div>
          <div class="v">{html.escape(fmt_duration(min_uptime_s))}</div>
        </div>
        <div class="stat">
          <div class="k">Longest uptime (descriptor)</div>
          <div class="v">{html.escape(fmt_duration(max_uptime_s))}</div>
        </div>
        <div class="stat">
          <div class="k">Uptime distribution (IPs with uptime)</div>
          <div class="v">
            <span class="badge">0–3d {html.escape(_fmt_int(b0_3))} ({html.escape(_fmt_pct(b0_3_pct))})</span>
            <span class="badge">4–14d {html.escape(_fmt_int(b4_14))} ({html.escape(_fmt_pct(b4_14_pct))})</span>
            <span class="badge">14+d {html.escape(_fmt_int(b14p))} ({html.escape(_fmt_pct(b14p_pct))})</span>
          </div>
        </div>

        {flag_stat_cards}
      </div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 6px; font-size: 15px;">Geo distribution (in-consensus IPs)</h2>
      <div class="muted">Top countries: {country_lines}</div>
    </div>

    <div class="card {panel_class}">
      <h2 style="margin:0 0 6px; font-size: 15px;">Qualitative assessment: {html.escape(label)}</h2>
      <div class="muted">{html.escape(message)}</div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 8px; font-size: 15px;">Relay IPs</h2>
      <div class="muted">In-consensus first. Click Bandwidth/Uptime to sort.</div>

      <div class="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Descriptor Nickname</th>
              <th>IP</th>
              <th>Country</th>
              <th>Flags</th>
              <th><a class="smalllink" href="{sort_link('bandwidth')}">Bandwidth {bw_arrow}</a></th>
              <th><a class="smalllink" href="{sort_link('uptime')}">Uptime {up_arrow}</a></th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows) if rows else '<tr><td colspan="7" class="muted">No relays found for this wallet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    """
    return HTMLResponse(render_page("Wallet dashboard", body, active="lookup"))

_CACHE_TTL_NETWORK = 60
_cache_network_ts = 0.0
_cache_network_rows = None
_cache_network_totals = None


def _kbps_to_mibs(kbps: int | None) -> float:
    if not isinstance(kbps, int) or kbps < 0:
        return 0.0
    return kbps / 1024.0


def build_network_wallet_rows():
    global _cache_network_ts, _cache_network_rows, _cache_network_totals

    now = time.time()
    if _cache_network_rows is not None and (now - _cache_network_ts) < _CACHE_TTL_NETWORK:
        return _cache_network_rows, _cache_network_totals

    all_text = fetch_server_all()
    cons_text = fetch_consensus_text()
    ip_index, _ = build_consensus_ip_index(cons_text)

    wallets = {}
    for b in split_descriptor_blocks(all_text):
        w = wallet_from_descriptor_block(b)
        if not w:
            continue

        r = parse_router_line_from_descriptor(b)
        if not r:
            continue

        ip = r["ip"]
        up = uptime_from_descriptor_block(b)

        d = wallets.get(w)
        if d is None:
            d = {"wallet": w, "relay_blocks": 0, "ips": set(), "uptime_by_ip": {}, "desc_nick_by_ip": {}}
            wallets[w] = d

        d["relay_blocks"] += 1
        d["ips"].add(ip)
        d["desc_nick_by_ip"][ip] = r.get("nickname") or "unknown"
        if isinstance(up, int):
            prev = d["uptime_by_ip"].get(ip)
            if prev is None or up > prev:
                d["uptime_by_ip"][ip] = up

    rows = []
    totals = {"wallets_total": len(wallets), "unique_ips_total": 0, "in_consensus_ips_total": 0,
              "total_bw_mibs_total": 0.0, "exit_bw_mibs_total": 0.0}

    for w, d in wallets.items():
        ips = list(d["ips"])
        unique_ips = len(ips)
        totals["unique_ips_total"] += unique_ips

        in_cons = 0
        total_bw_kbps = 0
        exit_bw_kbps = 0
        exit_ips = 0
        flag_counts = {}
        uptime_samples = []
        country_counts = {}  # iso -> count

        for ip in ips:
            c = ip_index.get(ip)
            if not c:
                continue

            in_cons += 1
            flags = c.get("flags") or []
            bw = c.get("bandwidth")

            for f in flags:
                flag_counts[f] = flag_counts.get(f, 0) + 1

            if isinstance(bw, int):
                total_bw_kbps += bw
                if "Exit" in flags:
                    exit_bw_kbps += bw

            if "Exit" in flags:
                exit_ips += 1

            up = d["uptime_by_ip"].get(ip)
            if isinstance(up, int):
                uptime_samples.append(up)

            gi = geoip_country_info(ip) or {}
            iso = gi.get("iso") or "??"
            country_counts[iso] = country_counts.get(iso, 0) + 1

        totals["in_consensus_ips_total"] += in_cons

        consensus_pct = (in_cons / unique_ips * 100.0) if unique_ips else 0.0
        avg_uptime_s = int(sum(uptime_samples) / len(uptime_samples)) if uptime_samples else None

        total_bw_mibs = _kbps_to_mibs(total_bw_kbps)
        exit_bw_mibs = _kbps_to_mibs(exit_bw_kbps)

        totals["total_bw_mibs_total"] += total_bw_mibs
        totals["exit_bw_mibs_total"] += exit_bw_mibs

        top_flags = sorted(flag_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]

        try:
            anyone_domains = get_anyone_domains_for_owner(w)
        except Exception:
            anyone_domains = []

        rows.append({
            "wallet": w,
            "anyone_domains": anyone_domains,
            "relay_blocks": int(d["relay_blocks"]),
            "unique_ips": unique_ips,
            "in_consensus_ips": in_cons,
            "consensus_pct": consensus_pct,
            "total_bw_mibs": total_bw_mibs,
            "exit_bw_mibs": exit_bw_mibs,
            "exit_ips": exit_ips,
            "avg_uptime_s": avg_uptime_s,
            "flag_counts": flag_counts,
            "top_flags": top_flags,
            "country_counts": country_counts,
        })

    rows.sort(key=lambda r: r["total_bw_mibs"], reverse=True)

    _cache_network_rows = rows
    _cache_network_totals = totals
    _cache_network_ts = now
    return rows, totals

@app.get("/network", response_class=HTMLResponse)
def network(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=10),
    q: str | None = Query(default=None),
    sort: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    format: str | None = Query(default="html"),
):
    if per_page not in (10, 25, 50):
        per_page = 10

    rows, totals = build_network_wallet_rows()

    q_raw = (q or "").strip().lower()

    sort_key = (sort or "bw").strip().lower()
    sort_dir = (direction or "desc").strip().lower()
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    allowed = {"bw", "exitbw", "relays", "ips", "incon", "conspct", "uptime"}
    if sort_key not in allowed:
        sort_key = "bw"

    # filter
    if q_raw:
        def _row_matches(r):
            if q_raw in (r.get("wallet") or "").lower():
                return True
            for d in (r.get("anyone_domains") or []):
                if q_raw in str(d).lower():
                    return True
            return False
        rows = [r for r in rows if _row_matches(r)]

    # sort
    def _val(r, k):
        if k == "bw":
            return float(r.get("total_bw_mibs") or 0.0)
        if k == "exitbw":
            return float(r.get("exit_bw_mibs") or 0.0)
        if k == "relays":
            return int(r.get("relay_blocks") or 0)
        if k == "ips":
            return int(r.get("unique_ips") or 0)
        if k == "incon":
            return int(r.get("in_consensus_ips") or 0)
        if k == "conspct":
            return float(r.get("consensus_pct") or 0.0)
        if k == "uptime":
            u = r.get("avg_uptime_s")
            return int(u) if isinstance(u, int) else -1
        return 0

    rows.sort(key=lambda r: _val(r, sort_key), reverse=(sort_dir == "desc"))

    total_wallets = len(rows)
    pages = max(1, (total_wallets + per_page - 1) // per_page)
    if page > pages:
        page = pages

    start = (page - 1) * per_page
    end = min(start + per_page, total_wallets)
    slice_rows = rows[start:end]

    if wants_json(request, format):
        return JSONResponse({
            "page": page,
            "per_page": per_page,
            "pages": pages,
            "total_wallets": total_wallets,
            "totals": totals,
            "wallets": slice_rows,
        })

    def etherscan_link(w):
        return f"https://etherscan.io/address/{html.escape(w)}"

    def domains_badges(domains):
        if not domains:
            return '<span class="muted">—</span>'
        shown = domains[:6]
        more = len(domains) - len(shown)
        base = " ".join([f'<span class="badge">{html.escape(d)}</span>' for d in shown])
        if more > 0:
            base += f' <span class="badge">+{more} more</span>'
        return base

    def flags_badges(top_flags):
        if not top_flags:
            return '<span class="muted">—</span>'
        chips = []
        for f, n in top_flags:
            cls = re.sub(r"[^A-Za-z0-9]", "", f) or "Unknown"
            chips.append(f"<span class='badge flag f-{html.escape(cls)}'>{html.escape(f)} {_fmt_int(n)}</span>")
        return " ".join(chips)

    def countries_flags(country_counts):
        if not country_counts:
            return '<span class="muted">—</span>'
        items = sorted(country_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        out = []
        for iso, cnt in items:
            out.append(f"<span class='badge'>{country_flag_emoji(iso)} {_fmt_int(cnt)}</span>")
        return " ".join(out)

    def pager_link(p, pp):
        q_part = f"&q={html.escape(q_raw)}" if q_raw else ""
        s_part = f"&sort={html.escape(sort_key)}"
        d_part = f"&direction={html.escape(sort_dir)}"
        return f"/network?page={p}&per_page={pp}{q_part}{s_part}{d_part}"

    per_select = "<select class='select' onchange=\"location=this.value\">" + "".join([
        f"<option value='{pager_link(1, pp)}' {'selected' if pp==per_page else ''}>{pp} per page</option>"
        for pp in (10, 25, 50)
    ]) + "</select>"

    page_select = "<select class='select' onchange=\"location=this.value\">" + "".join([
        f"<option value='{pager_link(i, per_page)}' {'selected' if i==page else ''}>Page {i} / {pages}</option>"
        for i in range(1, pages+1)
    ]) + "</select>"

    sort_select = "<select class='select' onchange=\"location=this.value\">" + "".join([
        f"<option value='{pager_link(1, per_page)}&sort=bw&direction={sort_dir}' {'selected' if sort_key=='bw' else ''}>Sort: Total BW</option>",
        f"<option value='{pager_link(1, per_page)}&sort=exitbw&direction={sort_dir}' {'selected' if sort_key=='exitbw' else ''}>Sort: Exit BW</option>",
        f"<option value='{pager_link(1, per_page)}&sort=relays&direction={sort_dir}' {'selected' if sort_key=='relays' else ''}>Sort: Relays</option>",
        f"<option value='{pager_link(1, per_page)}&sort=ips&direction={sort_dir}' {'selected' if sort_key=='ips' else ''}>Sort: Unique IPs</option>",
        f"<option value='{pager_link(1, per_page)}&sort=incon&direction={sort_dir}' {'selected' if sort_key=='incon' else ''}>Sort: In consensus</option>",
        f"<option value='{pager_link(1, per_page)}&sort=conspct&direction={sort_dir}' {'selected' if sort_key=='conspct' else ''}>Sort: Consensus %</option>",
        f"<option value='{pager_link(1, per_page)}&sort=uptime&direction={sort_dir}' {'selected' if sort_key=='uptime' else ''}>Sort: Avg uptime</option>",
    ]) + "</select>"

    dir_select = "<select class='select' onchange=\"location=this.value\">" + "".join([
        f"<option value='{pager_link(1, per_page)}&sort={sort_key}&direction=desc' {'selected' if sort_dir=='desc' else ''}>Direction: Desc</option>",
        f"<option value='{pager_link(1, per_page)}&sort={sort_key}&direction=asc' {'selected' if sort_dir=='asc' else ''}>Direction: Asc</option>",
    ]) + "</select>"

    prev_link = f'<a class="smalllink" href="{pager_link(page-1, per_page)}">← Prev</a>' if page > 1 else '<span class="muted">← Prev</span>'
    next_link = f'<a class="smalllink" href="{pager_link(page+1, per_page)}">Next →</a>' if page < pages else '<span class="muted">Next →</span>'

    tr = []
    for r in slice_rows:
        w = r["wallet"]
        tr.append(
            "<tr>"
            f"<td class='mono'><a class='smalllink mono' href='/ips?wallet={html.escape(w)}'>{html.escape(w[:10] + '…' + w[-6:])}</a></td>"
            f"<td>{domains_badges(r.get('anyone_domains') or [])}</td>"
            f"<td class='mono'>{_fmt_int(r['relay_blocks'])}</td>"
            f"<td class='mono'>{_fmt_int(r['unique_ips'])}</td>"
            f"<td class='mono'>{_fmt_int(r['in_consensus_ips'])} <span class='muted'>({_fmt_pct(r['consensus_pct'])})</span></td>"
            f"<td class='mono'>{r['total_bw_mibs']:.2f}</td>"
            f"<td class='mono'>{r['exit_bw_mibs']:.2f} <span class='muted'>({r['exit_ips']} Exit IPs)</span></td>"
            f"<td class='mono'>{html.escape(fmt_duration(r['avg_uptime_s']))}</td>"
            f"<td>{flags_badges(r.get('top_flags') or [])}</td>"
            f"<td>{countries_flags(r.get('country_counts') or {})}</td>"
            "</tr>"
        )

    body = f"""
    <div class="hero">
      <h1>Network wallet overview</h1>
      <p class="muted">Search wallet or .anyone domain, then sort by bandwidth/exit/uptime and more.</p>

      <form method="get" action="/network" style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
        <input class="input" name="q" value="{html.escape(q_raw)}" placeholder="Search wallet (0x...) or xyz.anyone" style="max-width:520px; flex:1 1 320px;" />
        <input type="hidden" name="per_page" value="{per_page}" />
        <input type="hidden" name="sort" value="{html.escape(sort_key)}" />
        <input type="hidden" name="direction" value="{html.escape(sort_dir)}" />
        <button class="btn" type="submit">Search</button>
        <a class="smalllink" href="/network?per_page={per_page}">Clear</a>
      </form>

      <p class="muted">
        Controls: {per_select} {page_select} {sort_select} {dir_select}
      </p>

      <p class="muted">
        Wallets: <span class="mono">{_fmt_int(total_wallets)}</span> •
        Total BW (sum): <span class="mono">{totals['total_bw_mibs_total']:.2f} MiB/s</span> •
        Exit BW (sum): <span class="mono">{totals['exit_bw_mibs_total']:.2f} MiB/s</span>
      </p>
    </div>

    <div class="card">
      <div class="muted">
        {prev_link} &nbsp;&nbsp; Page <span class="mono">{page}</span> / <span class="mono">{pages}</span> &nbsp;&nbsp; {next_link}
      </div>

      <div class="tablewrap" style="margin-top:12px">
        <table>
          <thead>
            <tr>
              <th>Wallet</th>
              <th>.anyone domains</th>
              <th>Relays (desc)</th>
              <th>Unique IPs</th>
              <th>In consensus</th>
              <th>Total BW (MiB/s)</th>
              <th>Exit BW (MiB/s)</th>
              <th>Avg uptime</th>
              <th>Top flags</th>
              <th>Countries</th>
            </tr>
          </thead>
          <tbody>
            {''.join(tr) if tr else '<tr><td colspan="10" class="muted">No wallets found.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    """
    return HTMLResponse(render_page("Network overview", body, active="network"))

# End of file

# ---------------------------
# Operator Profiles (SQLite)
# ---------------------------
DB_PATH = "/opt/walletoperator/operator_profiles.db"
UPLOAD_DIR = "/opt/walletoperator/uploads"
MAX_BIO_WORDS = 400
MAX_IMAGE_BYTES = 2 * 1024 * 1024  # 2 MB


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def row_get(row, key: str):
    try:
        if row is None:
            return None
        # sqlite3.Row supports keys() + __getitem__
        if hasattr(row, "keys") and key in row.keys():
            return row[key]
        return row[key]
    except Exception:
        return None

def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operator_profiles (
                wallet TEXT PRIMARY KEY,
                x_handle TEXT,
                telegram_handle TEXT,
                bio TEXT,
                image_filename TEXT,
                password_hash TEXT,
                password_salt TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_operator_updated ON operator_profiles(updated_at)")
        # lightweight migrations (ignore if column exists)
        try:
            conn.execute("ALTER TABLE operator_profiles ADD COLUMN password_hash TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE operator_profiles ADD COLUMN password_salt TEXT")
        except Exception:
            pass

def word_count(text: str) -> int:
    if not text:
        return 0
    return len([w for w in re.split(r"\s+", text.strip()) if w])


def sanitize_handle(h: str | None) -> str | None:
    if not h:
        return None
    h = h.strip()
    if not h:
        return None
    if h.startswith("@"):
        h = h[1:]
    # keep it simple: letters, digits, underscore, dot, dash
    h = re.sub(r"[^A-Za-z0-9_.-]", "", h)
    return h[:64] if h else None


async def save_profile_image(file: UploadFile | None) -> str | None:
    if not file or not file.filename:
        return None

    ctype = (file.content_type or "").lower()
    if ctype not in ("image/png", "image/jpeg", "image/jpg", "image/webp"):
        raise ValueError("Unsupported image type. Use PNG/JPEG/WEBP.")

    data = await file.read()
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("Image too large (max 2 MB).")

    ext = ".png"
    if "jpeg" in ctype or "jpg" in ctype:
        ext = ".jpg"
    elif "webp" in ctype:
        ext = ".webp"

    fname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOAD_DIR, fname)
    with open(path, "wb") as f:
        f.write(data)
    return fname


def upsert_operator_profile(wallet: str, x_handle: str | None, tg_handle: str | None, bio: str, image_filename: str | None):
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with db() as conn:
        cur = conn.execute("SELECT image_filename FROM operator_profiles WHERE wallet = ?", (wallet,))
        row = cur.fetchone()
        existing_img = row["image_filename"] if row else None

        # if new image uploaded, optionally delete old
        if image_filename and existing_img and existing_img != image_filename:
            try:
                os.remove(os.path.join(UPLOAD_DIR, existing_img))
            except Exception:
                pass

        conn.execute(
            """
            INSERT INTO operator_profiles (wallet, x_handle, telegram_handle, bio, image_filename, password_hash, password_salt, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(wallet) DO UPDATE SET
              x_handle=excluded.x_handle,
              telegram_handle=excluded.telegram_handle,
              bio=excluded.bio,
              image_filename=COALESCE(excluded.image_filename, operator_profiles.image_filename),
              password_hash=COALESCE(excluded.password_hash, operator_profiles.password_hash),
              password_salt=COALESCE(excluded.password_salt, operator_profiles.password_salt),
              updated_at=excluded.updated_at
            """,
            (wallet, x_handle, tg_handle, bio, image_filename, None, None, now, now),
        )


def get_operator_profile(wallet: str):
    with db() as conn:
        cur = conn.execute("SELECT * FROM operator_profiles WHERE wallet = ?", (wallet,))
        return cur.fetchone()


def list_operator_profiles(limit: int = 200):
    with db() as conn:
        cur = conn.execute(
            "SELECT * FROM operator_profiles ORDER BY updated_at DESC LIMIT ?",
            (int(limit),),
        )
        return cur.fetchall()

@app.on_event("startup")
def _startup():
    init_db()
    init_db_auth()


@app.api_route("/uploads/{filename}", methods=["GET", "HEAD"])
def uploads(filename: str):
    # hardening: no path traversal
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=404, detail="Not Found")

    # allow:
    # - wallet filenames: 0x + 40 hex
    # - legacy filenames: 32 hex
    if not re.match(r"^(0x[a-f0-9]{40}|[a-f0-9]{32})\.(png|jpg|jpeg|webp)$", filename):
        raise HTTPException(status_code=404, detail="Not Found")

    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Not Found")

    return FileResponse(path)


@app.get("/operator", response_class=HTMLResponse)
def operator_index():
    rows = list_operator_profiles(limit=250)

    cards = []
    for r in rows:
        w = r["wallet"]
        xh = r["x_handle"]
        tg = r["telegram_handle"]
        bio = (r["bio"] or "").strip()
        img = r["image_filename"]

        bio_short = bio
        if len(bio_short) > 260:
            bio_short = bio_short[:260].rsplit(" ", 1)[0] + "…"

        img_html = (
            f"<img src='/uploads/{html.escape(img)}' style='width:64px;height:64px;border-radius:16px;object-fit:cover;border:1px solid rgba(11,18,32,0.12);background:#fff;'/>"
            if img else
            "<div style='width:64px;height:64px;border-radius:16px;border:1px solid rgba(11,18,32,0.12);background:#fff;display:flex;align-items:center;justify-content:center;font-weight:900;'>OP</div>"
        )

        links = []
        if xh:
            links.append(f"<a class='smalllink' target='_blank' rel='noopener noreferrer' href='https://x.com/{html.escape((xh or '').lstrip('@'))}'>@{html.escape((xh or '').lstrip('@'))}</a>")
        if tg:
            links.append(f"<span class='badge'>TG: {html.escape(tg)}</span>")

        cards.append(f"""
        <div class="card">
          <div style="display:flex; gap:14px; align-items:flex-start;">
            {img_html}
            <div style="flex:1 1 auto; min-width:0;">
              <div style="font-weight:950; font-size:16px; margin-bottom:6px;">
                <a class="smalllink mono" href="/operator/{html.escape(w)}">{html.escape(w[:10] + "…" + w[-6:])}</a>
              </div>
              <div style="margin-bottom:8px;">{" ".join(links) if links else "<span class='muted'>No socials provided</span>"}</div>
              <div class="muted" style="line-height:1.45;">{html.escape(bio_short) if bio_short else "—"}</div>
            </div>
          </div>
        </div>
        """)

    body = f"""
    <div class="hero">
      <h1>Operator profiles</h1>
      <p class="muted">Relay operators can create a public profile. Visitors can review bio + links and decide who to stake with.</p>
      <div style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap;">
        <a href="/operator/new" class="btn">Create / update your profile</a>
        <a href="/network" class="btn secondary">Network overview</a>
      </div>
    </div>
    {''.join(cards) if cards else '<div class="card"><div class="muted">No operator profiles yet. Be the first to create one.</div></div>'}
    """
    return HTMLResponse(render_page("Operator profiles", body, active="operator"))


@app.get("/operator/new", response_class=HTMLResponse)
def operator_new(error: str | None = None):
    err_html = f"<div class='card panel-bad'><div class='muted'>{html.escape(error)}</div></div>" if error else ""
    body = f"""
    <div class="hero">
      <h1>Create / update your operator profile</h1>
      <p class="muted">Provide your wallet + socials + a short bio (max {MAX_BIO_WORDS} words). Upload a profile image (PNG/JPEG/WEBP, max 2MB).</p>
    </div>
    {err_html}
    
    <div class="card panel-ok" id="authBox">
      <h2 style="margin:0 0 8px; font-size: 15px;">Authenticate with your wallet</h2>
      <div class="muted" style="line-height:1.45;">
        Connect your Ethereum wallet and sign a message. This proves you own the wallet and enables profile save/update/delete.
      </div>
      <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn" id="btnConnectSign" type="button" onclick="connectAndSign()">Connect & Sign</button>
        <button class="btn secondary" id="btnLogout" type="button" onclick="logoutAuth()" disabled>Logout</button>
      </div>
      <div class="muted" id="authStatus" style="margin-top:10px;">Not authenticated.</div>
    </div>

    

<div class="card">
      <form class="form" action="/operator/submit" method="post" enctype="multipart/form-data" style="flex-direction:column; align-items:stretch;">
        <label class="muted">Wallet</label>
        <input type="text" name="wallet" placeholder="Connect wallet to autofill…"  />

        <label class="muted">X handle (optional)</label>
        <input type="text" name="x_handle" placeholder="@yourname" />

        <label class="muted">Telegram (optional)</label>
        <input type="text" name="telegram_handle" placeholder="@yourtelegram or username" />

        <label class="muted">Profile image (optional)</label>
        <input type="file" name="image" accept="image/png,image/jpeg,image/webp" />

        <label class="muted">Bio (max {MAX_BIO_WORDS} words)</label>
        <textarea name="bio" rows="8" style="width:100%; padding:12px; border-radius:12px; border:1px solid rgba(11,18,32,0.14); background: rgba(255,255,255,0.92); font-family: var(--sans); font-weight: 600; line-height: 1.45;"></textarea>

        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
          <button class="btn" type="submit">Save profile</button>
          <a class="btn secondary" href="/operator">Back to profiles</a>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(render_page("Create operator profile", body, active="operator"))


@app.post("/operator/submit")
async def operator_submit(
    request: Request,
    wallet: str = Form(...),
    x_handle: str = Form(default=""),
    telegram_handle: str = Form(default=""),
    bio: str = Form(default=""),
    image: UploadFile | None = File(default=None),
):
    # Require wallet auth session (Connect & Sign)
    authed = auth_wallet_from_request(request)
    if not authed:
        return RedirectResponse(url="/operator/new?error=Please+connect+wallet+and+sign+before+saving", status_code=303)

    # Force wallet from auth (ignore form input)
    w = normalize_wallet(authed)
    if not w:
        return RedirectResponse(url="/operator/new?error=Invalid+wallet+from+auth", status_code=303)

    # Basic validation
    bio_txt = (bio or "").strip()
    if len(bio_txt.split()) > 400:
        return RedirectResponse(url="/operator/new?error=Bio+must+be+400+words+or+less", status_code=303)

    xh = (x_handle or "").strip()
    tg = (telegram_handle or "").strip()

    # Handle image upload (optional)
    img_name = None
    if image and image.filename:
        fn = image.filename.lower()
        if not any(fn.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".webp")):
            return RedirectResponse(url="/operator/new?error=Only+png,+jpg,+jpeg,+webp+allowed", status_code=303)

        import os
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Use wallet-based filename to avoid collisions
        ext = os.path.splitext(fn)[1]
        img_name = f"{w}{ext}"

        data = await image.read()
        with open(os.path.join(UPLOAD_DIR, img_name), "wb") as f:
            f.write(data)

    # Upsert
    upsert_operator_profile(w, xh, tg, bio_txt, img_name)

    return RedirectResponse(url=f"/operator/{w}", status_code=303)

# ---------------------------
# Wallet Auth (Ethereum)
# ---------------------------
AUTH_COOKIE_NAME = "op_auth"
AUTH_TTL_SECONDS = 30 * 60   # 30 min session
NONCE_TTL_SECONDS = 10 * 60  # 10 min challenge validity
AUTH_SECRET_ENV = "WALLETOPERATOR_AUTH_SECRET"


def _auth_secret() -> bytes:
    # MUST be stable across restarts. Set env var in systemd for production.
    sec = os.environ.get(AUTH_SECRET_ENV, "").strip()
    if sec:
        return sec.encode("utf-8")
    # fallback (works but logs out on restart)
    return b"DEV-CHANGE-ME"


def init_db_auth():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_nonces (
                wallet TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )

def _now() -> int:
    return int(time.time())


def _make_nonce() -> str:
    return secrets.token_hex(16)


def _set_nonce(wallet: str, nonce: str, expires_at: int):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO auth_nonces (wallet, nonce, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(wallet) DO UPDATE SET nonce=excluded.nonce, expires_at=excluded.expires_at
            """,
            (wallet, nonce, int(expires_at)),
        )


def _get_nonce(wallet: str):
    with db() as conn:
        cur = conn.execute("SELECT wallet, nonce, expires_at FROM auth_nonces WHERE wallet = ?", (wallet,))
        return cur.fetchone()


def _clear_nonce(wallet: str):
    with db() as conn:
        conn.execute("DELETE FROM auth_nonces WHERE wallet = ?", (wallet,))


def _sign_cookie(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    sig = hmac.new(_auth_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def _verify_cookie(token: str) -> dict | None:
    if not token or "." not in token:
        return None
    b64, sig = token.split(".", 1)
    exp_sig = hmac.new(_auth_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, exp_sig):
        return None
    # decode
    pad = "=" * ((4 - (len(b64) % 4)) % 4)
    raw = base64.urlsafe_b64decode((b64 + pad).encode("utf-8"))
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        return None
    if int(data.get("exp", 0)) < _now():
        return None
    return data


def auth_wallet_from_request(request: Request) -> str | None:
    token = request.cookies.get(AUTH_COOKIE_NAME)
    data = _verify_cookie(token) if token else None
    if not data:
        return None
    w = normalize_wallet(data.get("wallet", ""))
    return w


@app.post("/auth/challenge")
def auth_challenge(payload: dict):
    w = normalize_wallet(payload.get("wallet", ""))
    if not w:
        return JSONResponse({"error": "invalid wallet"}, status_code=400)

    nonce = _make_nonce()
    exp = _now() + NONCE_TTL_SECONDS
    _set_nonce(w, nonce, exp)

    # EIP-191 personal_sign message (simple & widely supported)
    msg = (
        "Anyone Wallet Operator Lookup\n\n"
        "Sign this message to prove you own this wallet.\n"
        "This does NOT trigger a blockchain transaction.\n\n"
        f"Wallet: {w}\n"
        f"Nonce: {nonce}\n"
        f"Expires: {exp}\n"
    )
    return {"wallet": w, "message": msg, "expires": exp}


@app.post("/auth/verify")
def auth_verify(payload: dict):
    w = normalize_wallet(payload.get("wallet", ""))
    sig = (payload.get("signature") or "").strip()
    if not w or not sig:
        return JSONResponse({"error": "missing wallet or signature"}, status_code=400)

    row = _get_nonce(w)
    if not row:
        return JSONResponse({"error": "no active challenge"}, status_code=400)

    expires_at = int(row["expires_at"])
    if expires_at < _now():
        _clear_nonce(w)
        return JSONResponse({"error": "challenge expired"}, status_code=400)

    nonce = row["nonce"]
    msg = (
        "Anyone Wallet Operator Lookup\n\n"
        "Sign this message to prove you own this wallet.\n"
        "This does NOT trigger a blockchain transaction.\n\n"
        f"Wallet: {w}\n"
        f"Nonce: {nonce}\n"
        f"Expires: {expires_at}\n"
    )

    try:
        recovered = Account.recover_message(encode_defunct(text=msg), signature=sig)
    except Exception:
        return JSONResponse({"error": "invalid signature"}, status_code=400)

    if recovered.lower() != w.lower():
        return JSONResponse({"error": "signature does not match wallet"}, status_code=403)

    _clear_nonce(w)
    exp = _now() + AUTH_TTL_SECONDS
    token = _sign_cookie({"wallet": w, "exp": exp})

    resp = JSONResponse({"ok": True, "wallet": w, "exp": exp})
    # HttpOnly cookie: JS kann ihn nicht lesen, aber Browser sendet automatisch
    resp.set_cookie(AUTH_COOKIE_NAME, token, httponly=True, samesite="lax", max_age=AUTH_TTL_SECONDS, path="/")
    return resp


@app.post("/auth/logout")
def auth_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return resp

def wallet_auth_widget_js():
    # Keep as a pure Python string to avoid syntax issues.
    return r"""
    <script>
      async function refreshAuthStatus(){
        try{
          const r = await fetch("/auth/me", { method: "GET" });
          const j = await r.json();

          const st = document.getElementById("authStatus");
          const btnConnect = document.getElementById("btnConnectSign");
          const btnLogout = document.getElementById("btnLogout");

          const wIn = document.querySelector('input[name="wallet"]');

          if(j && j.authenticated && j.wallet){
            if(st) st.textContent = "Authenticated: " + j.wallet;
            if(btnConnect) btnConnect.disabled = true;
            if(btnLogout) btnLogout.disabled = false;

            if(wIn){
              wIn.value = j.wallet;
              wIn.readOnly = true;
              wIn.setAttribute("aria-readonly","true");
            }
          }else{
            if(st) st.textContent = "Not authenticated.";
            if(btnConnect) btnConnect.disabled = false;
            if(btnLogout) btnLogout.disabled = true;

            if(wIn){
              // keep user's value if they typed, but make editable
              wIn.readOnly = false;
              wIn.removeAttribute("aria-readonly");
            }
          }
        }catch(e){
          // ignore
        }
      }

      async function connectAndSign(){
        const st = document.getElementById("authStatus");
        try{
          if(!window.ethereum){
            if(st) st.textContent = "No wallet found (install MetaMask/Rabby).";
            return;
          }
          const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
          const wallet = accounts && accounts[0] ? accounts[0] : null;
          if(!wallet){ if(st) st.textContent = "No account selected."; return; }

          if(st) st.textContent = "Requesting challenge…";
          const chRes = await fetch("/auth/challenge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ wallet })
          });
          const ch = await chRes.json();
          if(ch.error){ if(st) st.textContent = "Challenge error: " + ch.error; return; }

          if(st) st.textContent = "Please sign the message in your wallet…";
          const msg = ch.message;

          const signature = await window.ethereum.request({
            method: "personal_sign",
            params: [msg, wallet]
          });

          if(st) st.textContent = "Verifying…";
          const vrRes = await fetch("/auth/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ wallet, signature })
          });
          const vr = await vrRes.json();
          if(vr.error){ if(st) st.textContent = "Verify error: " + vr.error; return; }

          await refreshAuthStatus();
        }catch(e){
          if(st) st.textContent = "Auth failed: " + (e && e.message ? e.message : e);
        }
      }

      async function logoutAuth(){
        try{ await fetch("/auth/logout", { method: "POST" }); }catch(e){}
        await refreshAuthStatus();
      }

      document.addEventListener("DOMContentLoaded", () => {
        refreshAuthStatus();
      });
    </script>
    """

@app.get("/auth/me")
def auth_me(request: Request):
    w = auth_wallet_from_request(request)
    return {"authenticated": bool(w), "wallet": w}

@app.post("/operator/submit_legacy")
async def operator_submit(
    request: Request,
    x_handle: str = Form(default=""),
    telegram_handle: str = Form(default=""),
    bio: str = Form(default=""),
    image: UploadFile | None = File(default=None),
):
    # Require wallet auth and force wallet from cookie
    authed = auth_wallet_from_request(request)
    if not authed:
        return RedirectResponse(url="/operator/new?error=Please+connect+wallet+and+sign+before+saving", status_code=303)

    w = normalize_wallet(authed)
    if not w:
        return RedirectResponse(url="/operator/new?error=Invalid+wallet+from+auth", status_code=303)

    xh = (x_handle or "").strip()
    tg = (telegram_handle or "").strip()
    bio_txt = (bio or "").strip()

    # 400 words limit
    if len(bio_txt.split()) > 400:
        return RedirectResponse(url="/operator/new?error=Bio+must+be+400+words+or+less", status_code=303)

    # Keep existing image unless a new one is uploaded
    existing = get_operator_profile(w)
    existing_img = row_get(existing, "image_filename") if existing else None
    img_name = existing_img

    if image and getattr(image, "filename", None):
        fn = (image.filename or "").lower()
        ok = fn.endswith(".png") or fn.endswith(".jpg") or fn.endswith(".jpeg") or fn.endswith(".webp")
        if not ok:
            return RedirectResponse(url="/operator/new?error=Only+png,+jpg,+jpeg,+webp+allowed", status_code=303)

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        ext = os.path.splitext(fn)[1]
        img_name = f"{w}{ext}"

        data = await image.read()
        if data:
            with open(os.path.join(UPLOAD_DIR, img_name), "wb") as f:
                f.write(data)

    # Persist
    upsert_operator_profile(w, xh, tg, bio_txt, img_name)

    # Redirect to the freshly saved profile page
    return RedirectResponse(url=f"/operator/{w}", status_code=303)

# --- Operator profile page ---
@app.get("/operator/{wallet}", response_class=HTMLResponse)
def operator_profile_page(wallet: str):
    w = normalize_wallet(wallet)
    if not w:
        return HTMLResponse("Invalid wallet", status_code=400)

    prof = get_operator_profile(w)
    if not prof:
        return HTMLResponse("Profile not found", status_code=404)

    xh = (row_get(prof, "x_handle") or "").strip()
    tg = (row_get(prof, "telegram_handle") or "").strip()
    bio = (row_get(prof, "bio") or "").strip()
    img = row_get(prof, "image_filename")

    img_html = ""
    if img:
        img_html = f'<div class="profile-img-wrap"><img class="profile-img" src="/uploads/{html.escape(img)}" alt="Profile image"></div>'

    # Reuse existing page shell/style helpers you already have
    body = f"""
    <div class="card">
      <div class="card-header">
        <div>
          <div class="h1">Operator Profile</div>
          <div class="muted">{html.escape(w)}</div>
        </div>
      </div>

      <div class="profile-grid">
        {img_html}
        <div>
          {f'<div><b>X</b>: {html.escape((xh or '').lstrip('@'))}</div>' if xh else ''}
          {f'<div><b>Telegram</b>: {html.escape(tg)}</div>' if tg else ''}
        </div>
      </div>

      {f'<div class="bio">{html.escape(bio).replace(chr(10), "<br>")}</div>' if bio else ''}

      <div style="margin-top:16px; display:flex; gap:10px;">
        <a class="btn" href="/operator">Back to operator list</a>
        <a class="btn secondary" href="/operator/new">Create / update your profile</a>
      </div>
    </div>
    """

    return HTMLResponse(render_page("Operator Profile", body))

# --- Operator profile page ---
@app.get("/operator/{wallet}", response_class=HTMLResponse)
def operator_profile_page(wallet: str):
    w = normalize_wallet(wallet)
    if not w:
        return HTMLResponse("Invalid wallet", status_code=400)

    prof = get_operator_profile(w)
    if not prof:
        return HTMLResponse("Profile not found", status_code=404)

    xh = (row_get(prof, "x_handle") or "").strip()
    tg = (row_get(prof, "telegram_handle") or "").strip()
    bio = (row_get(prof, "bio") or "").strip()
    img = row_get(prof, "image_filename")

    img_html = ""
    if img:
        img_html = f'<div class="profile-img-wrap"><img class="profile-img" src="/uploads/{html.escape(img)}" alt="Profile image"></div>'

    body = f"""
    <div class="card">
      <div class="card-header">
        <div>
          <div class="h1">Operator Profile</div>
          <div class="muted">{html.escape(w)}</div>
        </div>
      </div>

      <div class="profile-grid">
        {img_html}
        <div>
          {f'<div><b>X</b>: {html.escape((xh or '').lstrip('@'))}</div>' if xh else ''}
          {f'<div><b>Telegram</b>: {html.escape(tg)}</div>' if tg else ''}
        </div>
      </div>

      {f'<div class="bio">{html.escape(bio).replace(chr(10), "<br>")}</div>' if bio else ''}

      <div style="margin-top:16px; display:flex; gap:10px;">
        <a class="btn" href="/operator">Back to operator list</a>
        <a class="btn secondary" href="/operator/new">Create / update your profile</a>
      </div>
    </div>
    """

    # Use your existing page shell
    return HTMLResponse(page("Operator Profile", body))

