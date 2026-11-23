#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipreal-hunter
=============
Origin/real-IP candidate hunter for authorized bug bounty & VDP recon.

Given a list of hosts/subdomains (e.g. the output of subfinder -> subs.txt),
ipreal-hunter collects candidate IP addresses from several sources, then
intelligently groups them into:

  [ORIGIN]  candidate real/origin IPs worth investigating
  [CDN/WAF] IPs that belong to a CDN / WAF / reverse-proxy front (Cloudflare,
            Akamai, Fastly, CloudFront, Imperva, Sucuri, ...) -- these are the
            shield, NOT the origin.

Optionally it *verifies* origin candidates by connecting to each IP directly
with the target Host header and comparing the response to the CDN-fronted
baseline (status / title / content-length / favicon hash), producing a
confidence score.

Sources (all optional, auto-enabled when an API key is present):
  - Direct DNS resolution (A / AAAA) of every input host        [no key]
  - crt.sh Certificate Transparency                             [no key]
  - HackerTarget host->IP                                       [no key]
  - SecurityTrails DNS history (historical A records)           [key]
  - VirusTotal passive DNS resolutions                          [key]
  - Shodan host lookup / search                                 [key]
  - Censys hosts search                                         [key]
  - Certspotter issuances                                       [key]
  - DNSDumpster                                                 [key]

Classification data:
  - Live official CIDR feeds (Cloudflare, AWS/CloudFront, GCP, Fastly,
    DigitalOcean, Oracle, ...) cached locally
  - Team Cymru IP-to-ASN lookup (over DNS, no key) as a comprehensive
    fallback, matched against a provider keyword table.

API keys are read from your existing subfinder provider-config.yaml
(default: ~/.config/subfinder/provider-config.yaml) or from environment
variables. Keys are never written to disk by this tool.

    LEGAL / ETHICAL: Only run this against targets you are explicitly
    authorized to test (in-scope bug bounty / VDP / written permission).
    Unauthorized scanning is illegal.

License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ----------------------------------------------------------------------------
# Optional dependencies -- degrade gracefully if missing.
# ----------------------------------------------------------------------------
try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    import dns.resolver  # dnspython
    import dns.reversename
    _HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _HAVE_DNSPYTHON = False

try:
    import yaml  # PyYAML
    _HAVE_YAML = True
except ImportError:  # pragma: no cover
    _HAVE_YAML = False

try:
    import mmh3  # for favicon hashing (Shodan-style)
    _HAVE_MMH3 = True
except ImportError:  # pragma: no cover
    _HAVE_MMH3 = False


VERSION = "1.4.0"
UA = f"ipreal-hunter/{VERSION} (+bug-bounty recon)"
CACHE_DIR = Path(os.path.expanduser("~/.cache/ipreal-hunter"))
CACHE_TTL = 24 * 3600  # refresh CIDR feeds once a day


# ----------------------------------------------------------------------------
# Console colors
# ----------------------------------------------------------------------------
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; Cy = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
    BOLD = "\033[1m"; RST = "\033[0m"

    _enabled = sys.stdout.isatty()

    @classmethod
    def wrap(cls, color: str, text: str) -> str:
        if not cls._enabled:
            return text
        return f"{color}{text}{cls.RST}"


def log(msg: str, level: str = "info") -> None:
    tag = {
        "info": C.wrap(C.Cy, "[*]"),
        "ok": C.wrap(C.G, "[+]"),
        "warn": C.wrap(C.Y, "[!]"),
        "err": C.wrap(C.R, "[-]"),
        "src": C.wrap(C.M, "[>]"),
    }.get(level, "[*]")
    print(f"{tag} {msg}", file=sys.stderr)


# ----------------------------------------------------------------------------
# CDN / WAF / cloud provider knowledge base
# ----------------------------------------------------------------------------
CIDR_FEEDS = {
    "cloudflare-v4": {"url": "https://www.cloudflare.com/ips-v4/", "fmt": "lines", "provider": "Cloudflare", "cdn": True},
    "cloudflare-v6": {"url": "https://www.cloudflare.com/ips-v6/", "fmt": "lines", "provider": "Cloudflare", "cdn": True},
    "aws":           {"url": "https://ip-ranges.amazonaws.com/ip-ranges.json", "fmt": "aws", "provider": "AWS", "cdn": False},
    "gcp":           {"url": "https://www.gstatic.com/ipranges/cloud.json", "fmt": "gcp", "provider": "Google Cloud", "cdn": False},
    "fastly":        {"url": "https://api.fastly.com/public-ip-list", "fmt": "fastly", "provider": "Fastly", "cdn": True},
    "digitalocean":  {"url": "https://www.digitalocean.com/geo/google.csv", "fmt": "do_csv", "provider": "DigitalOcean", "cdn": False},
    "oracle":        {"url": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", "fmt": "oracle", "provider": "Oracle Cloud", "cdn": False},
    "github":        {"url": "https://api.github.com/meta", "fmt": "github", "provider": "GitHub", "cdn": True},
}

ASN_KEYWORDS: List[Tuple[str, str, bool]] = [
    ("cloudflare", "Cloudflare", True),
    ("akamai", "Akamai", True),
    ("fastly", "Fastly", True),
    ("cloudfront", "AWS CloudFront", True),
    ("incapsula", "Imperva Incapsula", True),
    ("imperva", "Imperva Incapsula", True),
    ("sucuri", "Sucuri", True),
    ("stackpath", "StackPath", True),
    ("highwinds", "StackPath", True),
    ("cdn77", "CDN77", True),
    ("cdnetworks", "CDNetworks", True),
    ("bunnyway", "BunnyCDN", True),
    ("bunny.net", "BunnyCDN", True),
    ("keycdn", "KeyCDN", True),
    ("proinity", "KeyCDN", True),
    ("g-core", "Gcore", True),
    ("gcore", "Gcore", True),
    ("edgecast", "Edgecast/Verizon", True),
    ("verizon digital", "Edgecast/Verizon", True),
    ("limelight", "Edgio/Limelight", True),
    ("edgio", "Edgio/Limelight", True),
    ("section.io", "Section.io", True),
    ("azion", "Azion", True),
    ("qrator", "Qrator", True),
    ("ddos-guard", "DDoS-Guard", True),
    ("ddosguard", "DDoS-Guard", True),
    ("vercel", "Vercel", True),
    ("netlify", "Netlify", True),
    ("frontdoor", "Azure Front Door", True),
    ("azure front", "Azure Front Door", True),
    ("wpengine", "WP Engine", True),
    # ---- cloud hosting (NOT a shield; origins often live here) ----
    ("amazon", "AWS", False),
    ("aws", "AWS", False),
    ("google", "Google Cloud", False),
    ("microsoft", "Azure", False),
    ("azure", "Azure", False),
    ("digitalocean", "DigitalOcean", False),
    ("linode", "Linode/Akamai Cloud", False),
    ("vultr", "Vultr", False),
    ("choopa", "Vultr", False),
    ("hetzner", "Hetzner", False),
    ("ovh", "OVH", False),
    ("oracle", "Oracle Cloud", False),
    ("alibaba", "Alibaba Cloud", False),
    ("aliyun", "Alibaba Cloud", False),
    ("tencent", "Tencent Cloud", False),
    ("contabo", "Contabo", False),
    ("scaleway", "Scaleway", False),
    ("upcloud", "UpCloud", False),
    ("leaseweb", "Leaseweb", False),
]


@dataclass
class ProviderDB:
    v4: List[Tuple[ipaddress.IPv4Network, str, bool]] = field(default_factory=list)
    v6: List[Tuple[ipaddress.IPv6Network, str, bool]] = field(default_factory=list)
    asn_cache: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    def add(self, cidr: str, provider: str, cdn: bool) -> None:
        cidr = cidr.strip()
        if not cidr:
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        if net.version == 4:
            self.v4.append((net, provider, cdn))
        else:
            self.v6.append((net, provider, cdn))

    def match_cidr(self, ip: str) -> Optional[Tuple[str, bool]]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        table = self.v4 if addr.version == 4 else self.v6
        for net, provider, cdn in table:
            if addr in net:
                return provider, cdn
        return None


# ----------------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------------
def http_get(url: str, timeout: int = 20, headers: Optional[dict] = None,
             auth=None, params=None):
    if requests is None:
        raise RuntimeError("The 'requests' library is required. pip install requests")
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    return requests.get(url, timeout=timeout, headers=h, auth=auth, params=params)


def cached_fetch(name: str, url: str, timeout: int = 25) -> Optional[str]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{name}.cache"
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < CACHE_TTL:
        try:
            return cache_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    try:
        r = http_get(url, timeout=timeout)
        if r.status_code == 200 and r.text:
            cache_file.write_text(r.text, encoding="utf-8")
            return r.text
    except Exception as e:  # noqa: BLE001
        log(f"feed fetch failed for {name}: {e}", "warn")
        if cache_file.exists():
            return cache_file.read_text(encoding="utf-8", errors="replace")
    return None


# ----------------------------------------------------------------------------
# Per-host API response cache (TTL) — re-runs skip unchanged history
# ----------------------------------------------------------------------------
# History sources (VT/shodan/censys/...) change slowly; verification stays
# live. Cache key covers method+url+headers+params+body. Privacy: the file
# stores only status+body, the filename is a hash (API keys never persisted).
API_CACHE_TTL_DEFAULT = 7 * 86400
_API_CACHE_ON = True
_API_CACHE_TTL = API_CACHE_TTL_DEFAULT
_API_CACHE_DIR = None  # override in tests; default CACHE_DIR/"api"


class CachedResp:
    """Minimal requests.Response shim (status_code/text/json) for cached replies."""

    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def _api_cache_file(source: str, fingerprint: str) -> Path:
    h = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:32]
    d = _API_CACHE_DIR if _API_CACHE_DIR is not None else (CACHE_DIR / "api")
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{source}-{h}.json"


def api_fetch(source: str, url: str, *, method: str = "GET",
              headers: Optional[dict] = None, params: Optional[dict] = None,
              json_body: Optional[dict] = None,
              timeout: int = 25) -> Optional[CachedResp]:
    """GET/POST with file cache (200-only, TTL). None on transport error.

    Non-200 passes through uncached so quota/auth changes surface promptly.
    """
    if requests is None:
        return None
    fp = "\n".join([
        method.upper(), url,
        json.dumps(headers or {}, sort_keys=True, default=str),
        json.dumps(params or {}, sort_keys=True, default=str),
        json.dumps(json_body or {}, sort_keys=True, default=str),
    ])
    cf_path = _api_cache_file(source, fp)
    if _API_CACHE_ON:
        try:
            if cf_path.exists() and (time.time() - cf_path.stat().st_mtime) < _API_CACHE_TTL:
                data = json.loads(cf_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and data.get("status") == 200 and data.get("text"):
                    return CachedResp(200, data["text"])
        except (OSError, ValueError):
            pass
    try:
        if method.upper() == "POST":
            r = requests.post(url, headers=headers, json=json_body, timeout=timeout)
        else:
            r = http_get(url, timeout=timeout, headers=headers, params=params)
        if r.status_code == 200 and r.text and _API_CACHE_ON:
            try:
                cf_path.write_text(json.dumps({"status": 200, "text": r.text}), encoding="utf-8")
            except OSError:
                pass
        return CachedResp(r.status_code, r.text or "")
    except Exception:
        return None


# ----------------------------------------------------------------------------
# Build provider DB from live feeds
# ----------------------------------------------------------------------------
def build_provider_db(offline: bool = False) -> ProviderDB:
    db = ProviderDB()
    if offline:
        log("offline mode: skipping live CIDR feeds, relying on Cymru ASN only", "warn")
        return db

    for name, spec in CIDR_FEEDS.items():
        text = cached_fetch(name, spec["url"])
        if not text:
            continue
        provider, cdn, fmt = spec["provider"], spec["cdn"], spec["fmt"]
        try:
            if fmt == "lines":
                for line in text.splitlines():
                    db.add(line, provider, cdn)
            elif fmt == "aws":
                data = json.loads(text)
                for pfx in data.get("prefixes", []):
                    svc = pfx.get("service", "")
                    is_cdn = svc == "CLOUDFRONT"
                    prov = "AWS CloudFront" if is_cdn else "AWS"
                    db.add(pfx.get("ip_prefix", ""), prov, is_cdn)
                for pfx in data.get("ipv6_prefixes", []):
                    svc = pfx.get("service", "")
                    is_cdn = svc == "CLOUDFRONT"
                    prov = "AWS CloudFront" if is_cdn else "AWS"
                    db.add(pfx.get("ipv6_prefix", ""), prov, is_cdn)
            elif fmt == "gcp":
                data = json.loads(text)
                for pfx in data.get("prefixes", []):
                    cidr = pfx.get("ipv4Prefix") or pfx.get("ipv6Prefix") or ""
                    db.add(cidr, provider, cdn)
            elif fmt == "fastly":
                data = json.loads(text)
                for cidr in data.get("addresses", []) + data.get("ipv6_addresses", []):
                    db.add(cidr, provider, cdn)
            elif fmt == "do_csv":
                for line in text.splitlines():
                    db.add(line.split(",")[0], provider, cdn)
            elif fmt == "oracle":
                data = json.loads(text)
                for region in data.get("regions", []):
                    for cidr in region.get("cidrs", []):
                        db.add(cidr.get("cidr", ""), provider, cdn)
            elif fmt == "github":
                data = json.loads(text)
                for key in ("web", "api", "pages"):
                    for cidr in data.get(key, []):
                        db.add(cidr, provider, cdn)
        except Exception as e:  # noqa: BLE001
            log(f"parse failed for feed {name}: {e}", "warn")

    log(f"provider DB loaded: {len(db.v4)} IPv4 + {len(db.v6)} IPv6 networks", "ok")
    return db


# ----------------------------------------------------------------------------
# Team Cymru IP -> ASN lookup (over DNS, no API key)
# ----------------------------------------------------------------------------
def cymru_lookup(ip: str, db: ProviderDB) -> Optional[Tuple[str, str]]:
    if ip in db.asn_cache:
        return db.asn_cache[ip]
    if not _HAVE_DNSPYTHON:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    try:
        if addr.version == 4:
            rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            nib = dns.reversename.from_address(ip).to_text().replace(".ip6.arpa.", "")
            rev = nib + ".origin6.asn.cymru.com"
        answers = dns.resolver.resolve(rev, "TXT", lifetime=6)
        txt = str(answers[0]).strip('"')
        asn = txt.split("|")[0].strip().split()[0]
        asname = ""
        try:
            a2 = dns.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT", lifetime=6)
            asname = str(a2[0]).strip('"').split("|")[-1].strip()
        except Exception:  # noqa: BLE001
            pass
        result = (asn, asname)
        db.asn_cache[ip] = result
        return result
    except Exception:  # noqa: BLE001
        return None


def classify_ip(ip: str, db: ProviderDB, use_asn: bool = True) -> Tuple[str, bool, str]:
    hit = db.match_cidr(ip)
    if hit:
        return hit[0], hit[1], "cidr"
    if use_asn:
        res = cymru_lookup(ip, db)
        if res:
            asn, asname = res
            low = asname.lower()
            for kw, prov, cdn in ASN_KEYWORDS:
                if kw in low:
                    return f"{prov} (AS{asn})", cdn, "asn"
            if asname:
                return f"{asname} (AS{asn})", False, "asn"
    return "Unknown", False, "unknown"


# ----------------------------------------------------------------------------
# Config: read API keys from subfinder provider-config.yaml or env
# ----------------------------------------------------------------------------
DEFAULT_SUBFINDER_CFG = Path(os.path.expanduser("~/.config/subfinder/provider-config.yaml"))


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v or None


def load_keys(cfg_path: Optional[Path]) -> Dict[str, Optional[str]]:
    keys: Dict[str, Optional[str]] = {}
    path = cfg_path or DEFAULT_SUBFINDER_CFG
    if _HAVE_YAML and path and path.exists():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for k, v in data.items():
                keys[k.lower()] = _first(v)
            log(f"loaded API keys from {path}", "ok")
        except Exception as e:  # noqa: BLE001
            log(f"could not parse {path}: {e}", "warn")
    for prov in ("securitytrails", "virustotal", "shodan", "censys",
                 "certspotter", "dnsdumpster"):
        env = os.environ.get(f"IPREAL_{prov.upper()}")
        if env:
            keys[prov] = env
    return keys


# ----------------------------------------------------------------------------
# IP-yielding sources
# ----------------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _valid_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_reserved or
                a.is_link_local or a.is_multicast or a.is_unspecified)


@dataclass
class Finding:
    ip: str
    hosts: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)


class Collector:
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        # (ip, host) pairs that are the host's CURRENT A/AAAA record. Kept
        # separately because Finding only stores a flat host/source union;
        # verification needs the pair to tell "serves its own DNS record"
        # apart from "serves a host it is not the DNS record of".
        self.dns_hosts: Set[Tuple[str, str]] = set()

    def add(self, ip: str, host: str, source: str) -> None:
        ip = ip.strip()
        if not _valid_public_ip(ip):
            return
        f = self.findings.get(ip)
        if not f:
            f = Finding(ip=ip)
            self.findings[ip] = f
        if host:
            f.hosts.add(host)
        f.sources.add(source)


def parse_known_ip_line(raw: str) -> Optional[str]:
    """Normalize one known-IP input line -> bare public IP, or None to skip."""
    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return None
    # tolerate "IP", "IP:port", "http(s)://IP/..." forms
    line = re.sub(r"^https?://", "", line).split("/")[0].split()[0]
    if ":" in line and line.count(":") == 1:
        line = line.split(":")[0]
    line = line.strip("[]")
    return line if _valid_public_ip(line) else None


def load_known_ips(path: str) -> Tuple[List[str], int]:
    """Read known candidate origin IPs from a file (one per line).

    Accepts bare IPs and host:port forms (port stripped -- verification
    always probes 443+80 directly). Returns (valid_ips, skipped_count).
    """
    valid: List[str] = []
    seen = set()
    skipped = 0
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        ip = parse_known_ip_line(raw)
        if ip and ip not in seen:
            seen.add(ip)
            valid.append(ip)
        elif (raw or "").strip() and not (raw or "").strip().startswith("#"):
            skipped += 1
    return valid, skipped


def src_resolve(host: str, collector: Collector) -> None:
    records = []
    if _HAVE_DNSPYTHON:
        for rtype in ("A", "AAAA"):
            try:
                ans = dns.resolver.resolve(host, rtype, lifetime=6)
                records += [r.to_text() for r in ans]
            except Exception:  # noqa: BLE001
                pass
    else:
        try:
            infos = socket.getaddrinfo(host, None)
            records += list({i[4][0] for i in infos})
        except Exception:  # noqa: BLE001
            pass
    for ip in records:
        collector.add(ip, host, "dns")
        if _valid_public_ip(ip):
            collector.dns_hosts.add((ip, host))


def src_crtsh(domain: str, collector: Collector, extra_hosts: Set[str]) -> None:
    try:
        r = api_fetch("crtsh", f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if r is None or r.status_code != 200:
            return
        for entry in r.json():
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    extra_hosts.add(name)
                for m in IP_RE.findall(name):
                    collector.add(m, name, "crtsh")
    except Exception as e:  # noqa: BLE001
        log(f"crt.sh failed for {domain}: {e}", "warn")


def src_hackertarget(host: str, collector: Collector) -> None:
    try:
        r = api_fetch("hackertarget", f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=20)
        if r is None:
            return
        if r.status_code == 200 and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    collector.add(parts[1], parts[0], "hackertarget")
    except Exception:  # noqa: BLE001
        pass


def src_securitytrails(host: str, key: str, collector: Collector) -> None:
    try:
        r = api_fetch(
            "securitytrails",
            f"https://api.securitytrails.com/v1/history/{host}/dns/a",
            timeout=25, headers={"APIKEY": key},
        )
        if r is None:
            return
        if r.status_code == 200:
            data = r.json()
            for rec in data.get("records", []):
                for v in rec.get("values", []):
                    ip = v.get("ip")
                    if ip:
                        collector.add(ip, host, "securitytrails-history")
        elif r.status_code in (401, 403):
            log("SecurityTrails: unauthorized (check key/quota)", "warn")
    except Exception as e:  # noqa: BLE001
        log(f"securitytrails failed for {host}: {e}", "warn")


def src_virustotal(host: str, key: str, collector: Collector) -> None:
    try:
        r = api_fetch(
            "virustotal",
            f"https://www.virustotal.com/api/v3/domains/{host}/resolutions",
            timeout=25, headers={"x-apikey": key}, params={"limit": 40},
        )
        if r is None:
            return
        if r.status_code == 200:
            for item in r.json().get("data", []):
                ip = item.get("attributes", {}).get("ip_address")
                if ip:
                    collector.add(ip, host, "virustotal")
    except Exception as e:  # noqa: BLE001
        log(f"virustotal failed for {host}: {e}", "warn")


def src_shodan_domain(domain: str, key: str, collector: Collector) -> None:
    try:
        r = api_fetch("shodan",
                      f"https://api.shodan.io/dns/domain/{domain}",
                      timeout=25, params={"key": key})
        if r is None:
            return
        if r.status_code == 200:
            data = r.json()
            for rec in data.get("data", []):
                if rec.get("type") in ("A", "AAAA") and rec.get("value"):
                    sub = rec.get("subdomain", "")
                    host = f"{sub}.{domain}" if sub else domain
                    collector.add(rec["value"], host, "shodan")
    except Exception as e:  # noqa: BLE001
        log(f"shodan failed for {domain}: {e}", "warn")


def src_censys(domain: str, token: str, collector: Collector) -> None:
    try:
        r = api_fetch(
            "censys",
            "https://search.censys.io/api/v2/hosts/search",
            method="POST",
            headers={"Authorization": f"Bearer {token}", "User-Agent": UA},
            json_body={"q": f"services.tls.certificates.leaf_data.names: {domain}",
                       "per_page": 50},
            timeout=25,
        )
        if r is None:
            return
        if r.status_code == 200:
            for hit in r.json().get("result", {}).get("hits", []):
                ip = hit.get("ip")
                if ip:
                    collector.add(ip, domain, "censys")
        elif r.status_code in (401, 403):
            log("censys: unauthorized (token/plan) -- skipping", "warn")
    except Exception as e:  # noqa: BLE001
        log(f"censys failed for {domain}: {e}", "warn")


def src_certspotter(domain: str, key: str, collector: Collector, extra_hosts: Set[str]) -> None:
    try:
        r = api_fetch(
            "certspotter",
            "https://api.certspotter.com/v1/issuances",
            timeout=25,
            headers={"Authorization": f"Bearer {key}"} if key else None,
            params={"domain": domain, "include_subdomains": "true",
                    "expand": "dns_names"},
        )
        if r is None:
            return
        if r.status_code == 200:
            for iss in r.json():
                for name in iss.get("dns_names", []):
                    name = name.lstrip("*.").lower()
                    if name.endswith(domain):
                        extra_hosts.add(name)
    except Exception as e:  # noqa: BLE001
        log(f"certspotter failed for {domain}: {e}", "warn")


def src_dnsdumpster(domain: str, key: str, collector: Collector) -> None:
    try:
        r = api_fetch("dnsdumpster",
                      f"https://api.dnsdumpster.com/domain/{domain}",
                      timeout=25, headers={"X-API-Key": key})
        if r is None:
            return
        if r.status_code == 200:
            data = r.json()
            for rec in data.get("a", []):
                host = rec.get("host", domain)
                for ipobj in rec.get("ips", []):
                    ip = ipobj.get("ip")
                    if ip:
                        collector.add(ip, host, "dnsdumpster")
    except Exception as e:  # noqa: BLE001
        log(f"dnsdumpster failed for {domain}: {e}", "warn")


# ----------------------------------------------------------------------------
# Origin verification
# ----------------------------------------------------------------------------

# Direct-IP responses that usually mean "WAF / server blocked the direct hit"
DENY_CODES = {403, 405, 406, 429, 451, 502, 503}


def _req_timeout(read: int, connect: Optional[int]):
    """requests timeout: split connect vs read so firewall drops fail fast."""
    if connect is None:
        return read
    return (max(1, int(connect)), max(1, int(read)))


def _is_connect_timeout(exc: BaseException) -> bool:
    """True only for TCP connect timeouts (SYN dropped), not read timeouts."""
    names = {c.__name__ for c in type(exc).__mro__}
    return bool(names & {"ConnectTimeout", "ConnectTimeoutError"})


def get_baseline(host: str, timeout: int = 15,
                 connect_timeout: Optional[int] = None) -> dict:
    base = {"title": None, "len": None, "status": None, "server": None}
    for scheme in ("https", "http"):
        try:
            r = http_get(f"{scheme}://{host}/",
                         timeout=_req_timeout(timeout, connect_timeout))
            base["status"] = r.status_code
            base["len"] = len(r.content)
            base["server"] = r.headers.get("Server")
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            base["title"] = m.group(1).strip()[:120] if m else None
            return base
        except Exception as exc:  # noqa: BLE001
            if _is_connect_timeout(exc):
                break  # 443 SYN dropped -> 80 will hang the same way
            continue
    return base



def _verdict_for(score: int, reached: bool, redirect_host: Optional[str],
                 codes: List[int], host: str) -> str:
    if score >= 70:
        return "ACCESS"
    if redirect_host:
        return "REDIRECT"
    if reached and codes and all(c in DENY_CODES for c in codes):
        return "DENIED"
    if reached:
        return "REACHED"
    return "BLOCKED"


def verify_origin(ip: str, host: str, baseline: dict, timeout: int = 12,
                  probe_path: str = "/",
                  connect_timeout: Optional[int] = None) -> Tuple[int, str, str]:
    if requests is None:
        return 0, "requests missing", "BLOCKED"
    notes = []
    score = 0
    reached = False
    codes: List[int] = []
    redirect_host: Optional[str] = None
    connect_dropped = False
    for scheme, port in (("https", 443), ("http", 80)):
        if scheme == "http" and connect_dropped:
            # TCP connect to this IP already timed out on 443: the same
            # firewall drop usually swallows 80 too, and retrying would burn
            # another full connect budget for nothing.
            notes.append("connect-timeout")
            continue
        url = f"{scheme}://{ip}:{port}{probe_path}"
        try:
            # direct connection only -- never route the probe through a proxy
            r = requests.get(
                url, timeout=_req_timeout(timeout, connect_timeout), verify=False,
                headers={"Host": host, "User-Agent": UA},
                allow_redirects=False,
                proxies={"http": None, "https": None},
            )
        except Exception as exc:  # noqa: BLE001
            if _is_connect_timeout(exc):
                connect_dropped = True
            continue
        reached = True
        codes.append(r.status_code)
        score = max(score, 10)
        if r.is_redirect or r.is_permanent_redirect:
            loc = (r.headers.get("Location") or "").strip()
            m = re.match(r"^https?://([^/:]+)", loc)
            rhost = m.group(1).lower().rstrip(".") if m else loc.lower().rstrip(".")
            if rhost and rhost != host:
                redirect_host = rhost
                notes.append(f"redirect:{rhost}")
                continue
            notes.append("redirect:same-host")
        if baseline.get("status") and r.status_code == baseline["status"]:
            score = max(score, 30); notes.append("status-match")
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        title = m.group(1).strip()[:120] if m else None
        if title and baseline.get("title") and title == baseline["title"]:
            score = max(score, 90); notes.append("title-match")
        elif title and baseline.get("title") and (
                title.lower() in baseline["title"].lower()
                or baseline["title"].lower() in title.lower()):
            score = max(score, 70); notes.append("title-partial")
        if baseline.get("len"):
            diff = abs(len(r.content) - baseline["len"])
            if diff < max(64, baseline["len"] * 0.02):
                score = max(score, 80); notes.append("body-size-match")
        if scheme == "https":
            try:
                if _cert_matches(ip, port, host, connect_timeout=connect_timeout):
                    score = max(score, 85); notes.append("tls-san-match")
            except Exception:  # noqa: BLE001
                pass
            if score >= 70:
                break  # ACCESS confirmed via https; http probe adds nothing
                # (score monotonic -> verdict can't downgrade; saves one probe)
    note = ",".join(sorted(set(notes)))
    if not note:
        note = "reachable" if reached else "no-response"
    verdict = _verdict_for(score, reached, redirect_host, codes, host)
    return score, note, verdict


def san_matches_host(san: str, host: str) -> bool:
    """True if one certificate SAN name covers `host`.

    Exact match, or a wildcard `*.parent` that covers `parent` itself and
    exactly one label below it. Crucially, `*.go.id` does NOT cover
    `kalsel.web.bps.go.id` -- two trailing labels are not a domain boundary.
    """
    san = (san or "").strip().lower().rstrip(".")
    host = (host or "").strip().lower().rstrip(".")
    if not san or not host:
        return False
    if san == host:
        return True
    if not san.startswith("*."):
        return False
    parent = san[2:]
    if not parent:
        return False
    if host == parent:
        return True
    if not host.endswith("." + parent):
        return False
    left = host[: -(len(parent) + 1)]
    return bool(left) and "." not in left


def _cert_san_names(ssock) -> List[str]:
    """DNS SANs from a negotiated TLS socket (getpeercert() alone is empty
    under CERT_NONE, so decode the DER certificate too)."""
    names: List[str] = []
    cert = {}
    try:
        cert = ssock.getpeercert() or {}
    except Exception:  # noqa: BLE001
        cert = {}
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS":
            names.append(val.lower())
    if names:
        return names
    der = None
    try:
        der = ssock.getpeercert(binary_form=True)
    except Exception:  # noqa: BLE001
        der = None
    if der and hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(ssl.DER_cert_to_PEM_cert(der))
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
            for typ, val in decoded.get("subjectAltName", ()):
                if typ == "DNS":
                    names.append(val.lower())
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    return names


def _cert_matches(ip: str, port: int, host: str,
                  connect_timeout: Optional[int] = None) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock_timeout = connect_timeout if connect_timeout else 8
    with socket.create_connection((ip, port), timeout=sock_timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            names = _cert_san_names(ssock)
    return any(san_matches_host(n, host) for n in names)


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
def classify_findings(collector: Collector, db: ProviderDB, use_asn: bool,
                      workers: int = 16) -> Tuple[
                          List[Tuple[str, str, Finding]], List[Tuple[str, str, Finding]]]:
    """Split collected IPs into (origins, shields).

    Cymru ASN lookups can stall per-IP on filtered networks, so run them
    concurrently instead of sequentially. This phase only talks to DNS (no
    target contact), so callers pass --api-workers rather than -w.
    """
    origins: List[Tuple[str, str, Finding]] = []
    shields: List[Tuple[str, str, Finding]] = []

    def _one(item):
        ip, f = item
        return classify_ip(ip, db, use_asn=use_asn)

    items = list(collector.findings.items())
    with cf.ThreadPoolExecutor(max_workers=min(max(workers, 1), 16)) as ex:
        for (ip, f), (provider, is_cdn, method) in zip(
                items, ex.map(_one, items)):
            if is_cdn:
                shields.append((provider, method, f))
            else:
                origins.append((provider, method, f))
    return origins, shields


def apex_of(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co", "com", "net", "org", "gov", "edu", "ac", "go", "or", "my", "id"}
    if len(parts) >= 3 and parts[-2] in two and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _norm_scope(value: str) -> str:
    s = (value or "").strip().lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    return s.strip(".")


def parse_scopes(values: Optional[List[str]]) -> List[str]:
    """--scope values: repeatable and/or comma separated, normalized + deduped."""
    scopes: List[str] = []
    for raw in values or []:
        for part in str(raw).split(","):
            s = _norm_scope(part)
            if s and s not in scopes:
                scopes.append(s)
    return scopes


def host_in_scope(host: str, scopes: List[str]) -> bool:
    if not scopes:
        return True
    h = (host or "").strip().lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in scopes)


def discovery_domains(hosts: List[str],
                      scopes: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Domains for per-apex sources + hosts whose apex_of() is a broader domain."""
    if scopes:
        return list(scopes), []
    domains = sorted({apex_of(h) for h in hosts})
    collapsed = [(h, apex_of(h)) for h in hosts if apex_of(h) != h]
    return domains, collapsed


def _prune_out_of_scope(collector: Collector, scopes: List[str]) -> int:
    """Drop findings whose every known host is outside --scope; trim host sets.

    Findings with no host attribution are kept: with --scope the queries
    themselves were scoped, so such an IP still came from an in-scope query.
    """
    if not scopes:
        return 0
    dropped = 0
    kept: Dict[str, Finding] = {}
    for ip, f in collector.findings.items():
        if not f.hosts:
            kept[ip] = f
            continue
        in_scope_hosts = {h for h in f.hosts if host_in_scope(h, scopes)}
        if not in_scope_hosts:
            dropped += 1
            continue
        f.hosts = in_scope_hosts
        kept[ip] = f
    collector.findings = kept
    return dropped


def gather(hosts: List[str], keys: Dict[str, Optional[str]], workers: int,
           enabled: Set[str], scopes: Optional[List[str]] = None,
           api_workers: Optional[int] = None) -> Collector:
    """Collect candidate IPs.

    `workers` (-w) bounds concurrent requests to the target / candidate IPs;
    `api_workers` (--api-workers) bounds the history + DNS source phase, which
    never touches the target and should not be throttled by a rate-limited -w.
    """
    scopes = scopes or []
    api_workers = max(1, api_workers if api_workers is not None else workers)
    collector = Collector()
    if scopes:
        kept_hosts = [h for h in hosts if host_in_scope(h, scopes)]
        if len(kept_hosts) != len(hosts):
            log(f"--scope: ignored {len(hosts) - len(kept_hosts)} input host(s) "
                f"outside {', '.join(scopes)}", "warn")
        hosts = kept_hosts
        if not hosts:
            log("no input host is inside --scope; nothing to gather", "warn")
            return collector
    apexes, collapsed = discovery_domains(hosts, scopes)
    if collapsed:
        h, apex = collapsed[0]
        log(f"apex_of() collapsed {len(collapsed)}/{len(hosts)} host(s) to a shorter "
            f"apex (e.g. {h} -> {apex}); per-apex sources will query that apex. "
            f"Use --scope <suffix> to keep discovery inside the target subtree.", "warn")
    extra_hosts: Set[str] = set()

    label = "scope suffix(es)" if scopes else "apex domain(s)"
    log(f"{len(hosts)} hosts across {len(apexes)} {label}", "info")

    with cf.ThreadPoolExecutor(max_workers=api_workers) as ex:
        futs = []
        for h in hosts:
            if "dns" in enabled:
                futs.append(ex.submit(src_resolve, h, collector))
            if "hackertarget" in enabled:
                futs.append(ex.submit(src_hackertarget, h, collector))
            if "securitytrails" in enabled and keys.get("securitytrails"):
                futs.append(ex.submit(src_securitytrails, h, keys["securitytrails"], collector))
            if "virustotal" in enabled and keys.get("virustotal"):
                futs.append(ex.submit(src_virustotal, h, keys["virustotal"], collector))
        for _ in cf.as_completed(futs):
            pass
    log(f"per-host sources done -> {len(collector.findings)} raw IPs", "src")

    with cf.ThreadPoolExecutor(max_workers=min(api_workers, 8)) as ex:
        futs = []
        for d in apexes:
            if "crtsh" in enabled:
                futs.append(ex.submit(src_crtsh, d, collector, extra_hosts))
            if "shodan" in enabled and keys.get("shodan"):
                futs.append(ex.submit(src_shodan_domain, d, keys["shodan"], collector))
            if "censys" in enabled and keys.get("censys"):
                futs.append(ex.submit(src_censys, d, keys["censys"], collector))
            if "certspotter" in enabled:
                futs.append(ex.submit(src_certspotter, d, keys.get("certspotter"), collector, extra_hosts))
            if "dnsdumpster" in enabled and keys.get("dnsdumpster"):
                futs.append(ex.submit(src_dnsdumpster, d, keys["dnsdumpster"], collector))
        for _ in cf.as_completed(futs):
            pass
    log(f"per-apex sources done -> {len(collector.findings)} IPs, "
        f"{len(extra_hosts)} extra hosts from CT", "src")

    new_hosts = [h for h in extra_hosts
                 if h not in set(hosts) and host_in_scope(h, scopes)]
    out_of_scope_ct = len(extra_hosts) - len(new_hosts)
    if out_of_scope_ct and scopes:
        log(f"--scope: dropped {out_of_scope_ct} CT host(s) outside "
            f"{', '.join(scopes)}", "warn")
    if new_hosts and "dns" in enabled:
        with cf.ThreadPoolExecutor(max_workers=api_workers) as ex:
            list(cf.as_completed([ex.submit(src_resolve, h, collector) for h in new_hosts]))
        log(f"resolved {len(new_hosts)} CT-discovered hosts", "src")

    dropped = _prune_out_of_scope(collector, scopes)
    if dropped:
        log(f"--scope: dropped {dropped} candidate IP(s) only seen on out-of-scope hosts",
            "warn")

    return collector


def run_known_origins(args, target: str, known_ips: List[str]) -> int:
    """Verify a KNOWN candidate origin-IP list against one target host.

    Skips discovery entirely: each IP is probed directly with
    Host: <target> and scored against the target's own baseline.
    This is the WAF-bypass workflow: find which known origin IP(s)
    actually serve the host, then retry blocked payloads via direct IP.
    """
    if requests is not None:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore
        except Exception:  # noqa: BLE001
            pass

    folder = args.outdir or str(Path("out") / target)
    args.outdir = folder

    db = build_provider_db(offline=args.offline)
    collector = Collector()
    for ip in known_ips:
        collector.add(ip, target, "known-list")
    log(f"{len(collector.findings)} known origin IP(s) to verify against {target}", "info")

    origins, shields = classify_findings(
        collector, db, use_asn=not args.no_asn, workers=args.api_workers)

    tbase = get_baseline(target, connect_timeout=args.connect_timeout)
    if not tbase.get("status"):
        log(f"could not fetch a baseline for {target} (site down / blocked?) -- "
            f"scores will be weaker", "warn")

    # Verify EVERY supplied IP (origins and shields alike): the user
    # explicitly asked "is this host served from these IPs?".
    to_probe = origins + shields
    verified: Dict[str, Tuple[int, str, str]] = {}
    log(f"probing {len(to_probe)} candidate IP(s) with Host: {target} ...", "info")
    with cf.ThreadPoolExecutor(max_workers=min(args.workers, 12)) as ex:
        def _dot(item):
            _p, _m, f = item
            return f.ip, verify_origin(f.ip, target, tbase,
                                       timeout=args.verify_timeout,
                                       probe_path=args.probe_path,
                                       connect_timeout=args.connect_timeout)
        for ip, res in ex.map(_dot, to_probe):
            verified[ip] = res
    origins.sort(key=lambda t: verified.get(t[2].ip, (0, "", "UNKNOWN"))[0], reverse=True)

    print_report(origins, shields, verified, args)
    write_outputs(origins, shields, verified, args)
    n_access = sum(1 for _, _, f in to_probe if verified.get(f.ip, (0, "", ""))[2] == "ACCESS")
    if n_access:
        log(f"{n_access} candidate IP(s) SERVE {target} directly -- "
            f"retry blocked payloads via direct IP (Host: {target}). "
            f"See {Path(folder) / 'accessible_origin.txt'}", "ok")
    else:
        log(f"no candidate IP serves {target} directly (all BLOCKED/DENIED/REDIRECT) -- "
            f"origin not bypassable via this list", "warn")
    return 0


def run(args) -> int:
    if requests is not None:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore
        except Exception:  # noqa: BLE001
            pass

    hosts = []
    seen = set()
    for raw in Path(args.input).read_text(encoding="utf-8", errors="replace").splitlines():
        h = raw.strip().lower().rstrip(".")
        h = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0]
        if h and h not in seen and "." in h:
            seen.add(h); hosts.append(h)
    if not hosts:
        log("no valid hosts in input file", "err")
        return 2

    target = (args.target or "").strip().lower().rstrip(".") or None
    scopes = parse_scopes(getattr(args, "scope", None))
    if args.outdir:
        folder = args.outdir
    else:
        if target:
            name = target
        elif scopes:
            name = scopes[0]
        else:
            name = Counter(apex_of(h) for h in hosts).most_common(1)[0][0]
        folder = str(Path("out") / name)
    args.outdir = folder

    keys = load_keys(Path(args.config) if args.config else None)
    active = [k for k in ("securitytrails", "virustotal", "shodan", "censys",
                          "certspotter", "dnsdumpster") if keys.get(k)]
    log(f"API keys available for: {', '.join(active) or 'none (free sources only)'}", "info")

    enabled = set(args.sources.split(",")) if args.sources else {
        "dns", "crtsh", "hackertarget", "securitytrails", "virustotal",
        "shodan", "censys", "certspotter", "dnsdumpster",
    }

    global _API_CACHE_ON, _API_CACHE_TTL
    _API_CACHE_ON = not args.no_cache
    _API_CACHE_TTL = args.cache_ttl
    if not _API_CACHE_ON:
        log("API response cache disabled (--no-cache)", "info")

    db = build_provider_db(offline=args.offline)
    collector = gather(hosts, keys, args.workers, enabled, scopes=scopes,
                       api_workers=args.api_workers)

    origins, shields = classify_findings(
        collector, db, use_asn=not args.no_asn, workers=args.api_workers)

    origins.sort(key=lambda t: (t[0] != "Unknown", t[0]))
    shields.sort(key=lambda t: t[0])

    verified: Dict[str, Tuple[int, str, str]] = {}
    do_verify = args.verify or bool(target)
    if do_verify and origins:
        if target:
            log(f"confirming origin of {target}: probing {len(origins)} candidate IP(s) "
                f"with Host: {target} ...", "info")
            tbase = get_baseline(target, connect_timeout=args.connect_timeout)
            if not tbase.get("status"):
                log(f"could not fetch a baseline for {target} (site down / blocked?) -- "
                    f"scores will be weaker", "warn")
            with cf.ThreadPoolExecutor(max_workers=min(args.workers, 12)) as ex:
                def _dot(item):
                    _p, _m, f = item
                    return f.ip, verify_origin(f.ip, target, tbase,
                                               timeout=args.verify_timeout,
                                               probe_path=args.probe_path,
                                               connect_timeout=args.connect_timeout)
                for ip, res in ex.map(_dot, origins):
                    verified[ip] = res
        else:
            log(f"verifying {len(origins)} origin candidates (direct-IP probe)...", "info")
            baselines: Dict[str, dict] = {}
            with cf.ThreadPoolExecutor(max_workers=min(args.workers, 12)) as ex:
                def _do(item):
                    provider, method, f = item
                    host = sorted(f.hosts)[0] if f.hosts else None
                    if not host:
                        return f.ip, (0, "no-host", "UNKNOWN")
                    if host not in baselines:
                        baselines[host] = get_baseline(
                            host, connect_timeout=args.connect_timeout)
                    # An IP that IS the host's current A/AAAA record trivially
                    # "serves" it; that is not a hidden origin. Keep the probe
                    # (reachability is still useful) but say so and keep it out
                    # of accessible_origin.txt.
                    res = verify_origin(f.ip, host, baselines[host],
                                        timeout=args.verify_timeout,
                                        probe_path=args.probe_path,
                                        connect_timeout=args.connect_timeout)
                    if (f.ip, host) in collector.dns_hosts:
                        score, note, verdict = res
                        note = "current-dns" if not note else f"current-dns,{note}"
                        res = (score, note, verdict)
                    return f.ip, res
                for ip, res in ex.map(_do, origins):
                    verified[ip] = res
            n_cdns = sum(1 for v in verified.values() if "current-dns" in v[1])
            if n_cdns:
                log(f"{n_cdns} candidate(s) are the host's current DNS record "
                    f"(note: current-dns) -- not treated as hidden origins",
                    "warn")
        origins.sort(key=lambda t: verified.get(t[2].ip, (0, "", "UNKNOWN"))[0], reverse=True)

    print_report(origins, shields, verified, args)
    write_outputs(origins, shields, verified, args)
    return 0


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
VERDICT_META = {
    "ACCESS":   (C.G + C.BOLD,  "direct-IP probe works & matches the target -- likely the REAL origin (wifi bypass WAF via HA or Host header)", 0),
    "REACHED":  (C.Cy + C.BOLD, "server responds on direct IP but content differs from target (maybe a different vhost on the same box)", 1),
    "REDIRECT": (C.Y + C.BOLD,  "direct-IP probe redirects elsewhere -- usually NOT the origin", 2),
    "DENIED":   (C.Y + C.BOLD,  "direct-IP access blocked (403/WAF short-circuit)", 3),
    "BLOCKED":  (C.GR + C.BOLD, "no response on direct IP (firewall drop, timeout) -- origin not directly reachable", 4),
    "UNKNOWN":  (C.GR + C.BOLD, "not verified (no --verify)", 5),
}


def print_report(origins, shields, verified, args) -> None:
    print()
    print(C.wrap(C.BOLD, "=" * 72))
    print(C.wrap(C.BOLD, " ipreal-hunter results"))
    print(C.wrap(C.BOLD, "=" * 72))

    if verified:
        groups: Dict[str, list] = {}
        for provider, method, f in origins:
            v = verified.get(f.ip, (0, "", "UNKNOWN"))[2]
            groups.setdefault(v, []).append((provider, method, f))
        for vname, (head, desc, _order) in sorted(
                VERDICT_META.items(), key=lambda kv: kv[1][2]):
            entries = groups.get(vname, [])
            if not entries:
                continue
            entries.sort(key=lambda t: verified.get(t[2].ip, (0, "", ""))[0], reverse=True)
            print(C.wrap(head, f"\n[{vname} ORIGIN] {len(entries)}"))
            print(C.wrap(C.GR, f"  {desc}\n"))
            for provider, method, f in entries:
                score, note = verified.get(f.ip, (0, "", ""))[:2]
                col = C.G if score >= 70 else (C.Y if score >= 30 else C.GR)
                badge = "  " + C.wrap(col, f"conf={score:>3} ({note})")
                hosts = ", ".join(sorted(f.hosts)[:3])
                more = f" +{len(f.hosts)-3}" if len(f.hosts) > 3 else ""
                print(f"  {C.wrap(C.G, f.ip.ljust(16))} {C.wrap(C.Cy, provider.ljust(26))}{badge}")
                srcs = ",".join(sorted(f.sources))
                print(f"      {C.wrap(C.GR, f'{hosts}{more}  [{srcs}]')}")
    else:
        print(C.wrap(C.G + C.BOLD, f"\n[ORIGIN CANDIDATES] {len(origins)}"))
        print(C.wrap(C.GR, "  (real/hosting IPs -- investigate these; NOT behind a CDN/WAF. Use --verify for filtering.)\n"))
        for provider, method, f in origins:
            hosts = ", ".join(sorted(f.hosts)[:3])
            more = f" +{len(f.hosts)-3}" if len(f.hosts) > 3 else ""
            print(f"  {C.wrap(C.G, f.ip.ljust(16))} {C.wrap(C.Cy, provider.ljust(26))}")
            srcs = ",".join(sorted(f.sources))
            print(f"      {C.wrap(C.GR, f'{hosts}{more}  [{srcs}]')}")

    print(C.wrap(C.R + C.BOLD, f"\n[CDN / WAF / PROXY] {len(shields)}"))
    print(C.wrap(C.GR, "  (shields in front of the target -- these are NOT the origin)\n"))
    grouped: Dict[str, int] = {}
    for provider, method, f in shields:
        base = provider.split(" (AS")[0]
        grouped[base] = grouped.get(base, 0) + 1
    for prov, cnt in sorted(grouped.items(), key=lambda x: -x[1]):
        print(f"  {C.wrap(C.R, str(cnt).rjust(4))}  {prov}")
    print()


def write_outputs(origins, shields, verified, args) -> None:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    get_v = lambda f: verified.get(f.ip, (0, "", "UNKNOWN"))

    def _is_current_dns(f) -> bool:
        return "current-dns" in (get_v(f)[1] or "")

    sel = [f for _, _, f in origins if (not verified) or get_v(f)[2] == "ACCESS" or get_v(f)[0] >= args.min_score]
    # An IP that is the host's own current A/AAAA record is not a hidden
    # origin: keep it visible (it IS reachable) but out of the two
    # "origin you can pivot through via Host:" lists.
    acc = [f for _, _, f in origins
           if get_v(f)[2] == "ACCESS" and not _is_current_dns(f)]
    reached = [f for _, _, f in origins
               if get_v(f)[2] in ("ACCESS", "REACHED") and not _is_current_dns(f)]

    for name, items in (("origin_candidates.txt", sel),
                        ("accessible_origin.txt", acc),
                        ("reachable_origin.txt", reached)):
        if not items:
            continue
        with (outdir / name).open("w", encoding="utf-8") as fh:
            for f in items:
                fh.write(f.ip + "\n")
        log(f"written: {outdir / name}", "ok")

    with (outdir / "cdn_waf_ips.txt").open("w", encoding="utf-8") as fh:
        for _, _, f in shields:
            fh.write(f.ip + "\n")
    log(f"written: {outdir / 'cdn_waf_ips.txt'}", "ok")

    report = {
        "tool": "ipreal-hunter", "version": VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "origin_candidates": [
            {
                "ip": f.ip, "provider": provider, "method": method,
                "hosts": sorted(f.hosts), "sources": sorted(f.sources),
                "confidence": get_v(f)[0],
                "confidence_note": get_v(f)[1],
                "verdict": get_v(f)[2],
            } for provider, method, f in origins
        ],
        "cdn_waf": [
            {
                "ip": f.ip, "provider": provider, "method": method,
                "hosts": sorted(f.hosts), "sources": sorted(f.sources),
            } for provider, method, f in shields
        ],
    }
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"written: {outdir / 'report.json'}", "ok")


# ----------------------------------------------------------------------------
# Self-test (offline, no network) -- verifies classification logic
# ----------------------------------------------------------------------------
def self_test() -> int:
    log("running offline self-test (classification logic)...", "info")
    db = ProviderDB()
    db.add("104.16.0.0/13", "Cloudflare", True)
    db.add("151.101.0.0/16", "Fastly", True)
    db.add("192.0.2.0/24", "AWS", False)
    cases = [
        ("104.16.132.229", True),
        ("151.101.1.69", True),
        ("192.0.2.55", False),
        ("203.0.113.9", False),
    ]
    ok = True
    for ip, expect_cdn in cases:
        provider, is_cdn, method = classify_ip(ip, db, use_asn=False)
        status = "OK" if is_cdn == expect_cdn else "FAIL"
        if is_cdn != expect_cdn:
            ok = False
        print(f"  [{status}] {ip:16} -> {provider:14} cdn={is_cdn} ({method})")
    assert apex_of("a.b.example.com") == "example.com", apex_of("a.b.example.com")
    assert apex_of("foo.example.co.id") == "example.co.id", apex_of("foo.example.co.id")
    assert _valid_public_ip("8.8.8.8") and not _valid_public_ip("10.0.0.1")
    # --origin-ips loader: bare IP / host:port / URL forms, dedup, skip garbage
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("1.2.3.4\n4.3.2.1:8443\nhttps://5.6.7.8/x\n# comment\n\n10.0.0.5\nnot-an-ip\n1.2.3.4\n")
        tf_path = tf.name
    try:
        ips, skipped = load_known_ips(tf_path)
        assert ips == ["1.2.3.4", "4.3.2.1", "5.6.7.8"], ips
        assert skipped == 3, skipped  # private + garbage + duplikat
        assert parse_known_ip_line("9.9.9.9") == "9.9.9.9"
        assert parse_known_ip_line("  9.9.9.9:443 ") == "9.9.9.9"
        assert parse_known_ip_line("10.1.2.3") is None
        assert parse_known_ip_line("# komen") is None
        assert parse_known_ip_line("") is None
        print(f"  [OK] load_known_ips -> {ips} (skipped={skipped})")
    except AssertionError:
        ok = False
        print("  [FAIL] load_known_ips")
    finally:
        os.unlink(tf_path)
    # api_fetch cache: roundtrip + TTL-expiry + non-200 tak dicache
    global _API_CACHE_ON, _API_CACHE_TTL, _API_CACHE_DIR
    import shutil as _shutil
    _t2d = tempfile.mkdtemp(prefix="ipreal-cache-test-")
    _old_cache = (_API_CACHE_ON, _API_CACHE_TTL, _API_CACHE_DIR)
    _real_http_get = globals()["http_get"]
    _calls = {"n": 0}

    def _fake_http_get(url, timeout=20, headers=None, params=None):
        _calls["n"] += 1

        class _R:
            status_code = 200
            text = '{"ok": true}'

        return _R()

    _API_CACHE_ON, _API_CACHE_TTL, _API_CACHE_DIR = True, 3600, Path(_t2d)
    globals()["http_get"] = _fake_http_get
    try:
        _r1 = api_fetch("selftest", "https://x.invalid/a", timeout=5)
        _r2 = api_fetch("selftest", "https://x.invalid/a", timeout=5)
        assert _calls["n"] == 1 and _r1.text == _r2.text == '{"ok": true}', (_calls["n"], _r1, _r2)
        _API_CACHE_TTL = 0  # paksa expired -> fetch ulang
        _r3 = api_fetch("selftest", "https://x.invalid/a", timeout=5)
        assert _calls["n"] == 2, _calls
        print("  [OK] api cache roundtrip + ttl-expiry")
    except AssertionError as _e:
        ok = False
        print(f"  [FAIL] api cache: {_e}")
    finally:
        globals()["http_get"] = _real_http_get
        _API_CACHE_ON, _API_CACHE_TTL, _API_CACHE_DIR = _old_cache
        _shutil.rmtree(_t2d, ignore_errors=True)
    # verify early-exit: https ACCESS -> http diskip (1 probe); https gagal -> http tetap jalan
    if requests is not None:
        _real_get = requests.get
        _seen_urls = []

        class _FakeResp:
            def __init__(self, status=200, body=b"<html><title>Acme</title>ok</html>"):
                self.status_code = status
                self.content = body
                self.text = body.decode("utf-8", "replace")
                self.headers = {}
                self.is_redirect = False
                self.is_permanent_redirect = False

        def _fake_get(url, **kw):
            _seen_urls.append(url)
            if ":443/" in url:
                return _FakeResp(200)
            if ":80/" in url and _fake_get.fail80:
                raise ConnectionError("refused")
            return _FakeResp(403, b"forbidden")

        _fake_get.fail80 = False
        _tbase = {"title": "Acme", "len": len(b"<html><title>Acme</title>ok</html>"),
                  "status": 200, "server": None}
        requests.get = _fake_get
        try:
            _seen_urls.clear()
            _sc, _nt, _vd = verify_origin("127.0.0.1", "acme.invalid", _tbase, timeout=5)
            assert _vd == "ACCESS" and len(_seen_urls) == 1 and ":443/" in _seen_urls[0], (_vd, _seen_urls)
            print("  [OK] verify early-exit on ACCESS (http skipped)")
            _fake_get.fail80 = True
            _seen_urls.clear()

            def _fake_get2(url, **kw):
                _seen_urls.append(url)
                if ":443/" in url:
                    raise ConnectionError("down")
                # body jauh beda (500B vs 33B) agar body-size-match tak ikut tembak
                return _FakeResp(403, b"x" * 500)

            requests.get = _fake_get2
            _sc2, _nt2, _vd2 = verify_origin("127.0.0.1", "acme.invalid", _tbase, timeout=5)
            assert _vd2 == "DENIED" and len(_seen_urls) == 2, (_vd2, _seen_urls)
            print("  [OK] verify tetap probe http saat https gagal")
        except AssertionError as _e:
            ok = False
            print(f"  [FAIL] verify early-exit: {_e}")
        finally:
            requests.get = _real_get

    if requests is None:
        print("  [SKIP] verify/concurrency/scope checks (requests missing)")
        print(C.wrap(C.G if ok else C.R, f"\nself-test {'PASSED' if ok else 'FAILED'}"))
        return 0 if ok else 1

    def _section(name, fn):
        nonlocal ok
        try:
            fn()
            print(f"  [OK] {name}")
        except AssertionError as _e:
            ok = False
            print(f"  [FAIL] {name}: {_e}")
        except Exception as _e:  # noqa: BLE001
            ok = False
            print(f"  [FAIL] {name}: {type(_e).__name__}: {_e}")

    # --scope: keep discovery in the target subtree instead of collapsing to apex
    def _check_scope():
        assert apex_of("kalsel.web.bps.go.id") == "bps.go.id"
        sc = parse_scopes(["kalsel.web.bps.go.id"])
        assert sc == ["kalsel.web.bps.go.id"], sc
        assert parse_scopes(["A.TEST, *.b.test", "b.test"]) == ["a.test", "b.test"]
        assert host_in_scope("kalsel.web.bps.go.id", sc)
        assert host_in_scope("x.kalsel.web.bps.go.id", sc)
        assert not host_in_scope("avior.bps.go.id", sc)
        assert not host_in_scope("kalsel.web.bps.go.id.evil.test", sc)
        dom, collapsed = discovery_domains(["kalsel.web.bps.go.id"], sc)
        assert dom == ["kalsel.web.bps.go.id"] and collapsed == [], (dom, collapsed)
        dom, collapsed = discovery_domains(["kalsel.web.bps.go.id"], [])
        assert dom == ["bps.go.id"], dom            # legacy: full registered apex
        assert collapsed == [("kalsel.web.bps.go.id", "bps.go.id")], collapsed

        col = Collector()
        col.add("8.8.8.8", "leak.bps.go.id", "crtsh")
        col.add("1.1.1.1", "x.kalsel.web.bps.go.id", "dns")
        col.add("8.8.4.4", "leak.bps.go.id", "dns")
        col.add("8.8.4.4", "x.kalsel.web.bps.go.id", "dns")
        dropped = _prune_out_of_scope(col, sc)
        assert dropped == 1, dropped
        assert set(col.findings) == {"1.1.1.1", "8.8.4.4"}, col.findings
        assert col.findings["8.8.4.4"].hosts == {"x.kalsel.web.bps.go.id"}

        calls = {"crtsh": [], "resolve": []}
        real_fn = {n: globals()[n] for n in ("src_crtsh", "src_resolve")}

        def fake_crtsh(domain, collector_, extra_hosts):
            calls["crtsh"].append(domain)
            extra_hosts.update({"in.kalsel.web.bps.go.id", "leak.bps.go.id"})

        def fake_resolve(host, collector_):
            calls["resolve"].append(host)
            ip = {"kalsel.web.bps.go.id": "203.123.60.40",
                  "in.kalsel.web.bps.go.id": "203.123.60.41",
                  "leak.bps.go.id": "198.41.0.4"}.get(host, "9.9.9.9")
            collector_.add(ip, host, "dns")
            collector_.dns_hosts.add((ip, host))

        globals()["src_crtsh"] = fake_crtsh
        globals()["src_resolve"] = fake_resolve
        try:
            col = gather(["kalsel.web.bps.go.id", "avior.bps.go.id"], {}, 1,
                         {"dns", "crtsh"}, scopes=sc, api_workers=2)
            scoped_calls = {k: list(v) for k, v in calls.items()}
            calls["crtsh"].clear(); calls["resolve"].clear()
            legacy = gather(["kalsel.web.bps.go.id"], {}, 1,
                            {"dns", "crtsh"}, scopes=[], api_workers=2)
        finally:
            for n, fn in real_fn.items():
                globals()[n] = fn
        assert scoped_calls["crtsh"] == ["kalsel.web.bps.go.id"], scoped_calls
        assert "avior.bps.go.id" not in scoped_calls["resolve"], scoped_calls
        assert "leak.bps.go.id" not in scoped_calls["resolve"], scoped_calls
        assert set(col.findings) == {"203.123.60.40", "203.123.60.41"}, col.findings
        assert calls["crtsh"] == ["bps.go.id"], calls          # legacy unchanged
        assert "leak.bps.go.id" in calls["resolve"], calls     # legacy keeps CT host
        assert "198.41.0.4" in legacy.findings

    _section("--scope pins per-apex queries + drops out-of-scope hosts", _check_scope)

    # --api-workers governs the no-target source phase; -w governs verify
    def _check_pools():
        import threading as _th
        state = {"cur": 0, "max": 0}
        lock = _th.Lock()
        real_resolve = globals()["src_resolve"]

        def slow_resolve(host, collector_):
            with lock:
                state["cur"] += 1
                state["max"] = max(state["max"], state["cur"])
            time.sleep(0.03)
            with lock:
                state["cur"] -= 1

        hosts = [f"h{i}.kalsel.web.bps.go.id" for i in range(24)]
        globals()["src_resolve"] = slow_resolve
        try:
            gather(hosts, {}, 1, {"dns"}, scopes=["kalsel.web.bps.go.id"], api_workers=8)
            api_max = state["max"]
            state["cur"] = state["max"] = 0
            gather(hosts, {}, 8, {"dns"}, scopes=["kalsel.web.bps.go.id"], api_workers=1)
            api_max_one = state["max"]
        finally:
            globals()["src_resolve"] = real_resolve
        assert api_max >= 3, api_max           # -w 1 does NOT serialize sources
        assert api_max_one == 1, api_max_one   # api_workers decides

        d = tempfile.mkdtemp(prefix="ipreal-pool-test-")
        inp = os.path.join(d, "subs.txt")
        Path(inp).write_text("".join(f"h{i}.kalsel.web.bps.go.id\n" for i in range(8)),
                             encoding="utf-8")
        col = Collector()
        for i in range(8):
            col.add(f"45.33.32.{i + 1}", f"h{i}.kalsel.web.bps.go.id", "dns")
        vstate = {"cur": 0, "max": 0}

        class _R:
            status_code = 200
            content = b"<html><title>Acme</title></html>"
            text = "<html><title>Acme</title></html>"
            headers = {}
            is_redirect = False
            is_permanent_redirect = False

        def fake_get(url, **kw):
            with lock:
                vstate["cur"] += 1
                vstate["max"] = max(vstate["max"], vstate["cur"])
            time.sleep(0.05)
            with lock:
                vstate["cur"] -= 1
            return _R()

        args = build_parser().parse_args([
            "-i", inp, "-o", os.path.join(d, "out"), "-c", os.path.join(d, "no.yaml"),
            "-w", "2", "--api-workers", "8", "--verify", "--offline", "--no-asn",
            "--sources", "dns", "--no-cache"])
        saved = {n: globals()[n] for n in ("gather", "print_report", "_cert_matches")}
        globals()["gather"] = lambda *a, **k: col
        globals()["print_report"] = lambda *a, **k: None
        globals()["_cert_matches"] = lambda *a, **k: False
        requests.get = fake_get
        try:
            run(args)
        finally:
            for n, fn in saved.items():
                globals()[n] = fn
            requests.get = _real_get
        assert vstate["max"] == 2, vstate["max"]   # verify follows -w, not api-workers

    _section("--api-workers (sources) vs -w (verify) concurrency", _check_pools)

    # connect timeout: one fast-failing probe, never verify-timeout x 2
    def _check_timeouts():
        seen = []

        def hang_get(url, **kw):
            seen.append((url, kw.get("timeout")))
            time.sleep(0.4)
            raise requests.exceptions.ConnectTimeout("connect timed out")

        requests.get = hang_get
        try:
            t0 = time.monotonic()
            sc, note, verdict = verify_origin(
                "203.123.60.49", "kalsel.web.bps.go.id", {},
                timeout=12, connect_timeout=1)
            elapsed = time.monotonic() - t0
        finally:
            requests.get = _real_get
        assert seen and len(seen) == 1, seen          # http not retried
        assert seen[0][1] == (1, 12), seen            # (connect, read)
        assert sc == 0 and verdict == "BLOCKED", (sc, verdict)
        assert "connect-timeout" in note, note
        assert elapsed < 0.9, elapsed                 # one connect budget, not 2x

        base_calls = []

        def hard_drop(url, **kw):
            base_calls.append(url)
            raise requests.exceptions.ConnectTimeout("drop")

        requests.get = hard_drop
        try:
            base = get_baseline("kalsel.web.bps.go.id", timeout=12, connect_timeout=1)
        finally:
            requests.get = _real_get
        assert len(base_calls) == 1 and base["status"] is None, base_calls

        def read_slow(url, **kw):
            if url.startswith("https"):
                raise requests.exceptions.ReadTimeout("slow")
            return _FakeResp(200)

        requests.get = read_slow
        try:
            base2 = get_baseline("kalsel.web.bps.go.id", timeout=12, connect_timeout=1)
        finally:
            requests.get = _real_get
        assert base2["status"] == 200, base2          # read timeout still tries http

        real_cc = socket.create_connection

        def slow_connect(addr, timeout=None, **kw):
            time.sleep(timeout or 0)
            raise TimeoutError("timed out")

        socket.create_connection = slow_connect
        try:
            t0 = time.monotonic()
            try:
                hit = _cert_matches("203.123.60.49", 443, "kalsel.web.bps.go.id",
                                    connect_timeout=1)
            except (TimeoutError, OSError):
                hit = None   # connect failure is fine; we only time it
            cert_elapsed = time.monotonic() - t0
        finally:
            socket.create_connection = real_cc
        assert hit is not True, hit
        assert 0.9 <= cert_elapsed < 1.8, cert_elapsed   # honours --connect-timeout, not 8s

    _section("connect/read timeout split + fast-fail", _check_timeouts)

    # current-dns (no -t): honest note, kept out of hidden-origin lists
    def _check_current_dns():
        d = tempfile.mkdtemp(prefix="ipreal-cdns-test-")
        inp = os.path.join(d, "subs.txt")
        host = "app.kalsel.web.bps.go.id"
        Path(inp).write_text(host + "\n", encoding="utf-8")
        col = Collector()
        col.add("8.8.8.8", host, "dns")
        col.dns_hosts.add(("8.8.8.8", host))
        col.add("1.1.1.1", host, "virustotal")

        def fake_get2(url, **kw):
            return _FakeResp(200)

        saved = {n: globals()[n] for n in ("gather", "print_report", "_cert_matches")}
        globals()["gather"] = lambda *a, **k: col
        globals()["print_report"] = lambda *a, **k: None
        globals()["_cert_matches"] = lambda *a, **k: False
        requests.get = fake_get2
        try:
            out = os.path.join(d, "out")
            args = build_parser().parse_args([
                "-i", inp, "-o", out, "-c", os.path.join(d, "no.yaml"),
                "--verify", "--offline", "--no-asn", "--sources", "dns", "--no-cache"])
            run(args)
            acc = (Path(out) / "accessible_origin.txt").read_text().split()
            reached = (Path(out) / "reachable_origin.txt").read_text().split()
            sel = (Path(out) / "origin_candidates.txt").read_text().split()
            rep = json.loads((Path(out) / "report.json").read_text())
            args_t = build_parser().parse_args([
                "-i", inp, "-o", os.path.join(d, "out_t"), "-t", host,
                "-c", os.path.join(d, "no.yaml"), "--offline", "--no-asn",
                "--sources", "dns", "--no-cache"])
            args_t.outdir = os.path.join(d, "out_t")
            run(args_t)
            rep_t = json.loads((Path(d, "out_t") / "report.json").read_text())
        finally:
            for n, fn in saved.items():
                globals()[n] = fn
            requests.get = _real_get
        notes = {e["ip"]: e["confidence_note"] for e in rep["origin_candidates"]}
        assert acc == ["1.1.1.1"], acc                 # hidden origin only
        assert reached == ["1.1.1.1"], reached
        assert "8.8.8.8" in sel and "1.1.1.1" in sel   # still visible as reachable
        assert notes["8.8.8.8"].startswith("current-dns"), notes
        assert "current-dns" not in notes["1.1.1.1"], notes
        verdicts = {e["ip"]: e["verdict"] for e in rep["origin_candidates"]}
        assert verdicts["8.8.8.8"] == "ACCESS", verdicts   # verdict itself unchanged
        notes_t = {e["ip"]: e["confidence_note"] for e in rep_t["origin_candidates"]}
        assert all("current-dns" not in n for n in notes_t.values()), notes_t

    _section("current-dns marked, excluded from accessible/reachable (no -t)", _check_current_dns)

    # SAN matching: correct wildcard semantics, not "last two labels"
    def _check_san():
        assert not san_matches_host("*.go.id", "kalsel.web.bps.go.id")
        assert san_matches_host("*.kalsel.web.bps.go.id", "kalsel.web.bps.go.id")
        assert san_matches_host("*.kalsel.web.bps.go.id", "a.kalsel.web.bps.go.id")
        assert not san_matches_host("*.kalsel.web.bps.go.id", "a.b.kalsel.web.bps.go.id")
        assert san_matches_host("kalsel.web.bps.go.id", "kalsel.web.bps.go.id")
        assert not san_matches_host("bps.go.id", "kalsel.web.bps.go.id")
        assert san_matches_host("*.bps.go.id", "avior.bps.go.id")
        assert san_matches_host("KALSEL.WEB.BPS.GO.ID.", "kalsel.web.bps.go.id")
        assert san_matches_host("*.web.bps.go.id", "kalsel.web.bps.go.id")
        assert not san_matches_host("*.web.bps.go.id", "a.kalsel.web.bps.go.id")
        assert not san_matches_host("", "x.test")

        import shutil as _sh2
        import subprocess as _sp
        import threading as _th
        if not _sh2.which("openssl"):
            print("  [SKIP] real TLS SAN handshake (openssl not available)")
            return

        def _serve(sans):
            dd = tempfile.mkdtemp()
            key, crt = os.path.join(dd, "k.pem"), os.path.join(dd, "c.pem")
            _sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=selftest",
                     "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans)],
                    check=True, capture_output=True)
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(crt, key)
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            srv.settimeout(0.2)
            stop = _th.Event()

            def _loop():
                while not stop.is_set():
                    try:
                        conn, _ = srv.accept()
                    except (socket.timeout, OSError):
                        continue
                    try:
                        with sctx.wrap_socket(conn, server_side=True) as s:
                            s.recv(16)
                    except Exception:  # noqa: BLE001
                        pass
                    finally:
                        conn.close()
                srv.close()

            _th.Thread(target=_loop, daemon=True).start()
            return srv.getsockname()[1], stop

        p_broad, stop1 = _serve(["*.go.id", "go.id"])
        p_narrow, stop2 = _serve(["*.kalsel.web.bps.go.id"])
        try:
            assert _cert_matches("127.0.0.1", p_broad,
                                 "kalsel.web.bps.go.id", connect_timeout=3) is False
            assert _cert_matches("127.0.0.1", p_narrow,
                                 "kalsel.web.bps.go.id", connect_timeout=3) is True
        finally:
            stop1.set()
            stop2.set()

    _section("TLS SAN matching (wildcard-aware, live handshake on 127.0.0.1)", _check_san)

    print(C.wrap(C.G if ok else C.R, f"\nself-test {'PASSED' if ok else 'FAILED'}"))
    return 0 if ok else 1


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipreal-hunter",
        description="Origin / real-IP candidate hunter for authorized bug bounty & VDP recon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 ipreal-hunter.py -i subs.txt
  python3 ipreal-hunter.py -i subs.txt --verify -o results/
  python3 ipreal-hunter.py -i subs.txt --sources dns,crtsh,hackertarget
  python3 ipreal-hunter.py -t app.target.com -lio out_ip/origin_candidates.txt -o out_ip/app/
  python3 ipreal-hunter.py -t app.target.com -io 1.2.3.4 -o out_ip/app-single/
  python3 ipreal-hunter.py --self-test

REMINDER: only test targets you are explicitly authorized to test.""",
    )
    p.add_argument("-i", "--input", help="file with hosts/subdomains, one per line (e.g. subs.txt)")
    p.add_argument("-t", "--target", help="the specific host you want the origin of, e.g. target.com. Every candidate IP is probed with Host: <target> and scored against <target>'s own baseline. Implies --verify.")
    p.add_argument("-io", "--input-origin", metavar="IP",
                   help="ONE known candidate origin IP to test (e.g. -io 1.2.3.4). "
                        "Skips discovery and directly verifies it against -t/--target. "
                        "Requires -t. Quick check: is this host served from this IP?")
    p.add_argument("-lio", "--list-input-origin", "--origin-ips", metavar="FILE",
                   dest="list_input_origin",
                   help="file with KNOWN candidate origin IPs (one per line, from a previous "
                        "discovery run e.g. out_ip/origin_candidates.txt or "
                        "out_ip/accessible_origin.txt). Skips discovery and "
                        "directly verifies each IP against -t/--target. Requires -t. "
                        "Use case: WAF blocks your payloads -> retest the host against known "
                        "origins to find a direct-IP (WAF-bypass) path.")
    p.add_argument("-o", "--outdir", help="output directory (default: out/<target>, or out/<root-domain> when no -t). auto-created")
    p.add_argument("-c", "--config", help="subfinder provider-config.yaml (default: ~/.config/subfinder/provider-config.yaml)")
    p.add_argument("-w", "--workers", type=int, default=25, help="concurrency for requests that touch the target / candidate IPs (verify + baseline). default: 25")
    p.add_argument("--api-workers", type=int, default=8, help="concurrency for history/DNS sources + Team Cymru classify (no target contact). default: 8")
    p.add_argument("--scope", action="append", metavar="SUFFIX",
                   help="keep discovery inside a host subtree (repeatable and/or comma separated), "
                        "e.g. --scope kalsel.web.bps.go.id. Per-apex sources query SUFFIX instead of "
                        "apex_of(host); CT/extra hosts outside it are ignored. Default: off (legacy: "
                        "query the full registered apex).")
    p.add_argument("--sources", help="comma list to enable (dns,crtsh,hackertarget,securitytrails,virustotal,shodan,censys,certspotter,dnsdumpster)")
    p.add_argument("--verify", action="store_true", help="probe each origin candidate directly and score confidence")
    p.add_argument("--min-score", type=int, default=0, help="only write candidates with confidence >= N to origin_candidates.txt (used with --verify/-t; default 0 = keep all)")
    p.add_argument("--probe-path", default="/", help="path probed during direct-IP verification (default: /)")
    p.add_argument("--verify-timeout", type=int, default=12, help="per-IP verification READ timeout in seconds (default: 12)")
    p.add_argument("--connect-timeout", type=int, default=4,
                   help="TCP connect timeout in seconds for verify/baseline probes; keeps firewall-dropped IPs cheap. default: 4")
    p.add_argument("--no-cache", action="store_true", help="disable API response cache (always re-query history sources)")
    p.add_argument("--cache-ttl", type=int, default=7 * 86400, help="API cache TTL in seconds (default: 604800 = 7d)")
    p.add_argument("--no-asn", action="store_true", help="disable Team Cymru ASN fallback classification")
    p.add_argument("--offline", action="store_true", help="skip live CIDR feeds (ASN-only classification)")
    p.add_argument("--self-test", action="store_true", help="run offline logic self-test and exit")
    p.add_argument("-V", "--version", action="version", version=f"ipreal-hunter {VERSION}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    list_file = getattr(args, "list_input_origin", None)
    if args.input_origin or list_file:
        target = (args.target or "").strip().lower().rstrip(".")
        if not target:
            log("-io/-lio requires -t/--target (which host should these IPs serve?).", "err")
            return 2
        known_ips: List[str] = []
        seen: Set[str] = set()
        skipped = 0
        if args.input_origin:
            ip = parse_known_ip_line(args.input_origin)
            if ip:
                seen.add(ip)
                known_ips.append(ip)
            else:
                log(f"invalid -io/--input-origin value: {args.input_origin!r} "
                    f"(need a public IP)", "err")
                return 2
        if list_file:
            try:
                file_ips, file_skipped = load_known_ips(list_file)
            except OSError as exc:
                log(f"cannot read -lio file: {exc}", "err")
                return 2
            skipped += file_skipped
            for ip in file_ips:
                if ip not in seen:
                    seen.add(ip)
                    known_ips.append(ip)
        if skipped:
            log(f"skipped {skipped} invalid/private line(s) in known-IP input", "warn")
        if not known_ips:
            log("no valid public IPs in known-IP input", "err")
            return 2
        if requests is None:
            log("missing dependency 'requests'. Run: pip install -r requirements.txt", "err")
            return 2
        banner = C.wrap(C.M + C.BOLD, f"ipreal-hunter v{VERSION}") + C.wrap(C.GR, "  authorized recon only")
        print(banner, file=sys.stderr)
        try:
            return run_known_origins(args, target, known_ips)
        except KeyboardInterrupt:
            log("interrupted", "warn")
            return 130
    if not args.input:
        log("missing -i/--input (a hosts file). Use --self-test for a logic check.", "err")
        return 2
    if requests is None:
        log("missing dependency 'requests'. Run: pip install -r requirements.txt", "err")
        return 2
    banner = C.wrap(C.M + C.BOLD, f"ipreal-hunter v{VERSION}") + C.wrap(C.GR, "  authorized recon only")
    print(banner, file=sys.stderr)
    try:
        return run(args)
    except KeyboardInterrupt:
        log("interrupted", "warn")
        return 130


if __name__ == "__main__":
    sys.exit(main())
