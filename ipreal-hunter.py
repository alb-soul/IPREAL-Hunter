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


VERSION = "1.1.0"
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


def src_crtsh(domain: str, collector: Collector, extra_hosts: Set[str]) -> None:
    try:
        r = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if r.status_code != 200:
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
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=20)
        if r.status_code == 200 and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) == 2:
                    collector.add(parts[1], parts[0], "hackertarget")
    except Exception:  # noqa: BLE001
        pass


def src_securitytrails(host: str, key: str, collector: Collector) -> None:
    try:
        r = http_get(
            f"https://api.securitytrails.com/v1/history/{host}/dns/a",
            timeout=25, headers={"APIKEY": key},
        )
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
        r = http_get(
            f"https://www.virustotal.com/api/v3/domains/{host}/resolutions",
            timeout=25, headers={"x-apikey": key}, params={"limit": 40},
        )
        if r.status_code == 200:
            for item in r.json().get("data", []):
                ip = item.get("attributes", {}).get("ip_address")
                if ip:
                    collector.add(ip, host, "virustotal")
    except Exception as e:  # noqa: BLE001
        log(f"virustotal failed for {host}: {e}", "warn")


def src_shodan_domain(domain: str, key: str, collector: Collector) -> None:
    try:
        r = http_get(f"https://api.shodan.io/dns/domain/{domain}",
                     timeout=25, params={"key": key})
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
        r = requests.post(
            "https://search.censys.io/api/v2/hosts/search",
            headers={"Authorization": f"Bearer {token}", "User-Agent": UA},
            json={"q": f"services.tls.certificates.leaf_data.names: {domain}",
                  "per_page": 50},
            timeout=25,
        )
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
        r = http_get(
            "https://api.certspotter.com/v1/issuances",
            timeout=25,
            headers={"Authorization": f"Bearer {key}"} if key else None,
            params={"domain": domain, "include_subdomains": "true",
                    "expand": "dns_names"},
        )
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
        r = http_get(f"https://api.dnsdumpster.com/domain/{domain}",
                     timeout=25, headers={"X-API-Key": key})
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


def get_baseline(host: str, timeout: int = 15) -> dict:
    base = {"title": None, "len": None, "status": None, "server": None}
    for scheme in ("https", "http"):
        try:
            r = http_get(f"{scheme}://{host}/", timeout=timeout)
            base["status"] = r.status_code
            base["len"] = len(r.content)
            base["server"] = r.headers.get("Server")
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            base["title"] = m.group(1).strip()[:120] if m else None
            return base
        except Exception:  # noqa: BLE001
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
                  probe_path: str = "/") -> Tuple[int, str, str]:
    if requests is None:
        return 0, "requests missing", "BLOCKED"
    notes = []
    score = 0
    reached = False
    codes: List[int] = []
    redirect_host: Optional[str] = None
    for scheme, port in (("https", 443), ("http", 80)):
        url = f"{scheme}://{ip}:{port}{probe_path}"
        try:
            # direct connection only -- never route the probe through a proxy
            r = requests.get(
                url, timeout=timeout, verify=False,
                headers={"Host": host, "User-Agent": UA},
                allow_redirects=False,
                proxies={"http": None, "https": None},
            )
        except Exception:  # noqa: BLE001
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
                if _cert_matches(ip, port, host):
                    score = max(score, 85); notes.append("tls-san-match")
            except Exception:  # noqa: BLE001
                pass
    note = ",".join(sorted(set(notes)))
    if not note:
        note = "reachable" if reached else "no-response"
    verdict = _verdict_for(score, reached, redirect_host, codes, host)
    return score, note, verdict


def _cert_matches(ip: str, port: int, host: str) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert:
        return False
    names = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS":
            names.append(val.lower())
    base = host.split(".")[-2:] if host.count(".") >= 1 else [host]
    apex = ".".join(base)
    return any(apex in n for n in names)


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
def apex_of(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co", "com", "net", "org", "gov", "edu", "ac", "go", "or", "my", "id"}
    if len(parts) >= 3 and parts[-2] in two and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def gather(hosts: List[str], keys: Dict[str, Optional[str]], workers: int,
           enabled: Set[str]) -> Collector:
    collector = Collector()
    apexes = sorted({apex_of(h) for h in hosts})
    extra_hosts: Set[str] = set()

    log(f"{len(hosts)} hosts across {len(apexes)} apex domain(s)", "info")

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
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

    with cf.ThreadPoolExecutor(max_workers=min(workers, 8)) as ex:
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

    new_hosts = [h for h in extra_hosts if h not in set(hosts)]
    if new_hosts and "dns" in enabled:
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            list(cf.as_completed([ex.submit(src_resolve, h, collector) for h in new_hosts]))
        log(f"resolved {len(new_hosts)} CT-discovered hosts", "src")

    return collector


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
    if args.outdir:
        folder = args.outdir
    else:
        name = target or Counter(apex_of(h) for h in hosts).most_common(1)[0][0]
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

    db = build_provider_db(offline=args.offline)
    collector = gather(hosts, keys, args.workers, enabled)

    origins: List[Tuple[str, str, Finding]] = []
    shields: List[Tuple[str, str, Finding]] = []
    for ip, f in collector.findings.items():
        provider, is_cdn, method = classify_ip(ip, db, use_asn=not args.no_asn)
        if is_cdn:
            shields.append((provider, method, f))
        else:
            origins.append((provider, method, f))

    origins.sort(key=lambda t: (t[0] != "Unknown", t[0]))
    shields.sort(key=lambda t: t[0])

    verified: Dict[str, Tuple[int, str, str]] = {}
    do_verify = args.verify or bool(target)
    if do_verify and origins:
        if target:
            log(f"confirming origin of {target}: probing {len(origins)} candidate IP(s) "
                f"with Host: {target} ...", "info")
            tbase = get_baseline(target)
            if not tbase.get("status"):
                log(f"could not fetch a baseline for {target} (site down / blocked?) -- "
                    f"scores will be weaker", "warn")
            with cf.ThreadPoolExecutor(max_workers=min(args.workers, 12)) as ex:
                def _dot(item):
                    _p, _m, f = item
                    return f.ip, verify_origin(f.ip, target, tbase,
                                               timeout=args.verify_timeout,
                                               probe_path=args.probe_path)
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
                        baselines[host] = get_baseline(host)
                    return f.ip, verify_origin(f.ip, host, baselines[host],
                                               timeout=args.verify_timeout,
                                               probe_path=args.probe_path)
                for ip, res in ex.map(_do, origins):
                    verified[ip] = res
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
    sel = [f for _, _, f in origins if (not verified) or get_v(f)[2] == "ACCESS" or get_v(f)[0] >= args.min_score]
    acc = [f for _, _, f in origins if get_v(f)[2] == "ACCESS"]
    reached = [f for _, _, f in origins if get_v(f)[2] in ("ACCESS", "REACHED")]

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
  python3 ipreal-hunter.py --self-test

REMINDER: only test targets you are explicitly authorized to test.""",
    )
    p.add_argument("-i", "--input", help="file with hosts/subdomains, one per line (e.g. subs.txt)")
    p.add_argument("-t", "--target", help="the specific host you want the origin of, e.g. target.com. Every candidate IP is probed with Host: <target> and scored against <target>'s own baseline. Implies --verify.")
    p.add_argument("-o", "--outdir", help="output directory (default: out/<target>, or out/<root-domain> when no -t). auto-created")
    p.add_argument("-c", "--config", help="subfinder provider-config.yaml (default: ~/.config/subfinder/provider-config.yaml)")
    p.add_argument("-w", "--workers", type=int, default=25, help="concurrent workers (default: 25)")
    p.add_argument("--sources", help="comma list to enable (dns,crtsh,hackertarget,securitytrails,virustotal,shodan,censys,certspotter,dnsdumpster)")
    p.add_argument("--verify", action="store_true", help="probe each origin candidate directly and score confidence")
    p.add_argument("--min-score", type=int, default=0, help="only write candidates with confidence >= N to origin_candidates.txt (used with --verify/-t; default 0 = keep all)")
    p.add_argument("--probe-path", default="/", help="path probed during direct-IP verification (default: /)")
    p.add_argument("--verify-timeout", type=int, default=12, help="per-IP verification connect/read timeout in seconds (default: 12)")
    p.add_argument("--no-asn", action="store_true", help="disable Team Cymru ASN fallback classification")
    p.add_argument("--offline", action="store_true", help="skip live CIDR feeds (ASN-only classification)")
    p.add_argument("--self-test", action="store_true", help="run offline logic self-test and exit")
    p.add_argument("-V", "--version", action="version", version=f"ipreal-hunter {VERSION}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
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
