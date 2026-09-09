# ipreal-hunter

Origin / real-IP candidate hunter for **authorized** bug bounty & VDP recon.

Feed it your subdomain recon (`subs.txt` from subfinder) and it collects
candidate IPs from many sources, then **groups them intelligently** into:

- **[ORIGIN CANDIDATES]** — real / hosting IPs worth investigating (not behind a CDN/WAF)
- **[CDN / WAF / PROXY]** — the shield in front of the target (Cloudflare, Akamai, Fastly, CloudFront, Imperva, Sucuri, …) — *not* the origin

> ⚠️ **Only run this against targets you are explicitly authorized to test.**
> Unauthorized scanning is illegal.

## Is this "DNS history"?

Partly. DNS history (a subdomain's historical A records from before it moved
behind a CDN) is one of the strongest signals, and `ipreal-hunter` uses it via
**SecurityTrails** and **VirusTotal passive DNS**. But it combines that with
several other origin-leak techniques so you don't rely on one source:

| Source | Yields | Key |
|---|---|---|
| Direct DNS resolve (A/AAAA) of every host | current IPs; non-proxied subdomains (dev/staging/mail) | no |
| crt.sh Certificate Transparency | extra subdomains + IPs in cert SANs | no |
| HackerTarget hostsearch | host→IP | no |
| **SecurityTrails DNS history** | **historical A records (real origin before CDN)** | yes |
| **VirusTotal** passive DNS | historical resolutions | yes |
| Shodan `dns/domain` | indexed A records | yes |
| Censys hosts search | IPs serving the target's TLS cert | yes |
| Certspotter | extra subdomains | optional |
| DNSDumpster | A records | yes |

## How grouping works

1. Each IP is matched against **live official CIDR feeds** (Cloudflare, AWS +
   CloudFront, Google Cloud, Fastly, DigitalOcean, Oracle, GitHub), cached 24h.
2. Anything not matched falls back to a **Team Cymru IP→ASN lookup** (over DNS,
   no key) whose AS-name is matched against a table of ~40 CDN/WAF and cloud
   providers.
3. CDN/WAF/proxy fronts → `[CDN/WAF]`. Everything else (including cloud hosting
   like EC2, DO, Hetzner, OVH — where origins usually live) → `[ORIGIN]`.

## Verification (`--verify`)

For each origin candidate it opens a **direct connection to the IP** with the
target's `Host` header and compares the response to the normal CDN-fronted
page — status code, page title, body size, and TLS SAN — producing a
**confidence score (0–100)** and a **verdict**:

| Verdict   | Meaning |
|---|---|
| `ACCESS`  | direct-IP probe works & matches the target → likely the **real origin** (use it to bypass the WAF via `Host:` header) |
| `REACHED` | server responds on direct IP but content differs (maybe a different vhost on the same box) |
| `REDIRECT`| the IP redirects to another hostname → usually **not** the origin |
| `DENIED`  | direct-IP access blocked (403 / WAF short-circuit) |
| `BLOCKED` | no response on direct IP (firewall drop, timeout) — origin not directly reachable |

Probes are always made **direct to the IP** (no system proxy) so the result
reflects real network reachability. The path probed defaults to `/` and can be
changed with `--probe-path /path/path` (same as a manual
`curl -I http://<IP>/path/path -H "Host: target.com"`).

## Confirming ONE specific target (`-t / --target`)

The common case: you want the origin of **target.com itself**, and the
subdomains are only there to *surface candidate IPs*. Use `-t`:

```bash
python3 ipreal-hunter.py -i subs.txt -t target.com
```

With `-t` set, `ipreal-hunter`:

1. gathers candidate IPs from every host in `subs.txt` (subdomains, CT, history…),
2. fetches `target.com`'s normal (CDN-fronted) page as the baseline,
3. probes **every** candidate IP with `Host: target.com` — no matter which
   subdomain the IP was discovered from — and scores how closely it matches,
4. sorts the list so the IP most likely to *be* `target.com`'s origin is on top.

`-t` implies `--verify`. Without `-t`, `--verify` instead tests each IP against
the host it was discovered from (useful when you care about many hosts at once).

## Retesting a host against KNOWN origin IPs (`--origin-ips`)

Discovery (step above) gives you `out_ip/origin_candidates.txt`. Later, when
you focus on ONE host — e.g. your injection payloads keep getting blocked by
the WAF — retest just that host against the already-known candidate IPs,
without re-running discovery:

```bash
python3 ipreal-hunter.py -t app.target.com \
  -lio out_ip/origin_candidates.txt \
  -o out_ip/app.target.com/
# atau satu IP saja:
python3 ipreal-hunter.py -t app.target.com -io 1.2.3.4 -o out_ip/app-single/
```

This skips all discovery sources and directly probes every IP in the file
with `Host: app.target.com`, scoring each against the host's own baseline.
Result: `out_ip/app.target.com/accessible_origin.txt` lists the IPs that
actually serve the host. Retry your blocked payloads via direct IP:

```bash
# manual WAF-bypass attempt via confirmed origin IP:
curl -i http://<ACCESS-IP>/injection-point -H "Host: app.target.com"
# or replay the request in Burp with the Host header kept and the
# connection pinned to <ACCESS-IP>
```

`-lio` (alias lama `--origin-ips` tetap berfungsi) requires `-t`. The file
accepts bare IPs, `IP:port` and `http(s)://IP/...` forms (one per line);
private/invalid lines are skipped with a warning. `-io` is the same check
for a single IP given directly on the command line.

## Install

Dependencies are **Python-only** — no external binaries/tools are required:

```bash
pip install -r requirements.txt   # requests, dnspython, PyYAML, mmh3
```

The optional `-i` input is a plain hosts file (one host per line, e.g. the
output of `subfinder`), but `subfinder` itself is not a dependency. API keys
are read from your existing subfinder config but the tool runs fully standalone.

## Usage

```bash
# basic — reads keys from ~/.config/subfinder/provider-config.yaml automatically
python3 ipreal-hunter.py -i subs.txt

# hunt + verify each candidate, custom output dir
python3 ipreal-hunter.py -i subs.txt --verify -o results/

# free sources only (no API keys)
python3 ipreal-hunter.py -i subs.txt --sources dns,crtsh,hackertarget

# offline logic check
python3 ipreal-hunter.py --self-test
```

### Options

```
-i, --input     hosts file, one per line (subfinder output)
-t, --target    the ONE host you want the origin of; probes every candidate
                IP with Host: <target> and scores it. Implies --verify
-o, --outdir    output dir (default: out/<target>, or out/<root-domain>
                when no -t). Created automatically.
-c, --config    path to subfinder provider-config.yaml
-w, --workers   concurrency (default 25)
--sources       comma list: dns,crtsh,hackertarget,securitytrails,
                virustotal,shodan,censys,certspotter,dnsdumpster
--verify        probe candidates directly and score confidence
--min-score N   only write candidates with confidence >= N to
                origin_candidates.txt (default 0 = keep all)
--probe-path    path probed on direct-IP verification (default: /)
--verify-timeout  per-IP verification timeout in seconds (default: 12)
--no-asn        disable Team Cymru ASN fallback
--offline       skip live CIDR feeds (ASN-only)
--self-test     run offline logic check
```

## API keys

Read automatically from your existing subfinder config
(`~/.config/subfinder/provider-config.yaml`) — no duplication. Override any key
with an env var, e.g. `IPREAL_SECURITYTRAILS=xxxx`. The tool never writes keys
to disk.

## Output

Results are written to an auto-created folder: `out/<target>/` when `-t` is
given, otherwise `out/<root-domain>/` (root domain taken from the hosts list).
Override with `-o`.

- `accessible_origin.txt` — only verdict `ACCESS` (direct-IP verified, sorted by score): pipe this into `curl -I http://<IP>/ -H "Host: target.com"`, `httpx`, `nuclei`
- `origin_candidates.txt` — all candidates passing `--min-score` (default: all)
- `reachable_origin.txt` — verdict `ACCESS` + `REACHED`
- `cdn_waf_ips.txt` — the shielded IPs
- `report.json` — full detail: provider, detection method, hosts, sources, confidence, verdict

## Recommended workflow

```bash
subfinder -d target.com -all -o subs.txt
python3 ipreal-hunter.py -i subs.txt -t target.com
# DOMINANT origin (verdict ACCESS) -- verify it directly:
curl -I http://$(head -1 out/target.com/accessible_origin.txt)/ -H "Host: target.com"
# or validate the top candidates:
httpx -l out/target.com/accessible_origin.txt -title -status-code -tech-detect
```

## Notes / limits

- Azure and Akamai have no single stable public CIDR file → caught via the ASN
  fallback instead.
- Free sources (crt.sh, HackerTarget) are rate-limited; the API sources are far
  more reliable for history.
- A candidate is only *confirmed* origin once `--verify` scores it high or you
  manually validate — treat the list as leads, not conclusions.

MIT.
