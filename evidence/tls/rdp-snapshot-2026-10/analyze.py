#!/usr/bin/env python3
"""Reproduce every Verified number in the "Two clocks" article from a Shodan
RDP export (gzipped JSON Lines). Aggregates only. Prints no per-host data, so
its output is safe to publish; the raw export is not.

Usage:  zcat export.json.gz | python3 -I analyze.py
   or:  python3 -I analyze.py export.json.gz   (handles .gz or plain .json)

EOL Windows is defined explicitly as any build string naming Server 2008/2008 R2,
Windows 7, Server 2012/2012 R2, Vista, or XP (all past Microsoft extended support
as of 2026), or carrying Shodan's own "eol-os" tag.
"""
import sys, json, gzip, collections

WEAK = ("sha1WithRSAEncryption", "md5WithRSAEncryption")
EOL_MARKERS = ("Windows 7", "Vista", "Windows XP",
               "2008", "2012")  # Server 2008/2008 R2, Server 2012/2012 R2

def is_eol(os_s, tags):
    if "eol-os" in (tags or []):
        return True
    return bool(os_s) and any(m in os_s for m in EOL_MARKERS)

def records(src):
    for line in src:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue

def main(src):
    n = ssl_n = 0
    ips = set()
    port = collections.Counter()
    self_total = ca_total = self_weak = ca_weak = 0
    eol_self = eol_self_weak = cur_self = cur_self_weak = 0
    pqc_hosts = {}            # CN -> set of groups  (dedupes multi-group hosts)
    jarm = collections.Counter()
    small_keys = collections.Counter()
    ntlm_domain = 0
    cert_ips = collections.defaultdict(set)
    cert_orgs = collections.defaultdict(set)

    for d in records(src):
        n += 1
        port[d.get("port")] += 1
        ip = d.get("ip_str"); ips.add(ip)
        s = d.get("ssl") or {}
        if not s:
            continue
        ssl_n += 1
        c = s.get("cert") or {}
        subj = (c.get("subject") or {}).get("CN")
        iss = (c.get("issuer") or {})
        sig = c.get("sig_alg", "?")
        tags = d.get("tags") or []
        eol = is_eol(d.get("os"), tags)
        is_self = ("self-signed" in tags) or (subj is not None and subj == iss.get("CN"))
        weak = sig in WEAK
        if is_self:
            self_total += 1
            if weak:
                self_weak += 1
            if eol:
                eol_self += 1
                if weak:
                    eol_self_weak += 1
            else:
                cur_self += 1
                if weak:
                    cur_self_weak += 1
        else:
            ca_total += 1
            if weak:
                ca_weak += 1
        groups = s.get("kex_groups") or []
        if any("MLKEM" in g.upper() or "KYBER" in g.upper() for g in groups):
            pqc_hosts.setdefault(subj, set()).update(groups)
        if s.get("jarm"):
            jarm[s["jarm"]] += 1
        pk = c.get("pubkey") or {}
        if isinstance(pk.get("bits"), int) and pk["bits"] < 2048:
            small_keys["%s-%s" % (pk.get("type"), pk["bits"])] += 1
        nt = d.get("ntlm") or {}
        if nt.get("ad_domain_name") or nt.get("dns_domain_name"):
            ntlm_domain += 1
        ch = (s.get("chain_sha256") or [None])[0]
        if ch:
            cert_ips[ch].add(ip)
            cert_orgs[ch].add(d.get("org") or "?")

    shared = sorted(((len(v), h) for h, v in cert_ips.items() if len(v) > 1), reverse=True)
    shared_ips = sum(nn for nn, _ in shared)
    jarm_top3 = sum(v for _, v in jarm.most_common(3))
    pct = lambda a, b: (100.0 * a / b) if b else 0.0

    p = print
    p("records: %d | with ssl: %d | distinct IPs: %d | port 3389: %d" % (n, ssl_n, len(ips), port[3389]))
    p("")
    p("self-signed: %d (%.1f%%) | CA-issued: %d" % (self_total, pct(self_total, ssl_n), ca_total))
    p("weak-hash (SHA-1/MD5) total: %d | self-signed: %d | CA-issued: %d" % (self_weak + ca_weak, self_weak, ca_weak))
    p("weak self-signed on EOL Windows: %d of %d weak self-signed" % (eol_self_weak, self_weak))
    p("weak-hash rate: EOL self-signed %.1f%% (%d/%d) vs current %.1f%% (%d/%d)"
      % (pct(eol_self_weak, eol_self), eol_self_weak, eol_self,
         pct(cur_self_weak, cur_self), cur_self_weak, cur_self))
    p("")
    p("PQC hybrid kex on %d DISTINCT hosts (FLOOR, not census):" % len(pqc_hosts))
    for cn, g in pqc_hosts.items():
        p("   %s  %s" % (cn, sorted(g)))
    p("")
    p("duplicate certs: %d shared across >1 distinct IP | %d distinct IPs implicated (%.1f%% of hosts)"
      % (len(shared), shared_ips, pct(shared_ips, len(ips))))
    p("  largest shared certs (distinct IPs | distinct orgs):")
    for nn, h in shared[:5]:
        p("    %4d ips | %d orgs" % (nn, len(cert_orgs[h])))
    p("")
    p("distinct JARM fingerprints: %d | top 3 cover %d (%.1f%%)" % (len(jarm), jarm_top3, pct(jarm_top3, ssl_n)))
    p("keys below RSA-2048: %s (total %d)" % (dict(small_keys), sum(small_keys.values())))
    p("hosts leaking internal domain name pre-auth (NTLM): %d (%.1f%%)" % (ntlm_domain, pct(ntlm_domain, n)))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
        op = gzip.open if path.endswith(".gz") else open
        with op(path, "rt", errors="replace") as fh:
            main(fh)
    else:
        main(sys.stdin)
