# Evidence: "Two clocks on the same internet"

Reproducible backing for the article's Verified claims.

## Files
- `analyze.py` reads a Shodan RDP export (gzipped JSON Lines) and prints every Verified aggregate in the article. Aggregates only, no per-host data.
- `OUTPUT.txt` is the captured run against the source export, 2026-10-28.

## Run it
```
python3 -I analyze.py export.json.gz
# or
zcat export.json.gz | python3 -I analyze.py
```

## Source data
A Shodan export of 1,914 exposed-RDP host records (1,908 distinct addresses), crawl 2026-09-28 to 2026-10-28. The raw export is NOT included here and is not published: it holds third-party IP addresses and hostnames, and redistributing Shodan host data is against their terms. The method and the aggregate counts are the publishable part. Anyone with their own Shodan query of the same shape can reproduce the shape of the result.

## Definitions that affect a number
- **Self-signed**: Shodan's self-signed tag, or certificate issuer CN equal to subject CN.
- **End-of-life Windows**: Shodan's eol-os tag, or an OS string naming Windows 7, Vista, XP, Server 2008/2008 R2, or Server 2012/2012 R2. Server 2016 and later are treated as current (Server 2016 extended support runs to 2027).
- **Shared key**: two or more hosts serving a certificate with the same whole-certificate hash. The server proves possession of the matching private key during the handshake, so an identical certificate on two hosts means the same private key on both.
- **PQC count is a floor**: Shodan records a key-exchange group only when its probe captures one, so the two post-quantum hosts are a lower bound, not a census.
