#!/usr/bin/env python3
"""
Lab B3: PQC TLS: X25519MLKEM768 Hybrid Handshake
===================================================
Chapter 6: PQC TLS: Protecting Data in Transit

Demonstrates a complete TLS 1.3 handshake using the X25519MLKEM768 hybrid
key exchange group (IETF draft-ietf-tls-hybrid-design). This is the
post-quantum TLS approach recommended by NIST, IETF, and Google.

What this proves:
  1. TLS 1.3 can negotiate X25519MLKEM768 today with OpenSSL 3.5.5
  2. The ClientHello key_share extension carries a hybrid KEM share
     (X25519 share: 32 bytes + ML-KEM-768 encapsulation key: 1,184 bytes)
  3. The handshake produces a classical + post-quantum shared secret
  4. The record layer (AES-256-GCM) is unchanged: only the KEX is upgraded

Architecture:
  - Server: openssl s_server with -groups X25519MLKEM768:x25519
  - Client: Python subprocess wrapping openssl s_client
  - Handshake capture: parse bytes written/read from s_client output
  - Certificate: ECDSA P-256 (signing key: unchanged from classical TLS)

Why hybrid (X25519 + ML-KEM-768)?
  Classical X25519 protects against today's threats.
  ML-KEM-768 protects against future quantum decryption.
  Both must be broken to compromise the session. Belt AND suspenders.

NIST Recommendation: Use hybrid constructions during the transition period.
IETF Reference: draft-ietf-tls-hybrid-design
OpenSSL support: Native in 3.5.x default provider.

Environment: Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14
Author:      Danny B. Carr, Jr.
"""

import os
import re
import subprocess
import tempfile
import time
import signal
from pathlib import Path

LAB_DIR  = Path(__file__).parent.parent.parent
CERT_DIR = LAB_DIR / "tls" / "certs"
OPENSSL  = "openssl"
PORT     = 14440


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------

def ensure_cert() -> tuple[Path, Path]:
    """Generate a P-256 ECDSA self-signed cert for the TLS server if needed."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    crt = CERT_DIR / "server.crt"
    key = CERT_DIR / "server.key"

    if crt.exists() and key.exists():
        return crt, key

    print("[*] Generating P-256 ECDSA server certificate...")
    subprocess.run([
        OPENSSL, "req", "-x509",
        "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-keyout", str(key),
        "-out", str(crt),
        "-days", "365",
        "-nodes",
        "-subj", "/CN=pqc-lab-server/O=Carr Digital LLC/C=US",
    ], capture_output=True, check=True)

    print(f"[+] Certificate → {crt}")
    print(f"[+] Private key → {key}")
    print()
    return crt, key


# ---------------------------------------------------------------------------
# Handshake runner
# ---------------------------------------------------------------------------

def run_handshake(
    group: str,
    crt: Path,
    key: Path,
    port: int,
) -> dict:
    """
    Spin up an openssl s_server, connect with s_client using the specified
    group, capture all handshake details, return a structured dict.
    """
    server_proc = subprocess.Popen([
        OPENSSL, "s_server",
        "-cert", str(crt),
        "-key",  str(key),
        "-tls1_3",
        "-groups", f"{group}:x25519",
        "-www",
        "-port", str(port),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(0.5)

    try:
        t0 = time.perf_counter()
        result = subprocess.run([
            OPENSSL, "s_client",
            "-connect", f"localhost:{port}",
            "-tls1_3",
            "-groups", f"{group}:x25519",
            "-CAfile", str(crt),
        ], capture_output=True, timeout=10, input=b"")
        elapsed_ms = (time.perf_counter() - t0) * 1000

        output = result.stderr.decode() + result.stdout.decode()
    finally:
        server_proc.terminate()
        server_proc.wait(timeout=3)

    # Parse the handshake output
    def extract(pattern, default="unknown"):
        m = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else default

    negotiated_group = extract(r"Negotiated TLS1\.3 group:\s*(.+)")
    cipher           = extract(r"New,.*?Cipher is (.+)")
    protocol         = extract(r"Protocol\s*:\s*(.+)")
    bytes_read       = extract(r"SSL handshake has read (\d+) bytes")
    bytes_written    = extract(r"and written (\d+) bytes")
    server_key_bits  = extract(r"Server public key is (\d+) bit")

    return {
        "group":          negotiated_group,
        "cipher":         cipher,
        "protocol":       protocol,
        "bytes_read":     int(bytes_read) if bytes_read.isdigit() else 0,
        "bytes_written":  int(bytes_written) if bytes_written.isdigit() else 0,
        "server_key_bits": server_key_bits,
        "elapsed_ms":     elapsed_ms,
        "raw_output":     output,
        "success":        "X25519MLKEM768" in output or "x25519" in output.lower() or negotiated_group != "unknown",
    }


def benchmark_handshakes(group: str, crt: Path, key: Path, port: int, n: int = 10) -> float:
    """Run N handshakes and return average elapsed ms."""
    times = []
    for i in range(n):
        server_proc = subprocess.Popen([
            OPENSSL, "s_server",
            "-cert", str(crt), "-key", str(key),
            "-tls1_3", "-groups", f"{group}:x25519",
            "-www", "-port", str(port),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        try:
            t0 = time.perf_counter()
            subprocess.run([
                OPENSSL, "s_client",
                "-connect", f"localhost:{port}",
                "-tls1_3", "-groups", f"{group}:x25519",
                "-CAfile", str(crt),
            ], capture_output=True, timeout=5, input=b"")
            times.append((time.perf_counter() - t0) * 1000)
        finally:
            server_proc.terminate()
            server_proc.wait(timeout=3)
        port += 1
    return sum(times) / len(times) if times else 0.0


# ---------------------------------------------------------------------------
# ClientHello key_share size analysis
# ---------------------------------------------------------------------------

def analyze_key_share_sizes() -> dict:
    """
    Theoretical key_share sizes for the ClientHello extension.
    Based on FIPS 203 and TLS 1.3 RFC 8446 encoding.
    """
    return {
        "x25519": {
            "description": "X25519 (classical only)",
            "key_share_bytes": 32,
            "note": "32-byte X25519 public key",
        },
        "SecP256r1": {
            "description": "P-256 ECDH (classical only)",
            "key_share_bytes": 65,
            "note": "04 || x || y uncompressed point",
        },
        "X25519MLKEM768": {
            "description": "X25519 + ML-KEM-768 hybrid (RECOMMENDED)",
            "key_share_bytes": 32 + 1184,  # X25519 key + ML-KEM-768 encap key
            "note": "32 (X25519) + 1,184 (ML-KEM-768 ek) = 1,216 bytes",
        },
        # draft-ietf-tls-ecdhe-mlkem defines no X448 hybrid: the Level-5
        # option is SecP384r1MLKEM1024 (confirmed via `openssl list -tls-groups`)
        "SecP384r1MLKEM1024": {
            "description": "P-384 + ML-KEM-1024 hybrid",
            "key_share_bytes": 97 + 1568,
            "note": "97 (P-384 uncompressed point) + 1,568 (ML-KEM-1024 ek) = 1,665 bytes",
        },
    }


# ---------------------------------------------------------------------------
# Main lab
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Lab B3 — PQC TLS: X25519MLKEM768 Hybrid Handshake")
    print(f"OpenSSL: {subprocess.run([OPENSSL, 'version'], capture_output=True).stdout.decode().strip()}")
    print("=" * 60)
    print()

    crt, key = ensure_cert()

    # ── Step 1: Classical baseline ──────────────────────────────────
    print("Step 1: Classical TLS 1.3 handshake (x25519 only)")
    print("-" * 40)
    classical = run_handshake("x25519", crt, key, PORT)
    print(f"  Negotiated group : {classical['group']}")
    print(f"  Cipher           : {classical['cipher']}")
    print(f"  Protocol         : {classical['protocol']}")
    print(f"  Bytes exchanged  : {classical['bytes_read']} read / {classical['bytes_written']} written")
    print(f"  Handshake time   : {classical['elapsed_ms']:.1f} ms")
    print()

    # ── Step 2: PQC hybrid handshake ────────────────────────────────
    print("Step 2: PQC hybrid TLS 1.3 handshake (X25519MLKEM768)")
    print("-" * 40)
    pqc = run_handshake("X25519MLKEM768", crt, key, PORT + 1)
    print(f"  Negotiated group : {pqc['group']}")
    print(f"  Cipher           : {pqc['cipher']}")
    print(f"  Protocol         : {pqc['protocol']}")
    print(f"  Bytes exchanged  : {pqc['bytes_read']} read / {pqc['bytes_written']} written")
    print(f"  Handshake time   : {pqc['elapsed_ms']:.1f} ms")
    print()
    print(f"  ✓ PQC group confirmed: {'X25519MLKEM768' in pqc['group']}")
    print()

    # ── Step 3: key_share size analysis ─────────────────────────────
    print("Step 3: ClientHello key_share size analysis")
    print("-" * 40)
    sizes = analyze_key_share_sizes()
    for name, info in sizes.items():
        marker = " ← RECOMMENDED" if name == "X25519MLKEM768" else ""
        print(f"  {name:<22} {info['key_share_bytes']:>6} bytes  {info['note']}{marker}")
    print()
    x25519_size = sizes["x25519"]["key_share_bytes"]
    hybrid_size = sizes["X25519MLKEM768"]["key_share_bytes"]
    print(f"  Overhead of hybrid vs classical: {hybrid_size - x25519_size} bytes ({hybrid_size/x25519_size:.0f}×)")
    print(f"  Context: this is ONE extra roundtrip field in ONE ClientHello.")
    print(f"  For long-lived connections (HTTP/2, gRPC), the cost is negligible.")
    print()

    # ── Step 4: Byte comparison ──────────────────────────────────────
    print("Step 4: Handshake byte comparison")
    print("-" * 40)
    delta_read    = pqc['bytes_read']    - classical['bytes_read']
    delta_written = pqc['bytes_written'] - classical['bytes_written']
    print(f"  Classical bytes  : {classical['bytes_read']} read / {classical['bytes_written']} written")
    print(f"  PQC hybrid bytes : {pqc['bytes_read']} read / {pqc['bytes_written']} written")
    print(f"  Delta (read)     : +{delta_read} bytes")
    print(f"  Delta (written)  : +{delta_written} bytes")
    print()
    print(f"  Book note: The ClientHello is larger by ~{hybrid_size - x25519_size} bytes")
    print(f"  (the ML-KEM-768 encapsulation key in the key_share extension).")
    print(f"  The ServerHello ciphertext adds ~1,088 bytes (the ML-KEM ciphertext).")
    print(f"  Total handshake overhead: ~2,273 bytes. On a 10 Mbps link: ~1.8 ms.")
    print()

    # ── Step 5: Benchmarks ───────────────────────────────────────────
    print("Step 5: Handshake latency benchmark (10 iterations each)")
    print("-" * 40)
    print("  Benchmarking classical (x25519)...")
    classical_avg = benchmark_handshakes("x25519", crt, key, PORT + 10, n=10)
    print(f"  Classical avg : {classical_avg:.1f} ms")

    print("  Benchmarking PQC hybrid (X25519MLKEM768)...")
    pqc_avg = benchmark_handshakes("X25519MLKEM768", crt, key, PORT + 30, n=10)
    print(f"  PQC hybrid avg: {pqc_avg:.1f} ms")
    print(f"  Overhead       : +{pqc_avg - classical_avg:.1f} ms ({(pqc_avg/classical_avg - 1)*100:.0f}%)")
    print()
    print(f"  Book note: The performance overhead of adding ML-KEM-768 to")
    print(f"  TLS is dominated by subprocess spawn time, not crypto. In a")
    print(f"  production TLS library the overhead is ~0.1-0.3 ms per handshake.")
    print()

    # ── Step 6: Summary ──────────────────────────────────────────────
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  PQC TLS working  : {'✓ YES' if 'X25519MLKEM768' in pqc['group'] else '✗ NO'}")
    print(f"  Negotiated group : {pqc['group']}")
    print(f"  TLS version      : {pqc['protocol']}")
    print(f"  Record cipher    : {pqc['cipher']}")
    print()
    print("  What changed vs classical TLS 1.3:")
    print("    ClientHello key_share : +1,184 bytes (ML-KEM-768 encap key)")
    print("    ServerHello response  : +1,088 bytes (ML-KEM-768 ciphertext)")
    print("    Record layer          : UNCHANGED (still AES-256-GCM)")
    print("    Certificate           : UNCHANGED (still ECDSA P-256)")
    print()
    print("  What is protected against quantum attacks:")
    print("    Session key derivation: ✓ (ML-KEM-768 shared secret included)")
    print("    Server authentication : ✗ (still ECDSA — needs ML-DSA cert)")
    print("    Forward secrecy       : ✓ (ephemeral KEM, no long-term key reuse)")
    print()
    print("  Next steps (Chapter 7):")
    print("    Replace ECDSA server cert with ML-DSA-65 cert for full PQC TLS.")

    # ── Save evidence ─────────────────────────────────────────────────
    ev_dir = LAB_DIR / "evidence" / "tls"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev_path = ev_dir / "lab-b3-pqc-tls-handshake.txt"
    ev_path.write_text(
        f"Lab B3 Evidence — PQC TLS Handshake\n"
        f"OpenSSL: {subprocess.run([OPENSSL, 'version'], capture_output=True).stdout.decode().strip()}\n"
        f"Date: {__import__('datetime').datetime.now().isoformat()}\n\n"
        f"Classical handshake:\n"
        f"  Group   : {classical['group']}\n"
        f"  Bytes   : {classical['bytes_read']} read / {classical['bytes_written']} written\n"
        f"  Avg ms  : {classical_avg:.1f}\n\n"
        f"PQC hybrid handshake:\n"
        f"  Group   : {pqc['group']}\n"
        f"  Cipher  : {pqc['cipher']}\n"
        f"  Protocol: {pqc['protocol']}\n"
        f"  Bytes   : {pqc['bytes_read']} read / {pqc['bytes_written']} written\n"
        f"  Avg ms  : {pqc_avg:.1f}\n\n"
        f"key_share sizes:\n"
        + "\n".join(f"  {k}: {v['key_share_bytes']} bytes" for k, v in sizes.items())
        + f"\n\nPQC TLS confirmed working: {'X25519MLKEM768' in pqc['group']}\n"
    )
    print(f"\n  Evidence saved → evidence/tls/lab-b3-pqc-tls-handshake.txt")


if __name__ == "__main__":
    main()
