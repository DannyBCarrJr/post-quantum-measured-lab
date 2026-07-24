#!/usr/bin/env python3
"""
Lab CA: PQC Certificate Authority Chain
==========================================
Chapter 7: PQC PKI: Certificates and CAs

Builds a complete 3-tier PQC PKI using ML-DSA-65 (FIPS 204):

    Root CA  (ML-DSA-65, self-signed, 10 years)
        └── Intermediate CA  (ML-DSA-65, signed by Root, 5 years)
                └── Leaf cert  (ML-DSA-65, signed by Intermediate, 1 year)
                        └── TLS server (X25519MLKEM768 KEX + ML-DSA-65 auth)

This represents a FULL post-quantum TLS stack:
  - Key exchange   : X25519MLKEM768 hybrid KEM (FIPS 203 + classical)
  - Authentication : ML-DSA-65 certificate chain (FIPS 204)
  - Record cipher  : AES-256-GCM (unchanged: quantum-safe with 256-bit keys)

After this lab, ALL three TLS security properties are quantum-resistant:
  ✓ Confidentiality  (AES-256-GCM record encryption)
  ✓ Key agreement    (X25519MLKEM768: Lab B3)
  ✓ Authentication   (ML-DSA-65 cert chain: THIS lab)

Environment: Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14
Author:      Danny B. Carr, Jr.
"""

import os
import re
import subprocess
import time
from pathlib import Path

OPENSSL  = "openssl"
CA_DIR   = Path(__file__).parent.parent.parent / "ca"
EVIDENCE = Path(__file__).parent.parent.parent / "evidence" / "signatures"

ALGORITHM = "ML-DSA-65"
ROOT_CN   = "Carr Digital PQC Root CA"
INT_CN    = "Carr Digital PQC Issuing CA"
LEAF_CN   = "pqc-lab.zeroshade.dev"
ORG       = "Carr Digital LLC"
COUNTRY   = "US"
PORT      = 14460


def run(cmd: list[str], input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, input=input, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"openssl failed:\n  cmd: {' '.join(str(c) for c in cmd)}\n"
            f"  stderr: {r.stderr.decode().strip()}"
        )
    return r


def cert_info(path: Path) -> dict:
    """Extract key fields from a certificate."""
    out = run([OPENSSL, "x509", "-in", str(path), "-noout", "-text"]).stdout.decode()
    def extract(pattern, default="unknown"):
        m = re.search(pattern, out, re.IGNORECASE)
        return m.group(1).strip() if m else default

    return {
        "subject":      extract(r"Subject:\s*(.+)"),
        "issuer":       extract(r"Issuer:\s*(.+)"),
        "sig_algo":     extract(r"Signature Algorithm:\s*(.+?)$"),
        "pubkey_algo":  extract(r"Public Key Algorithm:\s*(.+?)$"),
        "not_before":   extract(r"Not Before:\s*(.+)"),
        "not_after":    extract(r"Not After\s*:\s*(.+)"),
        "serial":       extract(r"Serial Number:\s*\n\s*(.+)"),
    }


def print_cert(label: str, info: dict) -> None:
    print(f"  {label}:")
    print(f"    Subject    : {info['subject']}")
    print(f"    Issuer     : {info['issuer']}")
    print(f"    Sig algo   : {info['sig_algo']}")
    print(f"    PubKey     : {info['pubkey_algo']}")
    print(f"    Valid until: {info['not_after']}")
    print()


def build_ca_chain() -> tuple[Path, Path, Path, Path, Path]:
    """
    Build the 3-tier ML-DSA-65 CA chain.
    Returns (root_key, root_crt, int_key, int_crt, chain_crt).
    """
    CA_DIR.mkdir(parents=True, exist_ok=True)

    root_key = CA_DIR / "root-ca.key"
    root_crt = CA_DIR / "root-ca.crt"
    int_key  = CA_DIR / "int-ca.key"
    int_crt  = CA_DIR / "int-ca.crt"
    int_csr  = CA_DIR / "int-ca.csr"
    chain    = CA_DIR / "ca-chain.crt"

    # ── Root CA ─────────────────────────────────────────────────────
    print("  Generating Root CA key (ML-DSA-65)...")
    t0 = time.perf_counter()
    run([OPENSSL, "genpkey", "-algorithm", ALGORITHM, "-out", str(root_key)])
    print(f"    Root CA key : {root_key} ({root_key.stat().st_size:,} bytes, {(time.perf_counter()-t0)*1000:.0f}ms)")

    # Self-contained extensions via -addext: `-extensions v3_ca` resolves the
    # section in whatever config OPENSSL_CONF points at, so the lab would break
    # on any machine with a custom config (e.g. a PQC TLS-groups override).
    run([
        OPENSSL, "req", "-new", "-x509",
        "-key", str(root_key),
        "-out", str(root_crt),
        "-days", "3650",
        "-subj", f"/CN={ROOT_CN}/O={ORG}/C={COUNTRY}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ])
    print(f"    Root CA cert: {root_crt} ({root_crt.stat().st_size:,} bytes)")

    # ── Intermediate CA ─────────────────────────────────────────────
    print("  Generating Intermediate CA key (ML-DSA-65)...")
    t0 = time.perf_counter()
    run([OPENSSL, "genpkey", "-algorithm", ALGORITHM, "-out", str(int_key)])
    print(f"    Int CA key  : {int_key} ({int_key.stat().st_size:,} bytes, {(time.perf_counter()-t0)*1000:.0f}ms)")

    run([
        OPENSSL, "req", "-new",
        "-key", str(int_key),
        "-out", str(int_csr),
        "-subj", f"/CN={INT_CN}/O={ORG}/C={COUNTRY}",
    ])

    # Sign the intermediate with root: mark as CA:TRUE with pathlen:0
    ext_content = (
        "[v3_ca]\n"
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
    )
    ext_file = CA_DIR / "int-ca-ext.cnf"
    ext_file.write_text(ext_content)

    run([
        OPENSSL, "x509", "-req",
        "-in", str(int_csr),
        "-CA", str(root_crt),
        "-CAkey", str(root_key),
        "-CAcreateserial",
        "-out", str(int_crt),
        "-days", "1825",
        "-extensions", "v3_ca",
        "-extfile", str(ext_file),
    ])
    print(f"    Int CA cert : {int_crt} ({int_crt.stat().st_size:,} bytes)")

    # Intermediate chain bundle (int + root, for TLS -cert_chain)
    chain.write_bytes(int_crt.read_bytes() + root_crt.read_bytes())
    print(f"    CA chain    : {chain} ({chain.stat().st_size:,} bytes)")

    return root_key, root_crt, int_key, int_crt, chain


def build_leaf_cert(int_key: Path, int_crt: Path) -> tuple[Path, Path]:
    """Issue a TLS server certificate from the Intermediate CA."""
    server_key = CA_DIR / "server.key"
    server_crt = CA_DIR / "server.crt"
    server_csr = CA_DIR / "server.csr"

    print("  Generating server leaf key (ML-DSA-65)...")
    t0 = time.perf_counter()
    run([OPENSSL, "genpkey", "-algorithm", ALGORITHM, "-out", str(server_key)])
    print(f"    Server key  : {server_key} ({server_key.stat().st_size:,} bytes, {(time.perf_counter()-t0)*1000:.0f}ms)")

    run([
        OPENSSL, "req", "-new",
        "-key", str(server_key),
        "-out", str(server_csr),
        "-subj", f"/CN={LEAF_CN}/O={ORG}/C={COUNTRY}",
    ])

    ext_content = (
        "[v3_server]\n"
        f"subjectAltName=DNS:{LEAF_CN},DNS:localhost\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
    )
    ext_file = CA_DIR / "server-ext.cnf"
    ext_file.write_text(ext_content)

    run([
        OPENSSL, "x509", "-req",
        "-in", str(server_csr),
        "-CA", str(int_crt),
        "-CAkey", str(int_key),
        "-CAcreateserial",
        "-out", str(server_crt),
        "-days", "365",
        "-extensions", "v3_server",
        "-extfile", str(ext_file),
    ])
    print(f"    Server cert : {server_crt} ({server_crt.stat().st_size:,} bytes)")

    return server_key, server_crt


def verify_chain(root_crt: Path, int_crt: Path, server_crt: Path) -> bool:
    """Verify the full certificate chain."""
    r = run([
        OPENSSL, "verify",
        "-CAfile", str(root_crt),
        "-untrusted", str(int_crt),
        str(server_crt),
    ], check=False)
    return r.returncode == 0


def run_full_pqc_tls_handshake(
    server_key: Path,
    server_crt: Path,
    chain: Path,
    root_crt: Path,
) -> dict:
    """
    Run a TLS 1.3 handshake with ML-DSA-65 cert + X25519MLKEM768 KEX.
    This is the full post-quantum TLS stack.
    """
    server_proc = subprocess.Popen([
        OPENSSL, "s_server",
        "-cert",       str(server_crt),
        "-key",        str(server_key),
        "-cert_chain", str(chain),
        "-tls1_3",
        "-groups", "X25519MLKEM768:x25519",
        "-www",
        "-port", str(PORT),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(0.5)

    try:
        t0 = time.perf_counter()
        result = subprocess.run([
            OPENSSL, "s_client",
            "-connect", f"localhost:{PORT}",
            "-tls1_3",
            "-groups", "X25519MLKEM768:x25519",
            "-CAfile", str(root_crt),
        ], capture_output=True, timeout=10, input=b"")
        elapsed = (time.perf_counter() - t0) * 1000
        output = result.stderr.decode() + result.stdout.decode()
    finally:
        server_proc.terminate()
        server_proc.wait(timeout=3)

    def extract(pattern, default="unknown"):
        m = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else default

    return {
        "group":       extract(r"Negotiated TLS1\.3 group:\s*(.+)"),
        "cipher":      extract(r"New,.*?Cipher is (.+)"),
        "protocol":    extract(r"Protocol\s*:\s*(.+)"),
        "verify":      extract(r"Verify return code: (.+)"),
        "subject":     extract(r"subject=(.+)"),
        "issuer":      extract(r"issuer=(.+)"),
        "bytes_read":  extract(r"SSL handshake has read (\d+) bytes"),
        "bytes_written": extract(r"and written (\d+) bytes"),
        "elapsed_ms":  elapsed,
        "success":     "X25519MLKEM768" in output and "Verify return code: 0" in output,
    }


def main():
    print("=" * 60)
    print("Lab CA — PQC Certificate Authority Chain")
    print(f"OpenSSL: {run([OPENSSL, 'version']).stdout.decode().strip()}")
    print(f"Algorithm: {ALGORITHM} (FIPS 204)")
    print("=" * 60)
    print()

    # ── Step 1: Key sizes comparison ────────────────────────────────
    print("Step 1: Certificate size comparison (Classical vs PQC)")
    print("-" * 40)
    print("  ECDSA P-256 (classical):")
    print("    CA private key    :    ~121 bytes  (SEC1 EC key)")
    print("    Certificate       :    ~500 bytes  (self-signed)")
    print("    Signature in cert :     64 bytes   (ECDSA)")
    print()
    print("  ML-DSA-65 (FIPS 204, post-quantum):")
    print("    CA private key    :  ~4,032 bytes  (per FIPS 204 spec)")
    print("    Certificate       :  ~3,900 bytes  (self-signed)")
    print("    Signature in cert :  3,309 bytes   (ML-DSA-65)")
    print()
    print("  Cost: ~8× larger certs. Delivered once per TLS session.")
    print("  On a 10 Mbps link, an extra ~3 KB cert ≈ 2.4 ms of transfer time.")
    print()

    # ── Step 2: Build the CA chain ──────────────────────────────────
    print("Step 2: Build 3-tier ML-DSA-65 PKI")
    print("-" * 40)
    t0 = time.perf_counter()
    root_key, root_crt, int_key, int_crt, chain = build_ca_chain()
    print()
    print("Step 3: Issue leaf TLS certificate")
    print("-" * 40)
    server_key, server_crt = build_leaf_cert(int_key, int_crt)
    total_ms = (time.perf_counter() - t0) * 1000
    print(f"\n  Total CA chain build time: {total_ms:.0f} ms")
    print()

    # ── Step 3: Verify chain ────────────────────────────────────────
    print("Step 4: Verify certificate chain")
    print("-" * 40)
    valid = verify_chain(root_crt, int_crt, server_crt)
    print(f"  Chain: Root CA → Intermediate CA → Server cert")
    print(f"  Result: {'✓ VALID' if valid else '✗ INVALID'}")
    print()

    # ── Step 4: Print cert details ──────────────────────────────────
    print("Step 5: Certificate details")
    print("-" * 40)
    print_cert("Root CA", cert_info(root_crt))
    print_cert("Intermediate CA", cert_info(int_crt))
    print_cert("Server cert", cert_info(server_crt))

    # ── Step 5: Full PQC TLS handshake ──────────────────────────────
    print("Step 6: Full PQC TLS handshake (ML-DSA-65 cert + X25519MLKEM768 KEX)")
    print("-" * 40)
    hs = run_full_pqc_tls_handshake(server_key, server_crt, chain, root_crt)
    print(f"  KEX group        : {hs['group']}")
    print(f"  Cipher suite     : {hs['cipher']}")
    print(f"  TLS version      : {hs['protocol']}")
    print(f"  Certificate CN   : {hs['subject']}")
    print(f"  Issued by        : {hs['issuer']}")
    print(f"  Chain verify     : {hs['verify']}")
    print(f"  Bytes exchanged  : {hs['bytes_read']} read / {hs['bytes_written']} written")
    print(f"  Handshake time   : {hs['elapsed_ms']:.1f} ms")
    print()
    pqc_kex  = "X25519MLKEM768" in hs['group']
    pqc_auth = "0 (ok)" in hs['verify']
    print(f"  ✓ PQC key exchange  : {'YES — X25519MLKEM768' if pqc_kex else 'NO'}")
    print(f"  ✓ PQC authentication: {'YES — ML-DSA-65 chain verified' if pqc_auth else 'NO'}")
    print(f"  ✓ Full PQC TLS      : {'YES' if pqc_kex and pqc_auth else 'NO — check above'}")
    print()

    # ── Summary ──────────────────────────────────────────────────────
    print("=" * 60)
    print("Summary — Full Post-Quantum TLS Stack")
    print("=" * 60)
    print()
    print("  Layer              Classical          Post-Quantum")
    print("  -----------------  -----------------  ------------------")
    print("  Record encryption  AES-256-GCM        AES-256-GCM (same)")
    print("  Key exchange       X25519 ECDH        X25519MLKEM768 ✓")
    print("  Authentication     ECDSA P-256         ML-DSA-65     ✓")
    print("  Certificate chain  RSA/ECDSA CA       ML-DSA-65 CA  ✓")
    print()
    print("  All three TLS security properties are now quantum-resistant.")
    print()
    print("  Remaining gaps (real-world migration):")
    print("    □ Client certificates (mutual TLS) also need ML-DSA")
    print("    □ OCSP responses need to be signed with ML-DSA")
    print("    □ CRL signatures need to be ML-DSA")
    print("    □ CT log inclusion proofs need PQC signatures")
    print("    □ HSM support for ML-DSA key storage (Venafi/CyberArk)")
    print()
    print("  These are Chapter 8 topics (PKI operations: revocation, the HSM gate, CLM state).")

    # ── Save evidence ─────────────────────────────────────────────────
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    ev = EVIDENCE / "lab-ca-pqc-chain.txt"
    ev.write_text(
        f"Lab CA Evidence — PQC Certificate Authority Chain\n"
        f"OpenSSL: {run([OPENSSL, 'version']).stdout.decode().strip()}\n"
        f"Date: {__import__('datetime').datetime.now().isoformat()}\n\n"
        f"Root CA cert:\n{root_crt.read_text()}\n"
        f"Chain verify: {valid}\n"
        f"Chain build time: {total_ms:.0f} ms (3 keygens + 3 signs, subprocess wall clock)\n"
        f"Cert sizes: root={root_crt.stat().st_size:,} B, int={int_crt.stat().st_size:,} B, "
        f"server={server_crt.stat().st_size:,} B, chain={chain.stat().st_size:,} B\n\n"
        f"Full PQC TLS handshake:\n"
        f"  Group  : {hs['group']}\n"
        f"  Cipher : {hs['cipher']}\n"
        f"  Verify : {hs['verify']}\n"
        f"  PQC KEX: {pqc_kex}\n"
        f"  PQC Auth:{pqc_auth}\n"
        f"  Full PQC:{pqc_kex and pqc_auth}\n"
    )
    print(f"  Evidence → evidence/signatures/lab-ca-pqc-chain.txt")
    print(f"  CA files → ca/")


if __name__ == "__main__":
    main()
