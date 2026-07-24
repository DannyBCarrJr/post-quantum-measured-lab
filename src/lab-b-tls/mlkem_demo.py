#!/usr/bin/env python3
"""
Lab B1: ML-KEM-768 Key Encapsulation Mechanism
=================================================
Chapter 3: ML-KEM (FIPS 203)

Demonstrates the complete ML-KEM-768 flow using OpenSSL 3.5.5 via subprocess.
This is the same primitive that will replace X25519 in key wrapping.

Protocol:
  Alice (recipient) generates a keypair and publishes the public key.
  Bob  (sender)     encapsulates a shared secret using Alice's public key.
  Alice             decapsulates using her private key.
  Both sides now hold the same shared secret: without ever transmitting it.

This is NOT Diffie-Hellman. There is no "key exchange" in the traditional sense.
The shared secret never traverses the wire. The ciphertext traverses the wire.

NIST FIPS 203: https://doi.org/10.6028/NIST.FIPS.203
Algorithm:      ML-KEM-768 (CRYSTALS-Kyber, security level 3 ≈ AES-192)

Environment:    Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14
Author:         Danny B. Carr, Jr.
"""

import subprocess
import tempfile
import os
import hashlib
import time

ALGORITHM = "ML-KEM-768"
OPENSSL   = "openssl"


# ---------------------------------------------------------------------------
# Helpers: thin wrappers over openssl CLI
# ---------------------------------------------------------------------------

def run(cmd: list[str], input: bytes | None = None) -> bytes:
    """Run an openssl command, raise on error, return stdout bytes."""
    result = subprocess.run(
        cmd,
        input=input,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl failed ({result.returncode}):\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  stderr: {result.stderr.decode().strip()}"
        )
    return result.stdout


def keygen() -> tuple[bytes, bytes]:
    """
    Generate an ML-KEM-768 keypair.
    Returns (private_key_pem, public_key_pem).
    """
    # Generate private key (PKCS#8 PEM)
    priv_pem = run([OPENSSL, "genpkey", "-algorithm", ALGORITHM])

    # Extract public key from private key
    pub_pem = run([OPENSSL, "pkey", "-pubout"], input=priv_pem)

    return priv_pem, pub_pem


def encapsulate(pub_pem: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the recipient's ML-KEM-768 public key.

    Writes the public key to a temp file (openssl pkeyutl requires a file path
    for the recipient key, not stdin, in this operation).

    Returns (ciphertext_bytes, shared_secret_bytes).
    """
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(pub_pem)
        pub_path = f.name

    try:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fc:
            ct_path = fc.name
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fs:
            ss_path = fs.name

        run([
            OPENSSL, "pkeyutl",
            "-encap",
            "-pubin",
            "-inkey", pub_path,
            "-secret", ss_path,
            "-out",    ct_path,
        ])

        with open(ct_path, "rb") as f:
            ciphertext = f.read()
        with open(ss_path, "rb") as f:
            shared_secret = f.read()

        return ciphertext, shared_secret
    finally:
        for p in [pub_path, ct_path, ss_path]:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def decapsulate(priv_pem: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate a shared secret using the recipient's ML-KEM-768 private key.
    Returns shared_secret_bytes.
    """
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(priv_pem)
        priv_path = f.name

    try:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fc:
            ct_path = fc.name
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fs:
            ss_path = fs.name

        with open(ct_path, "wb") as f:
            f.write(ciphertext)

        run([
            OPENSSL, "pkeyutl",
            "-decap",
            "-inkey", priv_path,
            "-in",     ct_path,
            "-secret", ss_path,
        ])

        with open(ss_path, "rb") as f:
            return f.read()
    finally:
        for p in [priv_path, ct_path, ss_path]:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# Lab run
# ---------------------------------------------------------------------------

def measure(fn, *args, **kwargs):
    """Run fn(*args, **kwargs) N times and return (result, avg_ms)."""
    N = 100
    start = time.perf_counter()
    for _ in range(N):
        result = fn(*args, **kwargs)
    elapsed = (time.perf_counter() - start) / N * 1000
    return result, elapsed


def main():
    print("=" * 60)
    print(f"Lab B1 — {ALGORITHM} Key Encapsulation")
    print(f"OpenSSL: {run([OPENSSL, 'version']).decode().strip()}")
    print("=" * 60)
    print()

    # ── Step 1: Key Generation ──────────────────────────────────────
    print("Step 1: Alice generates an ML-KEM-768 keypair")
    print("-" * 40)

    t0 = time.perf_counter()
    alice_priv, alice_pub = keygen()
    keygen_ms = (time.perf_counter() - t0) * 1000

    print(f"  Private key size : {len(alice_priv):,} bytes (PKCS#8 PEM)")
    print(f"  Public key size  : {len(alice_pub):,} bytes (SubjectPublicKeyInfo PEM)")
    print(f"  Keygen time      : {keygen_ms:.2f} ms (single run)")
    print()

    # Key size breakdown note (book content)
    print("  Note: ML-KEM-768 raw key sizes per FIPS 203:")
    print("    Encapsulation key (ek):  1,184 bytes")
    print("    Decapsulation key (dk):  2,400 bytes")
    print("    (PEM adds base64 + headers, hence larger file sizes)")
    print()

    # ── Step 2: Encapsulation ───────────────────────────────────────
    print("Step 2: Bob encapsulates a shared secret using Alice's public key")
    print("-" * 40)

    t0 = time.perf_counter()
    ciphertext, bob_shared_secret = encapsulate(alice_pub)
    encap_ms = (time.perf_counter() - t0) * 1000

    print(f"  Ciphertext size  : {len(ciphertext):,} bytes")
    print(f"  Shared secret    : {len(bob_shared_secret):,} bytes (256-bit)")
    print(f"  Shared secret    : {bob_shared_secret.hex()[:32]}... (first 16 bytes shown)")
    print(f"  Encap time       : {encap_ms:.2f} ms (single run)")
    print()

    print("  Note: ML-KEM-768 ciphertext size per FIPS 203: 1,088 bytes")
    print("  Compare: X25519 public key (sent over wire): 32 bytes")
    print("  The ciphertext IS the 'key exchange message' — 34× larger than X25519")
    print()

    # ── Step 3: Decapsulation ───────────────────────────────────────
    print("Step 3: Alice decapsulates using her private key")
    print("-" * 40)

    t0 = time.perf_counter()
    alice_shared_secret = decapsulate(alice_priv, ciphertext)
    decap_ms = (time.perf_counter() - t0) * 1000

    print(f"  Shared secret    : {alice_shared_secret.hex()[:32]}... (first 16 bytes shown)")
    print(f"  Decap time       : {decap_ms:.2f} ms (single run)")
    print()

    # ── Step 4: Verification ────────────────────────────────────────
    print("Step 4: Verify shared secrets match")
    print("-" * 40)

    match = bob_shared_secret == alice_shared_secret
    print(f"  Bob's secret     : {bob_shared_secret.hex()}")
    print(f"  Alice's secret   : {alice_shared_secret.hex()}")
    print(f"  Match            : {'✓ YES — KEM succeeded' if match else '✗ NO — BUG'}")
    print()

    if not match:
        raise RuntimeError("Shared secrets do not match: ML-KEM implementation error")

    # ── Step 5: Benchmarks ──────────────────────────────────────────
    print("Step 5: Benchmark (100 iterations each)")
    print("-" * 40)

    _, kg_ms  = measure(keygen)
    _, enc_ms = measure(encapsulate, alice_pub)
    _, dec_ms = measure(decapsulate, alice_priv, ciphertext)

    print(f"  Keygen (avg)     : {kg_ms:.2f} ms")
    print(f"  Encapsulate (avg): {enc_ms:.2f} ms")
    print(f"  Decapsulate (avg): {dec_ms:.2f} ms")
    print(f"  Total KEM op     : {enc_ms + dec_ms:.2f} ms")
    print()
    print("  Book note: Compare to X25519 ECDH (~0.05 ms total on this hardware)")
    print("  ML-KEM-768 via subprocess CLI is NOT representative of library speed.")
    print("  For production numbers, see Lab D (benchmark suite using libcrypto FFI).")
    print()

    # ── Summary for book ────────────────────────────────────────────
    print("=" * 60)
    print("Summary (FIPS 203 ML-KEM-768)")
    print("=" * 60)
    print(f"  Algorithm        : {ALGORITHM}")
    print(f"  NIST security    : Level 3 (≈ AES-192 / 192-bit classical)")
    print(f"  Public key       : 1,184 bytes raw")
    print(f"  Private key      : 2,400 bytes raw")
    print(f"  Ciphertext       : 1,088 bytes")
    print(f"  Shared secret    : 32 bytes")
    print(f"  Quantum security : Secure against Shor's algorithm")
    print(f"  Classical        : Based on MLWE hardness assumption")
    print()
    print("  Use this when: replacing X25519 in key wrapping / TLS KEM")
    print("  Use ML-KEM-1024 when: handling government/classified workloads")
    print("  Use hybrid X25519MLKEM768 when: transitional period (recommended now)")

    # ── Save evidence ───────────────────────────────────────────────
    evidence = (
        f"Lab B1 Evidence — {ALGORITHM}\n"
        f"OpenSSL: {run([OPENSSL, 'version']).decode().strip()}\n"
        f"Date: {__import__('datetime').datetime.now().isoformat()}\n\n"
        f"Public key (PEM):\n{alice_pub.decode()}\n"
        f"Ciphertext (hex, first 64 bytes): {ciphertext.hex()[:128]}...\n"
        f"Shared secret (hex): {bob_shared_secret.hex()}\n"
        f"Match: {match}\n\n"
        f"Benchmarks (100-run avg, subprocess CLI):\n"
        f"  Keygen:      {kg_ms:.2f} ms\n"
        f"  Encapsulate: {enc_ms:.2f} ms\n"
        f"  Decapsulate: {dec_ms:.2f} ms\n"
    )
    evidence_path = os.path.join(
        os.path.dirname(__file__), "../../evidence/tls/lab-b1-mlkem768.txt"
    )
    os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
    with open(evidence_path, "w") as f:
        f.write(evidence)
    print(f"\n  Evidence saved → evidence/tls/lab-b1-mlkem768.txt")


if __name__ == "__main__":
    main()
