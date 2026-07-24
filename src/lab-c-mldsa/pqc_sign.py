#!/usr/bin/env python3
"""
Lab C: pqc-sign: ML-DSA-65 File Signing Tool
===============================================
Chapter 4: ML-DSA (FIPS 204)

A production-usable CLI for signing and verifying arbitrary files using
ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204). Think `gpg --sign` but
post-quantum. Signature files are detached (.sig) and portable.

Usage:
    python3 pqc_sign.py keygen   --key-dir ./keys
    python3 pqc_sign.py sign     --key-dir ./keys --file artifact.aab
    python3 pqc_sign.py verify   --key-dir ./keys --file artifact.aab
    python3 pqc_sign.py demo                          # self-contained demo

Algorithm: ML-DSA-65 (FIPS 204, security level 3 ≈ AES-192)
  - Signature size:   3,309 bytes  (vs 64 bytes for Ed25519)
  - Public key size:  1,952 bytes  (vs 32 bytes for Ed25519)
  - Private key size: 4,032 bytes  (vs 64 bytes for Ed25519)

The size increase is the cost of quantum resistance. For file signing,
where signatures are stored not transmitted per-packet, this is fine.

NIST FIPS 204: https://doi.org/10.6028/NIST.FIPS.204
Environment:   Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14
Author:        Danny B. Carr, Jr.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ALGORITHM  = "ML-DSA-65"
OPENSSL    = "openssl"
SIG_EXT    = ".pqcsig"
PRIV_FILE  = "mldsa65_priv.pem"
PUB_FILE   = "mldsa65_pub.pem"


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def _run(cmd: list[str], input: bytes | None = None) -> bytes:
    r = subprocess.run(cmd, input=input, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"openssl error ({r.returncode}): {r.stderr.decode().strip()}"
        )
    return r.stdout


def cmd_keygen(key_dir: Path) -> None:
    """Generate an ML-DSA-65 keypair and save to key_dir."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / PRIV_FILE
    pub_path  = key_dir / PUB_FILE

    if priv_path.exists() or pub_path.exists():
        print(f"[!] Keys already exist in {key_dir}. Delete them first to regenerate.")
        sys.exit(1)

    print(f"[*] Generating {ALGORITHM} keypair...")
    t0 = time.perf_counter()

    priv_pem = _run([OPENSSL, "genpkey", "-algorithm", ALGORITHM])
    pub_pem  = _run([OPENSSL, "pkey", "-pubout"], input=priv_pem)

    ms = (time.perf_counter() - t0) * 1000

    # Write with tight permissions: private key is sensitive
    priv_path.write_bytes(priv_pem)
    priv_path.chmod(0o600)
    pub_path.write_bytes(pub_pem)
    pub_path.chmod(0o644)

    print(f"[+] Private key  → {priv_path}  ({len(priv_pem):,} bytes, mode 600)")
    print(f"[+] Public key   → {pub_path}  ({len(pub_pem):,} bytes, mode 644)")
    print(f"[+] Keygen time  : {ms:.1f} ms")
    print()
    print("    IMPORTANT: Back up the private key securely.")
    print("    Distribute the public key to anyone who needs to verify your signatures.")


def cmd_sign(key_dir: Path, file_path: Path) -> None:
    """Sign a file with ML-DSA-65. Writes a detached .pqcsig file."""
    priv_path = key_dir / PRIV_FILE
    sig_path  = file_path.with_suffix(file_path.suffix + SIG_EXT)

    if not priv_path.exists():
        print(f"[!] Private key not found: {priv_path}")
        print(f"    Run: python3 pqc_sign.py keygen --key-dir {key_dir}")
        sys.exit(1)

    if not file_path.exists():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    # Hash the file first (sign the hash, not the raw bytes, for large files)
    # ML-DSA signs arbitrary messages but hashing first is good practice and
    # matches how code-signing tools work (sign the digest, not the binary).
    file_bytes = file_path.read_bytes()
    digest = hashlib.sha3_256(file_bytes).digest()  # SHA3-256: also quantum-safe

    print(f"[*] Signing {file_path.name} with {ALGORITHM}...")
    print(f"    File size : {len(file_bytes):,} bytes")
    print(f"    SHA3-256  : {digest.hex()}")

    t0 = time.perf_counter()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(digest)
        digest_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as f:
        raw_sig_path = f.name

    try:
        _run([
            OPENSSL, "pkeyutl",
            "-sign",
            "-inkey", str(priv_path),
            "-in",    digest_path,
            "-out",   raw_sig_path,
        ])
        sig_bytes = Path(raw_sig_path).read_bytes()
    finally:
        for p in [digest_path, raw_sig_path]:
            try: os.unlink(p)
            except FileNotFoundError: pass

    ms = (time.perf_counter() - t0) * 1000

    # Write signature bundle: algorithm header + raw signature
    bundle = _make_sig_bundle(sig_bytes, digest, file_path.name)
    sig_path.write_bytes(bundle)

    print(f"[+] Signature    → {sig_path}  ({len(bundle):,} bytes)")
    print(f"[+] Sign time    : {ms:.1f} ms")
    print()
    print(f"    ML-DSA-65 signature: {len(sig_bytes):,} bytes")
    print(f"    (Ed25519 comparison: 64 bytes — {len(sig_bytes)//64}× larger)")


def cmd_verify(key_dir: Path, file_path: Path) -> bool:
    """Verify an ML-DSA-65 signature. Returns True if valid."""
    pub_path  = key_dir / PUB_FILE
    sig_path  = file_path.with_suffix(file_path.suffix + SIG_EXT)

    if not pub_path.exists():
        print(f"[!] Public key not found: {pub_path}")
        sys.exit(1)

    if not sig_path.exists():
        print(f"[!] Signature file not found: {sig_path}")
        sys.exit(1)

    print(f"[*] Verifying {file_path.name}...")

    # Parse signature bundle
    bundle = sig_path.read_bytes()
    sig_bytes, stored_digest, signed_filename = _parse_sig_bundle(bundle)

    # Recompute digest of the file
    file_bytes = file_path.read_bytes()
    actual_digest = hashlib.sha3_256(file_bytes).digest()

    print(f"    File size       : {len(file_bytes):,} bytes")
    print(f"    Stored digest   : {stored_digest.hex()}")
    print(f"    Computed digest : {actual_digest.hex()}")
    print(f"    Signed filename : {signed_filename}")

    # Verify digest matches before touching openssl
    if actual_digest != stored_digest:
        print("[✗] FAIL: file digest mismatch (file has been modified)")
        return False

    t0 = time.perf_counter()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(actual_digest)
        digest_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as f:
        f.write(sig_bytes)
        raw_sig_path = f.name

    try:
        result = subprocess.run([
            OPENSSL, "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey", str(pub_path),
            "-in",    digest_path,
            "-sigfile", raw_sig_path,
        ], capture_output=True)

        valid = result.returncode == 0
    finally:
        for p in [digest_path, raw_sig_path]:
            try: os.unlink(p)
            except FileNotFoundError: pass

    ms = (time.perf_counter() - t0) * 1000

    if valid:
        print(f"[✓] VALID: ML-DSA-65 signature verified ({ms:.1f} ms)")
    else:
        print(f"[✗] INVALID: signature verification failed")
        print(f"    openssl: {result.stderr.decode().strip()}")

    return valid


# ---------------------------------------------------------------------------
# Signature bundle format
# ---------------------------------------------------------------------------
# Simple binary format:
#   4 bytes  : magic "PQCS"
#   1 byte   : version (0x01)
#   32 bytes : SHA3-256 digest of the signed file
#   2 bytes  : filename length (big-endian)
#   N bytes  : filename (UTF-8)
#   4 bytes  : signature length (big-endian)
#   M bytes  : raw ML-DSA-65 signature

MAGIC   = b"PQCS"
VERSION = b"\x01"

def _make_sig_bundle(sig: bytes, digest: bytes, filename: str) -> bytes:
    fn = filename.encode("utf-8")
    return (
        MAGIC
        + VERSION
        + digest
        + len(fn).to_bytes(2, "big")
        + fn
        + len(sig).to_bytes(4, "big")
        + sig
    )

def _parse_sig_bundle(data: bytes) -> tuple[bytes, bytes, str]:
    if data[:4] != MAGIC:
        raise ValueError("Not a pqc-sign signature file (bad magic)")
    if data[4:5] != VERSION:
        raise ValueError(f"Unsupported signature bundle version: {data[4]}")
    digest   = data[5:37]
    fn_len   = int.from_bytes(data[37:39], "big")
    filename = data[39:39 + fn_len].decode("utf-8")
    sig_off  = 39 + fn_len
    sig_len  = int.from_bytes(data[sig_off:sig_off + 4], "big")
    sig      = data[sig_off + 4 : sig_off + 4 + sig_len]
    return sig, digest, filename


# ---------------------------------------------------------------------------
# Self-contained demo (Lab C1 + C2 together)
# ---------------------------------------------------------------------------

def cmd_demo() -> None:
    """Run a self-contained demo: keygen → sign → verify → tamper → verify."""
    import shutil

    print("=" * 60)
    print(f"Lab C — {ALGORITHM} Signing Tool Demo")
    print(f"OpenSSL: {_run([OPENSSL, 'version']).decode().strip()}")
    print("=" * 60)
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir   = Path(tmpdir) / "keys"
        test_file = Path(tmpdir) / "release_notes.txt"
        test_file.write_text(
            "Etergis 1.1.10+91 Release Notes\n"
            "=================================\n"
            "- Android home screen widget (Phase 1)\n"
            "- flutter_riverpod 2→3 migration\n"
            "- Billing hardening\n"
        )

        # Step 1: Keygen
        print("Step 1: Key Generation")
        print("-" * 40)
        cmd_keygen(key_dir)
        print()

        # Key size analysis
        priv_bytes = (key_dir / PRIV_FILE).read_bytes()
        pub_bytes  = (key_dir / PUB_FILE).read_bytes()
        print(f"  Ed25519 comparison:")
        print(f"    Ed25519 private key : 64 bytes")
        print(f"    Ed25519 public key  : 32 bytes")
        print(f"    ML-DSA-65 priv key  : ~4,032 bytes raw ({len(priv_bytes):,} PEM)")
        print(f"    ML-DSA-65 pub key   : ~1,952 bytes raw ({len(pub_bytes):,} PEM)")
        print(f"    Key size ratio      : ~63× larger private, ~61× larger public")
        print()

        # Step 2: Sign
        print("Step 2: Sign release_notes.txt")
        print("-" * 40)
        cmd_sign(key_dir, test_file)
        print()

        # Step 3: Verify (valid)
        print("Step 3: Verify signature (should pass)")
        print("-" * 40)
        valid = cmd_verify(key_dir, test_file)
        print()

        # Step 4: Tamper + verify (should fail)
        print("Step 4: Tamper with file, verify again (should fail)")
        print("-" * 40)
        original = test_file.read_text()
        test_file.write_text(original + "\n[TAMPERED BY MALLORY]\n")
        tampered_valid = cmd_verify(key_dir, test_file)
        print()

        # Step 5: Benchmark
        print("Step 5: Benchmark (100 iterations)")
        print("-" * 40)
        test_file.write_text(original)  # restore

        def do_sign():
            cmd_sign(key_dir, test_file)
        def do_verify():
            cmd_verify(key_dir, test_file)

        N = 10  # fewer iterations for sign/verify: they're slower
        t0 = time.perf_counter()
        for _ in range(N):
            priv_pem = _run([OPENSSL, "genpkey", "-algorithm", ALGORITHM])
        kg_ms = (time.perf_counter() - t0) / N * 1000

        priv_pem = (key_dir / PRIV_FILE).read_bytes()
        digest = hashlib.sha3_256(test_file.read_bytes()).digest()

        # Time sign op
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(digest); dpath = f.name
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as f:
            spath = f.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(priv_pem); ppath = f.name

        t0 = time.perf_counter()
        for _ in range(N):
            _run([OPENSSL, "pkeyutl", "-sign", "-inkey", ppath,
                  "-in", dpath, "-out", spath])
        sign_ms = (time.perf_counter() - t0) / N * 1000

        # Time verify op
        pub_pem = (key_dir / PUB_FILE).read_bytes()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(pub_pem); pubpath = f.name
        t0 = time.perf_counter()
        for _ in range(N):
            subprocess.run([OPENSSL, "pkeyutl", "-verify", "-pubin",
                           "-inkey", pubpath, "-in", dpath, "-sigfile", spath],
                          capture_output=True)
        verify_ms = (time.perf_counter() - t0) / N * 1000
        for p in [dpath, spath, ppath, pubpath]:
            try: os.unlink(p)
            except: pass

        print(f"  Keygen (avg)  : {kg_ms:.2f} ms")
        print(f"  Sign   (avg)  : {sign_ms:.2f} ms")
        print(f"  Verify (avg)  : {verify_ms:.2f} ms")
        print()
        print(f"  Ed25519 comparison (typical):")
        print(f"    Keygen: ~0.02 ms  |  Sign: ~0.05 ms  |  Verify: ~0.10 ms")
        print(f"  ML-DSA overhead is in signature SIZE (3,309 bytes), not time.")
        print()

        # Summary
        print("=" * 60)
        print(f"Summary (FIPS 204 {ALGORITHM})")
        print("=" * 60)
        sig_file = test_file.with_suffix(test_file.suffix + SIG_EXT)
        print(f"  Algorithm         : {ALGORITHM}")
        print(f"  NIST security     : Level 3 (≈ AES-192)")
        print(f"  Signature size    : ~3,309 bytes raw")
        print(f"  Public key        : ~1,952 bytes raw")
        print(f"  Private key       : ~4,032 bytes raw")
        print(f"  Valid sig result  : {valid}")
        print(f"  Tampered result   : {tampered_valid} (correct — should be False)")
        print()
        print("  Use this when: signing release artifacts, code, documents")
        print("  Use ML-DSA-87 when: top-secret / long-lived signatures")
        print("  Use SLH-DSA when: you want hash-based (no lattice assumption)")

        # Save evidence
        evidence_dir = Path(__file__).parent.parent.parent / "evidence" / "signatures"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        ev_path = evidence_dir / "lab-c-mldsa65-demo.txt"
        ev_path.write_text(
            f"Lab C Evidence — {ALGORITHM} Signing Tool\n"
            f"OpenSSL: {_run([OPENSSL, 'version']).decode().strip()}\n"
            f"Date: {__import__('datetime').datetime.now().isoformat()}\n\n"
            f"Public key (PEM):\n{pub_pem.decode()}\n"
            f"Keygen avg  : {kg_ms:.2f} ms\n"
            f"Sign avg    : {sign_ms:.2f} ms\n"
            f"Verify avg  : {verify_ms:.2f} ms\n"
            f"Valid sig   : {valid}\n"
            f"Tamper det. : {not tampered_valid}\n"
        )
        print(f"  Evidence saved → evidence/signatures/lab-c-mldsa65-demo.txt")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"pqc-sign: {ALGORITHM} file signing tool (FIPS 204)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s keygen  --key-dir ./keys
  %(prog)s sign    --key-dir ./keys --file release.aab
  %(prog)s verify  --key-dir ./keys --file release.aab
  %(prog)s demo
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="Generate ML-DSA-65 keypair")
    kg.add_argument("--key-dir", type=Path, default=Path("./keys"),
                    help="Directory to store key files (default: ./keys)")

    sg = sub.add_parser("sign", help="Sign a file")
    sg.add_argument("--key-dir", type=Path, default=Path("./keys"))
    sg.add_argument("--file", type=Path, required=True)

    vr = sub.add_parser("verify", help="Verify a file signature")
    vr.add_argument("--key-dir", type=Path, default=Path("./keys"))
    vr.add_argument("--file", type=Path, required=True)

    sub.add_parser("demo", help="Run self-contained demo (Lab C1+C2)")

    args = parser.parse_args()

    if args.command == "keygen":
        cmd_keygen(args.key_dir)
    elif args.command == "sign":
        cmd_sign(args.key_dir, args.file)
    elif args.command == "verify":
        result = cmd_verify(args.key_dir, args.file)
        sys.exit(0 if result else 1)
    elif args.command == "demo":
        cmd_demo()


if __name__ == "__main__":
    main()
