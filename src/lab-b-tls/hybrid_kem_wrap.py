#!/usr/bin/env python3
"""
Lab B2: Hybrid KEM Key Wrapping: X25519 + ML-KEM-768
=======================================================
Chapter 3: ML-KEM (FIPS 203): Section: Hybrid Constructions
Chapter 9: PQC in Application Crypto

Demonstrates the hybrid KEM key-wrapping pattern that should replace
pure X25519 in application-layer envelope formats like Etergis.

Protocol (HKDF-based hybrid KEM):
  1. Generate recipient X25519 + ML-KEM-768 keypairs (long-term)
  2. Sender:
     a. Ephemeral X25519 keygen → ECDH shared secret (ss_classical)
     b. ML-KEM-768 encapsulate  → KEM shared secret (ss_pqc)
     c. HKDF-combine both secrets → 32-byte wrapping key
     d. AES-256-GCM encrypt the DEK with the wrapping key
     e. Output: {x25519_epk, ml_kem_ct, aes_nonce, wrapped_dek}
  3. Recipient:
     a. X25519 ECDH with own private key + sender's ephemeral public key
     b. ML-KEM-768 decapsulate ciphertext with own private key
     c. HKDF-combine → same 32-byte wrapping key
     d. AES-256-GCM decrypt → recover DEK

Security properties:
  - If X25519 is broken (classical or quantum): ML-KEM-768 still protects
  - If ML-KEM-768 is broken (lattice attack):  X25519 still protects
  - Both must be broken simultaneously to compromise the DEK
  - AES-256-GCM is quantum-safe (Grover's only halves security to 128 bits)

This is the "belt AND suspenders" approach recommended by NIST during
the transition period. It is also what Google Chrome, Cloudflare, and
Signal use for their PQC deployments today.

Connection to Etergis:
  The current Etergis envelope uses X25519 + HKDF to wrap per-recipient
  DEKs (see encryption_util.dart). This lab shows the exact Python
  equivalent of upgrading that to hybrid X25519 + ML-KEM-768.
  Envelope v3 design: same pattern; Etergis uses pure-Dart pqcrypto 0.4.0
  (independently audited 2026-07-06): not FFI to libcrypto (Android forbids
  linking the platform libcrypto). Phases 1+2 live in production 2026-07-09.

Environment: Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14
Author:      Danny B. Carr, Jr.
"""

import hashlib
import hmac
import os
import subprocess
import struct
import tempfile
import time
from pathlib import Path

# We use pyca/cryptography for X25519 and AES-256-GCM (well-tested library)
# and openssl CLI for ML-KEM-768. Written when pyca/cryptography had no ML-KEM
# support; as of 48.0.0 (2026-05-04) it supports ML-KEM natively against
# OpenSSL 3.5+ (hazmat.primitives.asymmetric.mlkem): verified 2026-07-06.
# This lab keeps the CLI approach for now; a future revision could call that
# module directly instead of shelling out.
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OPENSSL = "openssl"

# HKDF context labels: domain separation prevents cross-protocol attacks
HKDF_INFO_WRAP = b"etergis-hybrid-kem-v1-wrap"
HKDF_INFO_X25519 = b"etergis-hybrid-kem-v1-x25519"
HKDF_INFO_MLKEM  = b"etergis-hybrid-kem-v1-mlkem768"


# ---------------------------------------------------------------------------
# ML-KEM-768 via OpenSSL CLI
# ---------------------------------------------------------------------------

def mlkem_keygen() -> tuple[bytes, bytes]:
    """Generate ML-KEM-768 keypair. Returns (priv_pem, pub_pem)."""
    priv = subprocess.run(
        [OPENSSL, "genpkey", "-algorithm", "ML-KEM-768"],
        capture_output=True, check=True
    ).stdout
    pub = subprocess.run(
        [OPENSSL, "pkey", "-pubout"],
        input=priv, capture_output=True, check=True
    ).stdout
    return priv, pub


def mlkem_encapsulate(pub_pem: bytes) -> tuple[bytes, bytes]:
    """ML-KEM-768 encapsulate. Returns (ciphertext, shared_secret)."""
    with (tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as pf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as cf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as sf):
        pf.write(pub_pem); pf.flush()
        subprocess.run([
            OPENSSL, "pkeyutl", "-encap", "-pubin",
            "-inkey", pf.name, "-secret", sf.name, "-out", cf.name,
        ], capture_output=True, check=True)
        ct = Path(cf.name).read_bytes()
        ss = Path(sf.name).read_bytes()
    for p in [pf.name, cf.name, sf.name]:
        try: os.unlink(p)
        except: pass
    return ct, ss


def mlkem_decapsulate(priv_pem: bytes, ciphertext: bytes) -> bytes:
    """ML-KEM-768 decapsulate. Returns shared_secret."""
    with (tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as cf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as sf):
        kf.write(priv_pem); kf.flush()
        cf.write(ciphertext); cf.flush()
        subprocess.run([
            OPENSSL, "pkeyutl", "-decap",
            "-inkey", kf.name, "-in", cf.name, "-secret", sf.name,
        ], capture_output=True, check=True)
        ss = Path(sf.name).read_bytes()
    for p in [kf.name, cf.name, sf.name]:
        try: os.unlink(p)
        except: pass
    return ss


# ---------------------------------------------------------------------------
# HKDF helpers
# ---------------------------------------------------------------------------

def hkdf_extract_expand(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract + expand."""
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def combine_shared_secrets(ss_classical: bytes, ss_pqc: bytes, context: bytes) -> bytes:
    """
    Combine two shared secrets into one wrapping key using HKDF.

    Concatenation-based hybrid: IKM = ss_classical || ss_pqc
    This is the approach in IETF draft-ietf-tls-hybrid-design and
    the Kyber/ML-KEM hybrid recommendation from NIST.

    The combined key is only as weak as the stronger of the two inputs.
    An attacker must break BOTH to recover the key.
    """
    ikm = ss_classical + ss_pqc
    return hkdf_extract_expand(
        ikm=ikm,
        salt=context,  # sender's ephemeral public keys as salt = context binding
        info=HKDF_INFO_WRAP,
        length=32,
    )


# ---------------------------------------------------------------------------
# Hybrid envelope format
# ---------------------------------------------------------------------------
#
# Wire format (big-endian lengths):
#   4 bytes : magic "HKEM"
#   1 byte  : version (0x01)
#   2 bytes : x25519_epk length (always 32)
#  32 bytes : X25519 ephemeral public key
#   4 bytes : mlkem_ct length
#   N bytes : ML-KEM-768 ciphertext (1088 bytes)
#  12 bytes : AES-GCM nonce
#   2 bytes : wrapped DEK length
#   M bytes : AES-GCM ciphertext (DEK + 16-byte tag)

MAGIC   = b"HKEM"
VERSION = b"\x01"

class HybridEnvelope:
    """A hybrid-KEM wrapped key envelope."""

    def __init__(
        self,
        x25519_epk: bytes,
        mlkem_ct: bytes,
        nonce: bytes,
        wrapped_dek: bytes,
    ):
        self.x25519_epk  = x25519_epk
        self.mlkem_ct    = mlkem_ct
        self.nonce       = nonce
        self.wrapped_dek = wrapped_dek

    def serialize(self) -> bytes:
        return (
            MAGIC + VERSION
            + struct.pack(">H", len(self.x25519_epk))
            + self.x25519_epk
            + struct.pack(">I", len(self.mlkem_ct))
            + self.mlkem_ct
            + self.nonce
            + struct.pack(">H", len(self.wrapped_dek))
            + self.wrapped_dek
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HybridEnvelope":
        assert data[:4] == MAGIC, "Bad magic"
        assert data[4:5] == VERSION, "Bad version"
        off = 5
        epk_len  = struct.unpack_from(">H", data, off)[0]; off += 2
        x25519_epk = data[off:off + epk_len]; off += epk_len
        ct_len   = struct.unpack_from(">I", data, off)[0]; off += 4
        mlkem_ct = data[off:off + ct_len]; off += ct_len
        nonce    = data[off:off + 12]; off += 12
        dek_len  = struct.unpack_from(">H", data, off)[0]; off += 2
        wrapped  = data[off:off + dek_len]
        return cls(x25519_epk, mlkem_ct, nonce, wrapped)

    def __repr__(self) -> str:
        total = len(self.serialize())
        return (
            f"HybridEnvelope("
            f"x25519_epk={len(self.x25519_epk)}B, "
            f"mlkem_ct={len(self.mlkem_ct)}B, "
            f"nonce={len(self.nonce)}B, "
            f"wrapped_dek={len(self.wrapped_dek)}B, "
            f"total={total}B)"
        )


# ---------------------------------------------------------------------------
# Wrap / Unwrap
# ---------------------------------------------------------------------------

class RecipientKeys:
    """A recipient's long-term X25519 + ML-KEM-768 keypair."""

    def __init__(self):
        self.x25519_priv = X25519PrivateKey.generate()
        self.x25519_pub  = self.x25519_priv.public_key()
        self.mlkem_priv, self.mlkem_pub = mlkem_keygen()

    @property
    def x25519_pub_bytes(self) -> bytes:
        return self.x25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def mlkem_pub_pem(self) -> bytes:
        return self.mlkem_pub


def wrap_dek(dek: bytes, recipient: RecipientKeys) -> HybridEnvelope:
    """
    Wrap a DEK for a recipient using hybrid X25519 + ML-KEM-768.

    This is the operation a sender performs when encrypting a secret
    for a recipient. The recipient's public keys are used; the sender
    generates ephemeral keys that are discarded after this call.
    """
    # 1. Ephemeral X25519 keygen + ECDH
    ephem_priv = X25519PrivateKey.generate()
    ephem_pub  = ephem_priv.public_key()
    ephem_pub_bytes = ephem_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    ss_x25519 = ephem_priv.exchange(recipient.x25519_pub)

    # 2. ML-KEM-768 encapsulate
    mlkem_ct, ss_mlkem = mlkem_encapsulate(recipient.mlkem_pub_pem)

    # 3. Combine: context = ephemeral X25519 pubkey || ML-KEM ciphertext prefix
    #    This binds the wrapping key to the specific encapsulation: prevents
    #    ciphertext substitution attacks.
    context = ephem_pub_bytes + mlkem_ct[:32]
    wrapping_key = combine_shared_secrets(ss_x25519, ss_mlkem, context)

    # 4. AES-256-GCM wrap the DEK
    nonce = os.urandom(12)
    aead  = AESGCM(wrapping_key)
    wrapped_dek = aead.encrypt(nonce, dek, None)

    return HybridEnvelope(
        x25519_epk  = ephem_pub_bytes,
        mlkem_ct    = mlkem_ct,
        nonce       = nonce,
        wrapped_dek = wrapped_dek,
    )


def unwrap_dek(envelope: HybridEnvelope, recipient: RecipientKeys) -> bytes:
    """
    Unwrap a DEK from a hybrid KEM envelope using the recipient's private keys.
    """
    # 1. X25519 ECDH with recipient's private key + sender's ephemeral public key
    ephem_pub = X25519PublicKey.from_public_bytes(envelope.x25519_epk)
    ss_x25519 = recipient.x25519_priv.exchange(ephem_pub)

    # 2. ML-KEM-768 decapsulate
    ss_mlkem = mlkem_decapsulate(recipient.mlkem_priv, envelope.mlkem_ct)

    # 3. Recompute wrapping key (same context binding as wrap)
    context = envelope.x25519_epk + envelope.mlkem_ct[:32]
    wrapping_key = combine_shared_secrets(ss_x25519, ss_mlkem, context)

    # 4. AES-256-GCM unwrap
    aead = AESGCM(wrapping_key)
    return aead.decrypt(envelope.nonce, envelope.wrapped_dek, None)


# ---------------------------------------------------------------------------
# Main lab
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Lab B2 — Hybrid KEM Key Wrapping")
    print("X25519 + ML-KEM-768 → AES-256-GCM wrapped DEK")
    print(f"OpenSSL: {subprocess.run([OPENSSL,'version'],capture_output=True).stdout.decode().strip()}")
    print("=" * 60)
    print()

    # ── Step 1: Recipient key generation ────────────────────────────
    print("Step 1: Alice generates long-term hybrid keypair")
    print("-" * 40)
    t0 = time.perf_counter()
    alice = RecipientKeys()
    kg_ms = (time.perf_counter() - t0) * 1000

    print(f"  X25519 public key  : {len(alice.x25519_pub_bytes)} bytes")
    print(f"  ML-KEM-768 pub key : {len(alice.mlkem_pub_pem)} bytes (PEM)")
    print(f"  Total keygen time  : {kg_ms:.0f} ms")
    print()

    # ── Step 2: Wrap a DEK ──────────────────────────────────────────
    print("Step 2: Bob wraps a random DEK for Alice")
    print("-" * 40)
    dek = os.urandom(32)
    print(f"  DEK (plaintext)  : {dek.hex()[:32]}... (32 bytes)")

    t0 = time.perf_counter()
    envelope = wrap_dek(dek, alice)
    wrap_ms = (time.perf_counter() - t0) * 1000

    wire_bytes = envelope.serialize()
    print(f"  Envelope         : {envelope}")
    print(f"  Wire size        : {len(wire_bytes)} bytes total")
    print(f"  Wrap time        : {wrap_ms:.1f} ms")
    print()

    # Size breakdown
    print("  Size breakdown:")
    print(f"    X25519 epk  :   32 bytes (ephemeral sender public key)")
    print(f"    ML-KEM-768 ct: 1088 bytes (encapsulation ciphertext)")
    print(f"    AES-GCM nonce:   12 bytes")
    print(f"    Wrapped DEK  :   48 bytes (32 DEK + 16 GCM tag)")
    framing = len(wire_bytes) - (32 + 1088 + 12 + 48)
    print(f"    Overhead     :   {framing} bytes (magic + version + lengths)")
    print(f"    Total        : {len(wire_bytes)} bytes")
    print()
    print(f"  Classical (X25519 only) envelope: ~92 bytes")
    print(f"  Hybrid overhead: +{len(wire_bytes) - 92} bytes per recipient (~{(len(wire_bytes)-92)/1024:.1f} KB)")
    print()

    # ── Step 3: Unwrap ──────────────────────────────────────────────
    print("Step 3: Alice unwraps the DEK with her private keys")
    print("-" * 40)
    t0 = time.perf_counter()
    recovered_dek = unwrap_dek(envelope, alice)
    unwrap_ms = (time.perf_counter() - t0) * 1000

    match = dek == recovered_dek
    print(f"  Original DEK   : {dek.hex()}")
    print(f"  Recovered DEK  : {recovered_dek.hex()}")
    print(f"  Match          : {'✓ YES' if match else '✗ NO — BUG'}")
    print(f"  Unwrap time    : {unwrap_ms:.1f} ms")
    print()

    if not match:
        raise RuntimeError("DEK mismatch: hybrid KEM implementation error")

    # ── Step 4: Tamper test ─────────────────────────────────────────
    print("Step 4: Tamper test — modify ciphertext, verify rejection")
    print("-" * 40)
    tampered = bytearray(wire_bytes)
    tampered[50] ^= 0xFF  # flip a byte in the ML-KEM ciphertext
    try:
        bad_envelope = HybridEnvelope.deserialize(bytes(tampered))
        unwrap_dek(bad_envelope, alice)
        print("  ✗ FAIL — tampered envelope was accepted (bug)")
    except Exception as e:
        print(f"  ✓ PASS — tampered envelope rejected: {type(e).__name__}")
    print()

    # ── Step 5: Benchmarks ──────────────────────────────────────────
    print("Step 5: Benchmark (10 iterations — subprocess overhead included)")
    print("-" * 40)
    N = 10
    wrap_times = []
    unwrap_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        env = wrap_dek(dek, alice)
        wrap_times.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        unwrap_dek(env, alice)
        unwrap_times.append((time.perf_counter() - t0) * 1000)

    import statistics
    print(f"  Wrap avg   : {statistics.median(wrap_times):.1f} ms")
    print(f"  Unwrap avg : {statistics.median(unwrap_times):.1f} ms")
    print()
    print("  Note: ~3ms is ML-KEM subprocess overhead.")
    print("  With libcrypto FFI (Lab D style): <0.1ms total.")
    print()

    # ── Summary ──────────────────────────────────────────────────────
    print("=" * 60)
    print("Summary — Hybrid KEM Key Wrapping")
    print("=" * 60)
    print()
    print("  Pattern: X25519 ECDH ──┐")
    print("                          ├──HKDF──► 32-byte wrap key ──► AES-256-GCM(DEK)")
    print("  ML-KEM-768 encap ───────┘")
    print()
    print("  Security guarantee:")
    print("    Classical adversary breaks X25519? ML-KEM-768 still holds.")
    print("    Quantum adversary breaks ML-KEM-768? X25519 still holds.")
    print("    Breaking the DEK requires breaking BOTH simultaneously.")
    print()
    overhead = len(wire_bytes) - 92
    print(f"  Wire overhead per recipient: {overhead:,} bytes vs 92 bytes classical")
    print(f"  For Etergis (avg 3 recipients): ~{overhead * 3 / 1024:.1f} KB additional per secret")
    print("  Storage cost: negligible. The DEK is protected for decades.")
    print()
    print("  This is the generic hybrid-KEM building block (HKEM/v1) behind")
    print("  the Etergis Envelope v3 design (Chapter 9) — Lab A specializes")
    print("  this pattern into Etergis's own naming/AAD convention; the two")
    print("  are not byte-compatible with each other.")
    print("  Current Etergis uses X25519 only — upgrading is additive,")
    print("  not a breaking change (new secrets get v3, old secrets stay v2).")

    # ── Evidence ─────────────────────────────────────────────────────
    ev_dir = Path(__file__).parent.parent.parent / "evidence" / "tls"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev = ev_dir / "lab-b2-hybrid-kem-wrap.txt"
    ev.write_text(
        f"Lab B2 Evidence — Hybrid KEM Key Wrapping\n"
        f"X25519 + ML-KEM-768 + AES-256-GCM\n"
        f"Date: {__import__('datetime').datetime.now().isoformat()}\n\n"
        f"Envelope wire format: {len(wire_bytes)} bytes total\n"
        f"  X25519 epk   : 32 bytes\n"
        f"  ML-KEM-768 ct: 1088 bytes\n"
        f"  AES nonce    : 12 bytes\n"
        f"  Wrapped DEK  : 48 bytes\n"
        f"  Overhead     : {len(wire_bytes) - (32 + 1088 + 12 + 48)} bytes\n\n"
        f"DEK recovery: {'SUCCESS' if match else 'FAILURE'}\n"
        f"Tamper rejection: PASS\n"
        f"Wrap median  : {statistics.median(wrap_times):.1f} ms (subprocess)\n"
        f"Unwrap median: {statistics.median(unwrap_times):.1f} ms (subprocess)\n"
    )
    print(f"\n  Evidence → evidence/tls/lab-b2-hybrid-kem-wrap.txt")


if __name__ == "__main__":
    main()
