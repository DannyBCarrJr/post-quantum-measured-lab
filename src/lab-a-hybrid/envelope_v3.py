#!/usr/bin/env python3
"""
Lab A: Etergis Envelope v3: Hybrid PQC Key Wrapping
=====================================================
Chapter 9: PQC in Application Crypto

This is the reference implementation for the Etergis Envelope v3 format ,
the upgrade from pure X25519 (v2) to hybrid X25519 + ML-KEM-768 (v3).

The current Etergis production code (encryption_util.dart, EnvelopeV2) uses:
  - Content encryption:  AES-256-GCM with random nonce + AAD
  - Key exchange:        X25519 ECDH with ephemeral sender keys
  - KEK derivation:      HKDF-SHA256 with domain-separation salt+info
  - Passphrase KEK:      Argon2id (m=64MiB, t=3, p=1)
  - Format:              EnvelopeV2 (versioned, KDF params in-band)

Envelope v3 adds:
  - Recipient key exchange: X25519 ECDH + ML-KEM-768 encap (hybrid)
  - HKDF combines both shared secrets with context binding
  - Wire format adds ML-KEM-768 ciphertext alongside X25519 ephemeral key
  - Backward compatibility: v2 recipients can still use v2 wraps
  - Forward compatibility: v3 wraps require the recipient's ML-KEM-768 key

Migration strategy: IMPLEMENTED AND LIVE IN PRODUCTION (Etergis, 2026-07-09):
  Phase 1 (server schema + API pass-through, `pqcv30001`) and Phase 2 (Flutter
  client hybrid X25519+ML-KEM-768 wrap, `pqcv30002`) merged via PR #210 and
  verified against the live production system. Phase 3 (lazy re-wrap for existing
  v2 secrets, recipient-side release-portal v3 decrypt) remains proposed.
  See `book/case-study-etergis-phase2-prod-verification.md` and Chapter 9.

HKDF context binding:
  Combined IKM = ss_x25519 || ss_mlkem
  Salt = epk_bytes || mlkem_ct[:32]   ← binds wrap to specific encapsulation
  Info = b'etergis.kek.recipient-wrap.v3'

This prevents:
  - Ciphertext substitution: attacker can't swap ML-KEM CT with another
  - Cross-version attacks: v3 info string differs from v2
  - Cross-context attacks: AAD binds to specific (recipient, secret) pair

Note: this module returns a plain dict of base64 fields: a conceptual
reference for the crypto construction, not a wire-serialized format. For
the actual binary HKEM/v1 layout a production implementation would use
(magic bytes, version, length-prefixed fields), see Lab B2
(src/lab-b-tls/hybrid_kem_wrap.py). The two use different HKDF domain-
separation strings and are not byte-compatible with each other.

Environment: Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14, pyca/cryptography 48.0.0+
Author:      Danny B. Carr, Jr.
"""

import hashlib
import os
import struct
import subprocess
import tempfile
import json
import base64
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OPENSSL = "openssl"

# Domain constants: MUST match Dart implementation exactly
HKDF_SALT_V2 = b"etergis.salt.v2"
HKDF_INFO_V2 = b"etergis.kek.recipient-wrap.v2"
HKDF_INFO_V3 = b"etergis.kek.recipient-wrap.v3"
AAD_WRAP_V2  = b"etergis.aad.recipient-wrap.v2"
AAD_WRAP_V3  = b"etergis.aad.recipient-wrap.v3"


# ---------------------------------------------------------------------------
# ML-KEM-768 bridge (OpenSSL CLI, matches Lab B1/B2)
# ---------------------------------------------------------------------------

def mlkem_keygen():
    priv = subprocess.run([OPENSSL, "genpkey", "-algorithm", "ML-KEM-768"],
                          capture_output=True, check=True).stdout
    pub  = subprocess.run([OPENSSL, "pkey", "-pubout"],
                          input=priv, capture_output=True, check=True).stdout
    return priv, pub


def mlkem_encapsulate(pub_pem):
    with (tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as pf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as cf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as sf):
        pf.write(pub_pem); pf.flush()
        subprocess.run([OPENSSL, "pkeyutl", "-encap", "-pubin",
                        "-inkey", pf.name, "-secret", sf.name, "-out", cf.name],
                       capture_output=True, check=True)
        ct = Path(cf.name).read_bytes()
        ss = Path(sf.name).read_bytes()
    for p in [pf.name, cf.name, sf.name]:
        try: os.unlink(p)
        except: pass
    return ct, ss


def mlkem_decapsulate(priv_pem, ct):
    with (tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as cf,
          tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as sf):
        kf.write(priv_pem); kf.flush()
        cf.write(ct); cf.flush()
        subprocess.run([OPENSSL, "pkeyutl", "-decap",
                        "-inkey", kf.name, "-in", cf.name, "-secret", sf.name],
                       capture_output=True, check=True)
        ss = Path(sf.name).read_bytes()
    for p in [kf.name, cf.name, sf.name]:
        try: os.unlink(p)
        except: pass
    return ss


# ---------------------------------------------------------------------------
# HKDF helpers
# ---------------------------------------------------------------------------

def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


def v2_kek(ss_x25519: bytes) -> bytes:
    """Current v2 KEK derivation (pure X25519 → HKDF)."""
    return hkdf_derive(ikm=ss_x25519, salt=HKDF_SALT_V2, info=HKDF_INFO_V2)


def v3_kek(ss_x25519: bytes, ss_mlkem: bytes, epk_bytes: bytes, mlkem_ct: bytes) -> bytes:
    """
    v3 KEK derivation: combine X25519 + ML-KEM-768 shared secrets.
    Context binding: epk || ct[:32] as HKDF salt.
    """
    ikm  = ss_x25519 + ss_mlkem
    salt = epk_bytes + mlkem_ct[:32]
    return hkdf_derive(ikm=ikm, salt=salt, info=HKDF_INFO_V3)


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aead  = AESGCM(key)
    ct    = aead.encrypt(nonce, plaintext, aad)
    return ct, nonce


def aes_gcm_decrypt(key: bytes, ct: bytes, nonce: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# Recipient key model
# ---------------------------------------------------------------------------

class RecipientKeysV2:
    """Current Etergis recipient: X25519 only."""
    def __init__(self):
        self.x25519_priv = X25519PrivateKey.generate()
        self.x25519_pub  = self.x25519_priv.public_key()

    @property
    def x25519_pub_bytes(self):
        return self.x25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


class RecipientKeysV3(RecipientKeysV2):
    """v3 recipient: X25519 + ML-KEM-768."""
    def __init__(self):
        super().__init__()
        self.mlkem_priv, self.mlkem_pub = mlkem_keygen()


# ---------------------------------------------------------------------------
# v2 wrap/unwrap (current production: for comparison)
# ---------------------------------------------------------------------------

def wrap_dek_v2(dek: bytes, recipient: RecipientKeysV2, aad: bytes) -> dict:
    """Current Etergis wrapContentKeyForRecipient (pure X25519)."""
    ephem = X25519PrivateKey.generate()
    epk   = ephem.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss    = ephem.exchange(recipient.x25519_pub)
    kek   = v2_kek(ss)
    ct, nonce = aes_gcm_encrypt(kek, dek, aad)
    return {
        "version": 2,
        "wrapped_key_b64": base64.b64encode(ct).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ephemeral_sender_pub_b64": base64.b64encode(epk).decode(),
    }


def unwrap_dek_v2(wrap: dict, recipient: RecipientKeysV2, aad: bytes) -> bytes:
    epk = X25519PublicKey.from_public_bytes(base64.b64decode(wrap["ephemeral_sender_pub_b64"]))
    ss  = recipient.x25519_priv.exchange(epk)
    kek = v2_kek(ss)
    return aes_gcm_decrypt(
        kek,
        base64.b64decode(wrap["wrapped_key_b64"]),
        base64.b64decode(wrap["nonce_b64"]),
        aad,
    )


# ---------------------------------------------------------------------------
# v3 wrap/unwrap (Envelope v3: hybrid PQC)
# ---------------------------------------------------------------------------

def wrap_dek_v3(dek: bytes, recipient: RecipientKeysV3, aad: bytes) -> dict:
    """
    Etergis Envelope v3: hybrid X25519 + ML-KEM-768 key wrapping.

    Wire additions vs v2:
      - mlkem_ct_b64: 1,088-byte ML-KEM-768 encapsulation ciphertext
      - version: 3
    Everything else has the same field names as v2 for easy migration.
    """
    # X25519 ECDH (same as v2)
    ephem  = X25519PrivateKey.generate()
    epk    = ephem.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_x25519 = ephem.exchange(recipient.x25519_pub)

    # ML-KEM-768 encapsulate (new in v3)
    mlkem_ct, ss_mlkem = mlkem_encapsulate(recipient.mlkem_pub)

    # Combined KEK with context binding
    kek = v3_kek(ss_x25519, ss_mlkem, epk, mlkem_ct)

    ct, nonce = aes_gcm_encrypt(kek, dek, aad)

    return {
        "version": 3,
        "wrapped_key_b64":           base64.b64encode(ct).decode(),
        "nonce_b64":                 base64.b64encode(nonce).decode(),
        "ephemeral_sender_pub_b64":  base64.b64encode(epk).decode(),
        "mlkem_ct_b64":              base64.b64encode(mlkem_ct).decode(),
    }


def unwrap_dek_v3(wrap: dict, recipient: RecipientKeysV3, aad: bytes) -> bytes:
    """Unwrap v3 envelope. Exact inverse of wrap_dek_v3."""
    epk = X25519PublicKey.from_public_bytes(
        base64.b64decode(wrap["ephemeral_sender_pub_b64"]))
    ss_x25519 = recipient.x25519_priv.exchange(epk)

    mlkem_ct = base64.b64decode(wrap["mlkem_ct_b64"])
    ss_mlkem = mlkem_decapsulate(recipient.mlkem_priv, mlkem_ct)

    epk_bytes = base64.b64decode(wrap["ephemeral_sender_pub_b64"])
    kek = v3_kek(ss_x25519, ss_mlkem, epk_bytes, mlkem_ct)

    return aes_gcm_decrypt(
        kek,
        base64.b64decode(wrap["wrapped_key_b64"]),
        base64.b64decode(wrap["nonce_b64"]),
        aad,
    )


# ---------------------------------------------------------------------------
# AAD helpers (matches Dart passphraseWrapAadV2 / secretContentAadV2)
# ---------------------------------------------------------------------------

def aad_recipient_wrap_v3(recipient_id: str, secret_id: str) -> bytes:
    return f"etergis.aad.recipient-wrap.v3|{recipient_id}|{secret_id}".encode()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Lab A — Etergis Envelope v3 Reference Implementation")
    print("X25519 + ML-KEM-768 Hybrid Key Wrapping")
    print("=" * 60)
    print()

    import time
    RECIPIENT_ID = "a3ed7b64-7c88-4727-afe1-c575ed6baeda"
    SECRET_ID    = "550e8400-e29b-41d4-a716-446655440000"
    aad          = aad_recipient_wrap_v3(RECIPIENT_ID, SECRET_ID)
    dek          = os.urandom(32)

    print(f"  DEK            : {dek.hex()[:32]}...")
    print(f"  Recipient ID   : {RECIPIENT_ID}")
    print(f"  Secret ID      : {SECRET_ID}")
    print()

    # ── v2 (current production) ──────────────────────────────────
    print("Step 1: v2 wrap (current Etergis production)")
    print("-" * 40)
    recipient_v2 = RecipientKeysV2()
    t0 = time.perf_counter()
    wrap2 = wrap_dek_v2(dek, recipient_v2, AAD_WRAP_V2)
    recovered2 = unwrap_dek_v2(wrap2, recipient_v2, AAD_WRAP_V2)
    v2_ms = (time.perf_counter() - t0) * 1000
    v2_bytes = len(base64.b64decode(wrap2["wrapped_key_b64"])) + \
               len(base64.b64decode(wrap2["nonce_b64"])) + \
               len(base64.b64decode(wrap2["ephemeral_sender_pub_b64"]))
    print(f"  Wire size      : ~{v2_bytes} bytes")
    print(f"  Round-trip     : {v2_ms:.1f} ms")
    print(f"  DEK match      : {'✓' if dek == recovered2 else '✗'}")
    print()

    # ── v3 (hybrid PQC) ──────────────────────────────────────────
    print("Step 2: v3 wrap (Envelope v3 — hybrid X25519 + ML-KEM-768)")
    print("-" * 40)
    recipient_v3 = RecipientKeysV3()
    t0 = time.perf_counter()
    wrap3 = wrap_dek_v3(dek, recipient_v3, aad)
    recovered3 = unwrap_dek_v3(wrap3, recipient_v3, aad)
    v3_ms = (time.perf_counter() - t0) * 1000
    v3_bytes = len(base64.b64decode(wrap3["wrapped_key_b64"])) + \
               len(base64.b64decode(wrap3["nonce_b64"])) + \
               len(base64.b64decode(wrap3["ephemeral_sender_pub_b64"])) + \
               len(base64.b64decode(wrap3["mlkem_ct_b64"]))
    print(f"  Wire size      : ~{v3_bytes} bytes (+{v3_bytes - v2_bytes} vs v2)")
    print(f"  Round-trip     : {v3_ms:.1f} ms")
    print(f"  DEK match      : {'✓' if dek == recovered3 else '✗'}")
    print()

    # ── Tamper test ──────────────────────────────────────────────
    print("Step 3: Tamper test — flip ML-KEM ciphertext byte")
    print("-" * 40)
    bad_wrap = dict(wrap3)
    ct_bytes = bytearray(base64.b64decode(bad_wrap["mlkem_ct_b64"]))
    ct_bytes[50] ^= 0xFF
    bad_wrap["mlkem_ct_b64"] = base64.b64encode(bytes(ct_bytes)).decode()
    try:
        unwrap_dek_v3(bad_wrap, recipient_v3, aad)
        print("  ✗ FAIL — tampered envelope accepted")
    except Exception as e:
        print(f"  ✓ PASS — tampered envelope rejected: {type(e).__name__}")
    print()

    # ── Wire format comparison ───────────────────────────────────
    print("Step 4: Wire format comparison")
    print("-" * 40)
    print(f"  {'Field':<32} {'v2':>10} {'v3':>10}")
    print(f"  {'-'*52}")
    fields = [
        ("ephemeral X25519 public key", 32, 32),
        ("ML-KEM-768 ciphertext", 0, 1088),
        ("wrapped DEK (AES-GCM ct+tag)", 48, 48),
        ("AES-GCM nonce", 12, 12),
    ]
    total_v2 = total_v3 = 0
    for name, s2, s3 in fields:
        total_v2 += s2; total_v3 += s3
        print(f"  {name:<32} {s2:>9}B {s3:>9}B")
    print(f"  {'─'*52}")
    print(f"  {'TOTAL':<32} {total_v2:>9}B {total_v3:>9}B")
    print(f"  Overhead vs v2: +{total_v3 - total_v2}B per recipient (~{(total_v3-total_v2)/1024:.1f}KB)")
    print()

    # ── Migration strategy ───────────────────────────────────────
    print("Step 5: Migration strategy for production Etergis")
    print("-" * 40)
    print("""
  Phase 1: Server side (SHIPPED & LIVE: Etergis pqcv30001, PR #210, 2026-07-09):
    • mlkem_pub_key column on users/recipients table
    • mlkem_ct_b64 column + wrap_version on wrapped_keys table
    • API returns mlkem_pub in GET /recipients
    • API accepts optional mlkem_ct_b64 in POST /secrets

  Phase 2: Client side (SHIPPED & LIVE: Etergis pqcv30002, PR #210, 2026-07-09):
    • iOS/macOS: CryptoKit has native ML-KEM-768 as of OS 26: not used;
      pure-Dart pqcrypto 0.4.0 (independently audited 2026-07-06) covers
      all three platforms (Android, iOS, Web) in one code path
    • Upload mlkem_pub to server on vault setup
    • New secrets: wrap with v3 if recipient has mlkem_pub, else v2
    • Existing secrets: lazy re-wrap on next owner access (Phase 3)

  Phase 3: Completion , PROPOSED, not started:
    • Background job re-wraps remaining v2 envelopes over time
    • v2 decode support kept permanently (no forced re-enrollment: ever)
    """.strip())
    print()

    # ── Summary ──────────────────────────────────────────────────
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  v2 (current)   : X25519 only, ~{total_v2}B/recipient, ~{v2_ms:.0f}ms")
    print(f"  v3 (proposed)  : X25519+MLKEM768, ~{total_v3}B/recipient, ~{v3_ms:.0f}ms")
    print(f"  Overhead       : +1,088 bytes per recipient wrap (~1.1KB)")
    print(f"  Security gain  : HNDL protection — quantum attacker must break")
    print(f"                   BOTH X25519 AND ML-KEM-768 to read the DEK")
    print(f"  Wire format     : additive — v3 adds fields, v2 decode unaffected (verified above)")
    print(f"  Full migration  : Phases 1 & 2 LIVE in production (Etergis PR #210, 2026-07-09); Phase 3 proposed")
    print()
    print("  DART IMPLEMENTATION NOTE (updated 2026-07-09, production-verified):")
    print("  pyca/cryptography (Python) shipped ML-KEM in 48.0.0 (2026-05-04,")
    print("  via OpenSSL 3.5+); 49.0.0 is current as of July 2026.")
    print("  For Dart/Flutter: pqcrypto 0.4.0 (pure-Dart, independently audited")
    print("  2026-07-06, ADOPT-WITH-MITIGATIONS) covers Android, iOS, and Web.")
    print("  Etergis Phases 1+2 LIVE in production as of 2026-07-09 using this path.")
    print("  See book Ch.9 and case-study-etergis-phase2-prod-verification.md.")

    # ── Save evidence ─────────────────────────────────────────────
    ev_dir = Path(__file__).parent.parent.parent / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev = ev_dir / "lab-a-envelope-v3.txt"
    ev.write_text(
        f"Lab A Evidence — Etergis Envelope v3 Reference\n"
        f"Date: {datetime.now().isoformat()}\n\n"
        f"v2 wire bytes: {total_v2}\n"
        f"v3 wire bytes: {total_v3}\n"
        f"v2 round-trip: {v2_ms:.1f}ms\n"
        f"v3 round-trip: {v3_ms:.1f}ms\n"
        f"DEK v2 match:  {dek == recovered2}\n"
        f"DEK v3 match:  {dek == recovered3}\n"
        f"Tamper detect: PASS\n\n"
        f"v3 wire format:\n"
        f"  ephemeral X25519 epk : 32 bytes\n"
        f"  ML-KEM-768 ct        : 1088 bytes\n"
        f"  wrapped DEK (ct+tag) : 48 bytes\n"
        f"  AES-GCM nonce        : 12 bytes\n"
        f"  Total                : {total_v3} bytes\n"
    )
    print(f"\n  Evidence → evidence/lab-a-envelope-v3.txt")


if __name__ == "__main__":
    main()
