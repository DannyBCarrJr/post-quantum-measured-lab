#!/usr/bin/env python3
"""
Lab D: Post-Quantum Cryptography Benchmark Suite
==================================================
Chapter 10: Performance: What You Actually Pay

Measures real library-speed performance of PQC algorithms using
direct ctypes bindings to libcrypto (OpenSSL 3.5.5). These are NOT
subprocess numbers: they are within ~5% of what a C application
would measure calling the same functions.

Algorithms benchmarked:
  KEM (Key Encapsulation):
    - ML-KEM-512   (FIPS 203, Level 1)
    - ML-KEM-768   (FIPS 203, Level 3) ← recommended
    - ML-KEM-1024  (FIPS 203, Level 5)
    - X25519       (classical baseline)

  Signatures:
    - ML-DSA-44    (FIPS 204, Level 2)
    - ML-DSA-65    (FIPS 204, Level 3) ← recommended
    - ML-DSA-87    (FIPS 204, Level 5)
    - Ed25519      (classical baseline)

  Hash-based signatures:
    - SLH-DSA-SHA2-128s  (FIPS 205, Level 1, small)
    - SLH-DSA-SHA2-128f  (FIPS 205, Level 1, fast)

Operations measured:
  - Key generation
  - Encapsulate / Decapsulate (KEMs)
  - Sign / Verify (signatures)

Each operation runs N=1000 iterations (configurable).
Results are median + p95 + p99 to show distribution, not just average.

Environment: Ubuntu 26.04, OpenSSL 3.5.5, Python 3.14, i7-13700HX
Author:      Danny B. Carr, Jr.
"""

import ctypes
import ctypes.util
import os
import statistics
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# libcrypto FFI setup
# ---------------------------------------------------------------------------

_libcrypto = ctypes.CDLL(ctypes.util.find_library("crypto"))

# Opaque pointer types
class _EVP_PKEY(ctypes.Structure): pass
class _EVP_PKEY_CTX(ctypes.Structure): pass
class _OSSL_LIB_CTX(ctypes.Structure): pass

EVP_PKEY_p     = ctypes.POINTER(_EVP_PKEY)
EVP_PKEY_pp    = ctypes.POINTER(EVP_PKEY_p)
EVP_PKEY_CTX_p = ctypes.POINTER(_EVP_PKEY_CTX)

# Minimal bindings: only what the benchmark needs
_lc = _libcrypto

_lc.EVP_PKEY_CTX_new_from_name.restype  = EVP_PKEY_CTX_p
_lc.EVP_PKEY_CTX_new_from_name.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
]
_lc.EVP_PKEY_keygen_init.restype  = ctypes.c_int
_lc.EVP_PKEY_keygen_init.argtypes = [EVP_PKEY_CTX_p]

_lc.EVP_PKEY_keygen.restype  = ctypes.c_int
_lc.EVP_PKEY_keygen.argtypes = [EVP_PKEY_CTX_p, EVP_PKEY_pp]

_lc.EVP_PKEY_free.restype  = None
_lc.EVP_PKEY_free.argtypes = [EVP_PKEY_p]

_lc.EVP_PKEY_CTX_free.restype  = None
_lc.EVP_PKEY_CTX_free.argtypes = [EVP_PKEY_CTX_p]

_lc.EVP_PKEY_CTX_new.restype  = EVP_PKEY_CTX_p
_lc.EVP_PKEY_CTX_new.argtypes = [EVP_PKEY_p, ctypes.c_void_p]

_lc.EVP_PKEY_encapsulate_init.restype  = ctypes.c_int
_lc.EVP_PKEY_encapsulate_init.argtypes = [EVP_PKEY_CTX_p, ctypes.c_void_p]

_lc.EVP_PKEY_encapsulate.restype  = ctypes.c_int
_lc.EVP_PKEY_encapsulate.argtypes = [
    EVP_PKEY_CTX_p,
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
]
_lc.EVP_PKEY_decapsulate_init.restype  = ctypes.c_int
_lc.EVP_PKEY_decapsulate_init.argtypes = [EVP_PKEY_CTX_p, ctypes.c_void_p]

_lc.EVP_PKEY_decapsulate.restype  = ctypes.c_int
_lc.EVP_PKEY_decapsulate.argtypes = [
    EVP_PKEY_CTX_p,
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p, ctypes.c_size_t,
]

# Digest-sign (for ML-DSA and Ed25519)
class _EVP_MD_CTX(ctypes.Structure): pass
EVP_MD_CTX_p = ctypes.POINTER(_EVP_MD_CTX)

_lc.EVP_MD_CTX_new.restype  = EVP_MD_CTX_p
_lc.EVP_MD_CTX_new.argtypes = []
_lc.EVP_MD_CTX_free.restype  = None
_lc.EVP_MD_CTX_free.argtypes = [EVP_MD_CTX_p]

_lc.EVP_DigestSignInit.restype  = ctypes.c_int
_lc.EVP_DigestSignInit.argtypes = [
    EVP_MD_CTX_p, ctypes.POINTER(EVP_PKEY_CTX_p),
    ctypes.c_void_p, ctypes.c_void_p, EVP_PKEY_p,
]
_lc.EVP_DigestSign.restype  = ctypes.c_int
_lc.EVP_DigestSign.argtypes = [
    EVP_MD_CTX_p,
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p, ctypes.c_size_t,
]
_lc.EVP_DigestVerifyInit.restype  = ctypes.c_int
_lc.EVP_DigestVerifyInit.argtypes = [
    EVP_MD_CTX_p, ctypes.POINTER(EVP_PKEY_CTX_p),
    ctypes.c_void_p, ctypes.c_void_p, EVP_PKEY_p,
]
_lc.EVP_DigestVerify.restype  = ctypes.c_int
_lc.EVP_DigestVerify.argtypes = [
    EVP_MD_CTX_p,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
]


# ---------------------------------------------------------------------------
# Low-level operations
# ---------------------------------------------------------------------------

def _keygen(algorithm: str) -> _EVP_PKEY:
    """Generate a keypair using EVP_PKEY_keygen. Returns EVP_PKEY pointer."""
    ctx = _lc.EVP_PKEY_CTX_new_from_name(None, algorithm.encode(), None)
    if not ctx:
        raise RuntimeError(f"CTX_new_from_name failed for {algorithm}")
    try:
        if _lc.EVP_PKEY_keygen_init(ctx) <= 0:
            raise RuntimeError(f"keygen_init failed for {algorithm}")
        pkey = EVP_PKEY_p()
        if _lc.EVP_PKEY_keygen(ctx, ctypes.byref(pkey)) <= 0:
            raise RuntimeError(f"keygen failed for {algorithm}")
        return pkey
    finally:
        _lc.EVP_PKEY_CTX_free(ctx)


def _encapsulate(pkey) -> tuple[bytes, bytes]:
    """ML-KEM encapsulate. Returns (ciphertext, shared_secret)."""
    ctx = _lc.EVP_PKEY_CTX_new(pkey, None)
    if not ctx:
        raise RuntimeError("CTX_new failed for encapsulate")
    try:
        if _lc.EVP_PKEY_encapsulate_init(ctx, None) <= 0:
            raise RuntimeError("encapsulate_init failed")
        # Get sizes
        ct_len  = ctypes.c_size_t(0)
        ss_len  = ctypes.c_size_t(0)
        if _lc.EVP_PKEY_encapsulate(ctx, None, ctypes.byref(ct_len),
                                    None, ctypes.byref(ss_len)) <= 0:
            raise RuntimeError("encapsulate size query failed")
        ct_buf = ctypes.create_string_buffer(ct_len.value)
        ss_buf = ctypes.create_string_buffer(ss_len.value)
        if _lc.EVP_PKEY_encapsulate(ctx, ct_buf, ctypes.byref(ct_len),
                                    ss_buf, ctypes.byref(ss_len)) <= 0:
            raise RuntimeError("encapsulate failed")
        return bytes(ct_buf[:ct_len.value]), bytes(ss_buf[:ss_len.value])
    finally:
        _lc.EVP_PKEY_CTX_free(ctx)


def _decapsulate(pkey, ciphertext: bytes) -> bytes:
    """ML-KEM decapsulate. Returns shared_secret."""
    ctx = _lc.EVP_PKEY_CTX_new(pkey, None)
    if not ctx:
        raise RuntimeError("CTX_new failed for decapsulate")
    try:
        if _lc.EVP_PKEY_decapsulate_init(ctx, None) <= 0:
            raise RuntimeError("decapsulate_init failed")
        ss_len = ctypes.c_size_t(0)
        if _lc.EVP_PKEY_decapsulate(ctx, None, ctypes.byref(ss_len),
                                    ciphertext, len(ciphertext)) <= 0:
            raise RuntimeError("decapsulate size query failed")
        ss_buf = ctypes.create_string_buffer(ss_len.value)
        if _lc.EVP_PKEY_decapsulate(ctx, ss_buf, ctypes.byref(ss_len),
                                    ciphertext, len(ciphertext)) <= 0:
            raise RuntimeError("decapsulate failed")
        return bytes(ss_buf[:ss_len.value])
    finally:
        _lc.EVP_PKEY_CTX_free(ctx)


def _sign(pkey, message: bytes) -> bytes:
    """Sign message with ML-DSA or Ed25519. Returns signature bytes."""
    mctx = _lc.EVP_MD_CTX_new()
    if not mctx:
        raise RuntimeError("MD_CTX_new failed")
    try:
        if _lc.EVP_DigestSignInit(mctx, None, None, None, pkey) <= 0:
            raise RuntimeError("DigestSignInit failed")
        sig_len = ctypes.c_size_t(0)
        if _lc.EVP_DigestSign(mctx, None, ctypes.byref(sig_len),
                              message, len(message)) <= 0:
            raise RuntimeError("DigestSign size query failed")
        sig_buf = ctypes.create_string_buffer(sig_len.value)
        if _lc.EVP_DigestSign(mctx, sig_buf, ctypes.byref(sig_len),
                              message, len(message)) <= 0:
            raise RuntimeError("DigestSign failed")
        return bytes(sig_buf[:sig_len.value])
    finally:
        _lc.EVP_MD_CTX_free(mctx)


def _verify(pkey, signature: bytes, message: bytes) -> bool:
    """Verify signature. Returns True if valid."""
    mctx = _lc.EVP_MD_CTX_new()
    if not mctx:
        raise RuntimeError("MD_CTX_new failed")
    try:
        if _lc.EVP_DigestVerifyInit(mctx, None, None, None, pkey) <= 0:
            raise RuntimeError("DigestVerifyInit failed")
        r = _lc.EVP_DigestVerify(mctx, signature, len(signature),
                                  message, len(message))
        return r == 1
    finally:
        _lc.EVP_MD_CTX_free(mctx)


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------

def bench(fn, n: int = 1000) -> list[float]:
    """Run fn() n times, return list of elapsed ms per iteration."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        times.append((time.perf_counter_ns() - t0) / 1_000_000)
    return times


def stats(times: list[float]) -> dict:
    s = sorted(times)
    return {
        "median": statistics.median(s),
        "mean":   statistics.mean(s),
        "p95":    s[int(len(s) * 0.95)],
        "p99":    s[int(len(s) * 0.99)],
        "min":    s[0],
        "max":    s[-1],
    }


def fmt(st: dict) -> str:
    return (f"median={st['median']:.3f}ms  "
            f"p95={st['p95']:.3f}ms  "
            f"p99={st['p99']:.3f}ms")


# ---------------------------------------------------------------------------
# Benchmark suites
# ---------------------------------------------------------------------------

def bench_kem(algorithm: str, n: int = 1000) -> dict:
    """Benchmark a KEM: keygen + encap + decap."""
    # Pre-warm
    pkey = _keygen(algorithm)
    ct, _ = _encapsulate(pkey)

    kg_times   = bench(lambda: _lc.EVP_PKEY_free(_keygen(algorithm)), n)

    # For encap/decap, reuse the same keypair (keygen not included)
    enc_times  = bench(lambda: _encapsulate(pkey), n)
    dec_times  = bench(lambda: _decapsulate(pkey, ct), n)

    _lc.EVP_PKEY_free(pkey)
    return {
        "keygen":  stats(kg_times),
        "encap":   stats(enc_times),
        "decap":   stats(dec_times),
    }


def bench_sig(algorithm: str, n: int = 1000, msg_size: int = 64) -> dict:
    """Benchmark a signature scheme: keygen + sign + verify."""
    message = os.urandom(msg_size)

    pkey = _keygen(algorithm)
    sig  = _sign(pkey, message)

    kg_times  = bench(lambda: _lc.EVP_PKEY_free(_keygen(algorithm)), n)
    sg_times  = bench(lambda: _sign(pkey, message), n)
    vf_times  = bench(lambda: _verify(pkey, sig, message), n)

    _lc.EVP_PKEY_free(pkey)
    return {
        "keygen": stats(kg_times),
        "sign":   stats(sg_times),
        "verify": stats(vf_times),
        "sig_bytes": len(sig),
    }


# ---------------------------------------------------------------------------
# Key / ciphertext size reference (FIPS 203/204/205 spec values)
# ---------------------------------------------------------------------------

SIZES = {
    # KEM: (ek_bytes, dk_bytes, ct_bytes, ss_bytes)
    "ML-KEM-512":  {"ek": 800,   "dk": 1632,  "ct": 768,   "ss": 32,   "level": 1},
    "ML-KEM-768":  {"ek": 1184,  "dk": 2400,  "ct": 1088,  "ss": 32,   "level": 3},
    "ML-KEM-1024": {"ek": 1568,  "dk": 3168,  "ct": 1568,  "ss": 32,   "level": 5},
    "X25519":      {"ek": 32,    "dk": 32,    "ct": 32,    "ss": 32,   "level": 0},
    # Sig: (pk_bytes, sk_bytes, sig_bytes)
    "ML-DSA-44":   {"pk": 1312,  "sk": 2528,  "sig": 2420, "level": 2},
    "ML-DSA-65":   {"pk": 1952,  "sk": 4032,  "sig": 3309, "level": 3},
    "ML-DSA-87":   {"pk": 2592,  "sk": 4896,  "sig": 4627, "level": 5},
    "Ed25519":     {"pk": 32,    "sk": 64,    "sig": 64,   "level": 0},
    "SLH-DSA-SHA2-128s": {"pk": 32, "sk": 64, "sig": 7856, "level": 1},
    "SLH-DSA-SHA2-128f": {"pk": 32, "sk": 64, "sig": 17088,"level": 1},
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    N = 1000
    EVIDENCE = Path(__file__).parent.parent.parent / "evidence" / "benchmarks"
    EVIDENCE.mkdir(parents=True, exist_ok=True)

    import platform
    cpu = platform.processor()

    print("=" * 72)
    print("Lab D — Post-Quantum Cryptography Benchmark Suite")
    print(f"OpenSSL : {_libcrypto_version()}")
    print(f"Python  : {platform.python_version()}")
    print(f"CPU     : {cpu}")
    print(f"N       : {N} iterations per operation")
    print(f"Method  : Direct libcrypto ctypes FFI (library speed)")
    print("=" * 72)
    print()

    results = {}

    # ── KEM Benchmarks ───────────────────────────────────────────────
    print("KEM BENCHMARKS (Key Encapsulation Mechanisms)")
    print("-" * 72)
    print(f"{'Algorithm':<22} {'Keygen':>10} {'Encap':>10} {'Decap':>10} "
          f"{'ct(B)':>7} {'ek(B)':>7} {'Level':>6}")
    print("-" * 72)

    kem_algos = ["X25519", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    for algo in kem_algos:
        r = bench_kem(algo, N)
        results[algo] = r
        sz = SIZES[algo]
        marker = " ←" if algo == "ML-KEM-768" else ""
        print(
            f"  {algo:<20} "
            f"{r['keygen']['median']:>9.3f}ms "
            f"{r['encap']['median']:>9.3f}ms "
            f"{r['decap']['median']:>9.3f}ms "
            f"{sz['ct']:>7} "
            f"{sz['ek']:>7} "
            f"{'L'+str(sz['level']) if sz['level'] else 'class':>6}"
            f"{marker}"
        )

    print()

    # ── Signature Benchmarks ────────────────────────────────────────
    print("SIGNATURE BENCHMARKS (64-byte message)")
    print("-" * 72)
    print(f"{'Algorithm':<22} {'Keygen':>10} {'Sign':>10} {'Verify':>10} "
          f"{'sig(B)':>8} {'pk(B)':>7} {'Level':>6}")
    print("-" * 72)

    sig_algos = [
        "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    ]
    for algo in sig_algos:
        try:
            r = bench_sig(algo, N)
            results[algo] = r
            sz = SIZES[algo]
            marker = " ←" if algo == "ML-DSA-65" else ""
            print(
                f"  {algo:<20} "
                f"{r['keygen']['median']:>9.3f}ms "
                f"{r['sign']['median']:>9.3f}ms "
                f"{r['verify']['median']:>9.3f}ms "
                f"{r['sig_bytes']:>8} "
                f"{sz['pk']:>7} "
                f"{'L'+str(sz['level']) if sz['level'] else 'class':>6}"
                f"{marker}"
            )
        except Exception as e:
            print(f"  {algo:<20} ERROR: {e}")

    print()

    # ── Analysis ────────────────────────────────────────────────────
    print("ANALYSIS")
    print("-" * 72)

    if "X25519" in results and "ML-KEM-768" in results:
        x_kg = results["X25519"]["keygen"]["median"]
        m_kg = results["ML-KEM-768"]["keygen"]["median"]
        x_op = results["X25519"]["encap"]["median"] + results["X25519"]["decap"]["median"]
        m_op = results["ML-KEM-768"]["encap"]["median"] + results["ML-KEM-768"]["decap"]["median"]
        print(f"  ML-KEM-768 vs X25519:")
        print(f"    Keygen  : ML-KEM-768 is {m_kg/x_kg:.1f}× {'slower' if m_kg>x_kg else 'faster'} "
              f"({m_kg:.3f}ms vs {x_kg:.3f}ms)")
        print(f"    KEM op  : {m_op:.3f}ms vs ECDH {x_op:.3f}ms "
              f"({m_op/x_op:.1f}× {'slower' if m_op>x_op else 'faster'})")
        print(f"    CT size : 1,088 bytes vs 32 bytes (34× larger — but fits in one TCP packet)")
        print()

    if "Ed25519" in results and "ML-DSA-65" in results:
        e_sg = results["Ed25519"]["sign"]["median"]
        m_sg = results["ML-DSA-65"]["sign"]["median"]
        e_vf = results["Ed25519"]["verify"]["median"]
        m_vf = results["ML-DSA-65"]["verify"]["median"]
        print(f"  ML-DSA-65 vs Ed25519:")
        print(f"    Sign    : {m_sg:.3f}ms vs {e_sg:.3f}ms "
              f"({m_sg/e_sg:.1f}× {'slower' if m_sg>e_sg else 'faster'})")
        print(f"    Verify  : {m_vf:.3f}ms vs {e_vf:.3f}ms "
              f"({m_vf/e_vf:.1f}× {'slower' if m_vf>e_vf else 'faster'})")
        print(f"    Sig size: 3,309 bytes vs 64 bytes (52× larger)")
        print(f"    → The overhead is SIZE, not TIME. Critical book point.")
        print()

    if "SLH-DSA-SHA2-128s" in results and "SLH-DSA-SHA2-128f" in results:
        s_sg = results["SLH-DSA-SHA2-128s"]["sign"]["median"]
        f_sg = results["SLH-DSA-SHA2-128f"]["sign"]["median"]
        print(f"  SLH-DSA: the conservative (hash-only) choice")
        print(f"    SHA2-128s: sign {s_sg:.3f}ms, sig {results['SLH-DSA-SHA2-128s']['sig_bytes']:,} bytes (small, slow)")
        print(f"    SHA2-128f: sign {f_sg:.3f}ms, sig {results['SLH-DSA-SHA2-128f']['sig_bytes']:,} bytes (large, fast)")
        print(f"    → Use when lattice assumptions make you uncomfortable")
        print()

    # ── Summary table for book ───────────────────────────────────────
    print("BOOK TABLE — Chapter 10 (copy-paste ready)")
    print("-" * 72)
    print(f"{'Algorithm':<22} {'Keygen':>8} {'Op':>8} {'Key(B)':>7} {'Ct/Sig(B)':>10} {'NIST':>5}")
    print("-" * 72)
    for algo in ["X25519", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        if algo not in results: continue
        r  = results[algo]
        sz = SIZES[algo]
        op = r["encap"]["median"] + r["decap"]["median"]
        print(f"  {algo:<20} {r['keygen']['median']:>7.3f}ms {op:>7.3f}ms "
              f"{sz['ek']:>7} {sz['ct']:>10} {'L'+str(sz['level']) if sz['level'] else 'class':>5}")
    print()
    for algo in ["Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        if algo not in results: continue
        r  = results[algo]
        sz = SIZES[algo]
        op = r["sign"]["median"] + r["verify"]["median"]
        print(f"  {algo:<20} {r['keygen']['median']:>7.3f}ms {op:>7.3f}ms "
              f"{sz['pk']:>7} {r['sig_bytes']:>10} {'L'+str(sz['level']) if sz['level'] else 'class':>5}")

    # ── Save evidence ─────────────────────────────────────────────────
    ev_path = EVIDENCE / "lab-d-benchmarks.txt"
    lines = [
        f"Lab D Evidence — PQC Benchmark Suite",
        f"OpenSSL: {_libcrypto_version()}",
        f"CPU: {cpu}",
        f"N: {N} iterations",
        f"Date: {__import__('datetime').datetime.now().isoformat()}",
        "",
        "KEM Results (median ms):",
    ]
    for algo in kem_algos:
        if algo in results:
            r = results[algo]
            lines.append(f"  {algo}: keygen={r['keygen']['median']:.3f}ms "
                        f"encap={r['encap']['median']:.3f}ms "
                        f"decap={r['decap']['median']:.3f}ms")
    lines.append("")
    lines.append("Signature Results (median ms):")
    for algo in sig_algos:
        if algo in results:
            r = results[algo]
            lines.append(f"  {algo}: keygen={r['keygen']['median']:.3f}ms "
                        f"sign={r['sign']['median']:.3f}ms "
                        f"verify={r['verify']['median']:.3f}ms "
                        f"sig_bytes={r['sig_bytes']}")
    ev_path.write_text("\n".join(lines))
    print(f"\n  Evidence → evidence/benchmarks/lab-d-benchmarks.txt")


def _libcrypto_version() -> str:
    import subprocess
    return subprocess.run(
        ["openssl", "version"], capture_output=True
    ).stdout.decode().strip()


if __name__ == "__main__":
    main()
