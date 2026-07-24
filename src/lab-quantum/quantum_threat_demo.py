#!/usr/bin/env python3
"""Quantum-threat demo: the two algorithms Chapter 1 names, run locally.

  * Shor  factors 15  -> breaks RSA/ECDSA-style problems (period finding).
  * Grover finds a marked item -> quadratic speedup (why symmetric keys double).

Runs on qiskit's built-in statevector simulator (qiskit.primitives): no
qiskit-aer and no IBM Quantum account required. Faithful in spirit to the
libquantum / Quantum Computing Playground QScript demos, reproduced here so the
result is locally verifiable per the repo Verification Standard.

Reproduce:  python src/lab-quantum/quantum_threat_demo.py
Env:        pip install -r requirements-quantum.txt   (qiskit 2.5.x)
"""
import math
from fractions import Fraction
from math import gcd

import qiskit
from qiskit import QuantumCircuit
from qiskit.primitives import StatevectorSampler

SAMPLER = StatevectorSampler()


def _counts(pub_result):
    """Pull counts from a sampler result regardless of classical-register name."""
    data = pub_result.data
    reg = next(iter(data.keys()))  # single classical register in these circuits
    return getattr(data, reg).get_counts()


# ---------------------------------------------------------------------------
# Grover: search for |101> = 5 in a 3-qubit register
# ---------------------------------------------------------------------------
def grover_find(target=5, n=3, shots=2048):
    def ccz(qc, a, b, c):
        qc.h(c); qc.ccx(a, b, c); qc.h(c)

    def oracle(qc):
        for i in range(n):
            if not (target >> i) & 1:
                qc.x(i)
        ccz(qc, 0, 1, 2)
        for i in range(n):
            if not (target >> i) & 1:
                qc.x(i)

    def diffuser(qc):
        qc.h(range(n)); qc.x(range(n))
        ccz(qc, 0, 1, 2)
        qc.x(range(n)); qc.h(range(n))

    qc = QuantumCircuit(n)
    qc.h(range(n))
    iters = int(math.floor(math.pi / 4 * math.sqrt(2 ** n)))
    for _ in range(iters):
        oracle(qc)
        diffuser(qc)
    qc.measure_all()

    counts = _counts(SAMPLER.run([qc], shots=shots).result()[0])
    top = max(counts, key=counts.get)
    return {
        "iters": iters, "shots": shots, "counts": counts,
        "top": top, "value": int(top, 2), "target": target,
        "confidence": counts[top] / shots,
    }


# ---------------------------------------------------------------------------
# Shor: factor 15 by quantum order-finding (a=7 mod 15, order r=4)
# ---------------------------------------------------------------------------
def _qft_inverse_gate(n):
    qc = QuantumCircuit(n)
    for j in range(n):
        qc.h(j)
        for k in range(j + 1, n):
            qc.cp(math.pi / 2 ** (k - j), k, j)
    for i in range(n // 2):
        qc.swap(i, n - 1 - i)
    return qc.inverse().to_gate(label="QFT+")


def _c_amod15(a, power):
    # Controlled multiplication by a^power mod 15 on a 4-qubit work register.
    # Standard compact construction for a in {2,4,7,8,11,13}.
    if a not in (2, 4, 7, 8, 11, 13):
        raise ValueError("a must be one of 2,4,7,8,11,13 (coprime, known circuit)")
    u = QuantumCircuit(4)
    for _ in range(power):
        if a in (2, 13):
            u.swap(0, 1); u.swap(1, 2); u.swap(2, 3)
        if a in (7, 8):
            u.swap(2, 3); u.swap(1, 2); u.swap(0, 1)
        if a in (4, 11):
            u.swap(1, 3); u.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                u.x(q)
    g = u.to_gate(); g.name = f"{a}^{power} mod 15"
    return g.control()


def shor_factor_15(a=7, n_count=6, shots=2048):
    N = 15
    if gcd(a, N) != 1:
        return {"a": a, "N": N, "factors": (gcd(a, N), N // gcd(a, N)),
                "note": "gcd shortcut (a shared a factor)", "phases": {}}
    qc = QuantumCircuit(n_count + 4, n_count)
    qc.h(range(n_count))
    qc.x(n_count)  # work register = |1>
    for q in range(n_count):
        qc.append(_c_amod15(a, 2 ** q), [q] + list(range(n_count, n_count + 4)))
    qc.append(_qft_inverse_gate(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))

    counts = _counts(SAMPLER.run([qc], shots=shots).result()[0])
    phases = {}
    for bits, c in counts.items():
        phases[int(bits, 2) / 2 ** n_count] = phases.get(int(bits, 2) / 2 ** n_count, 0) + c

    # classical post-processing: phase -> period r -> factor.
    # Prefer a phase whose recovered r is the TRUE order (a^r == 1 mod N), so the
    # reported period is 4, not the 2 you get from the reduced fraction 2/4 = 1/2.
    ordered = [p for p in sorted(phases, key=lambda p: -phases[p]) if p != 0]
    for require_true_order in (True, False):
        for phase in ordered:
            r = Fraction(phase).limit_denominator(N).denominator
            if r % 2:
                continue
            if require_true_order and pow(a, r, N) != 1:
                continue
            for guess in (gcd(a ** (r // 2) - 1, N), gcd(a ** (r // 2) + 1, N)):
                if 1 < guess < N and N % guess == 0:
                    return {"a": a, "N": N, "n_count": n_count, "shots": shots,
                            "phase": phase, "period": r,
                            "true_order": pow(a, r, N) == 1,
                            "factors": (guess, N // guess),
                            "phases": {round(k, 4): v for k, v in sorted(phases.items())}}
    return {"a": a, "N": N, "factors": None, "phases": phases}


if __name__ == "__main__":
    print(f"qiskit {qiskit.__version__} | built-in StatevectorSampler (no Aer, no account)\n")

    print("== Shor: factor 15 ==")
    s = shor_factor_15()
    print(f"  a={s['a']}  measured phase={s['phase']}  ->  period r={s['period']}")
    print(f"  factors of {s['N']}: {s['factors'][0]} x {s['factors'][1]}")
    ok_s = s["factors"] and s["factors"][0] * s["factors"][1] == 15 and 1 < s["factors"][0] < 15
    print(f"  RESULT: {'FACTORED 15' if ok_s else 'FAILED'}\n")

    print("== Grover: find 5 in a 3-qubit register ==")
    g = grover_find()
    print(f"  iters={g['iters']} shots={g['shots']}")
    print(f"  most-measured: {g['top']} = {g['value']} (target {g['target']}, "
          f"{g['confidence']*100:.1f}% of shots)")
    ok_g = g["value"] == g["target"]
    print(f"  RESULT: {'FOUND 5' if ok_g else 'FAILED'}")
