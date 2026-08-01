# Post-Quantum, Measured: the lab

[![DOI](https://zenodo.org/badge/1310524485.svg)](https://doi.org/10.5281/zenodo.21750546)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Runnable companion code and captured output for the book *Post-Quantum, Measured*
by Danny B. Carr, Jr. (Carr Digital LLC).

Every performance number, certificate size, and handshake result the book labels
**Verified** was produced by the scripts in this repository, on stock OpenSSL, on one
laptop. This repo exists so you can run them yourself and check.

## The verification standard

The book labels every claim one of three ways:

- **Verified.** Measured in this lab. The script and its captured output are both here.
- **Reported.** Cited to a standard or vendor document, not re-derived.
- **Proposed.** Designed but not yet shipped or measured.

Only Verified claims live in this repository. If a number in the book is marked Verified
and you cannot reproduce it from here, that is a bug worth reporting.

## Requirements

- **OpenSSL 3.5 or later.** ML-KEM, ML-DSA, and SLH-DSA are native from 3.5. Measurements
  here were taken on OpenSSL 3.5.5 (27 Jan 2026).
- **Python 3.11 or later.** Developed against 3.14.4.
- `qiskit` for the quantum demo only. No IBM Quantum account needed, it runs on the local
  statevector simulator.
- Dart SDK for the `audit-pqcrypto/` interop check only.

No network access, no HSM, and no cloud account is required by any lab.

## Labs

| Path | What it does | Book chapter |
|---|---|---|
| `src/lab-quantum/quantum_threat_demo.py` | Shor factors 15, Grover searches. Why RSA and ECDSA break and symmetric keys only halve. | 1 |
| `src/lab-b-tls/mlkem_demo.py` | Full ML-KEM-768 encapsulate and decapsulate flow | 3 |
| `src/lab-b-tls/hybrid_kem_wrap.py` | Hybrid X25519 + ML-KEM-768 key wrapping | 3, 9 |
| `src/lab-c-mldsa/pqc_sign.py` | ML-DSA-65 file signing CLI. Detached signatures, like `gpg --sign` but post-quantum. | 4 |
| `src/lab-b-tls/pqc_tls_lab.py` | TLS 1.3 handshake over the X25519MLKEM768 hybrid group | 6 |
| `src/lab-b-tls/pqc_ca.py` | Three-tier ML-DSA-65 PKI, root through leaf | 7 |
| `src/lab-ca/run-mixed-chain-lab.sh` | Certificate chain size ledger and KEM-cert issuance mechanics | 7 |
| `src/lab-ca/san-size-sweep.sh` | How SAN count moves leaf size, and where a chain crosses the TLS record and initcwnd thresholds | 7 |
| `src/lab-ops/run-ops-labs.sh` | OCSP and CRL sizing, cross-signed root rotation | 8 |
| `src/lab-a-hybrid/envelope_v3.py` | Reference implementation of a hybrid application-layer envelope format | 9 |
| `src/lab-d-bench/pqc_bench.py` | Benchmark suite via direct ctypes bindings to libcrypto, not subprocess timing | 10 |
| `audit-pqcrypto/run-interop.sh` | ML-KEM-768 interop: pure-Dart `pqcrypto` against OpenSSL, both directions | 9 |

The certificate-size labs use fixed serials and a fixed validity window so DER byte counts
are stable across runs. The only size drivers left are the algorithm and the extension set,
which is the point.

## Captured output

`evidence/` holds what these scripts actually printed here, with the OpenSSL version stamped
in each file. Compare your run against it.

```
evidence/quantum/          Shor and Grover demo
evidence/tls/              ML-KEM-768, hybrid wrap, PQC TLS handshake
evidence/signatures/       ML-DSA-65 signing, PQC CA chain
evidence/benchmarks/       full benchmark suite
evidence/research/         chain size ledger, SAN sweep, ops labs
evidence/lab-a-*.txt       hybrid envelope reference
```

`ca/` and `tls/certs/` hold generated certificates from the PKI labs. Public certificates
only. No private key material is published in this repository, and none of it would be
trustworthy if it were: regenerate your own with `src/lab-b-tls/pqc_ca.py`.

## Running a lab

```bash
openssl version                      # need 3.5+
python3 src/lab-b-tls/mlkem_demo.py
bash   src/lab-ca/san-size-sweep.sh
```

Each script is self-contained and prints what it measured. The shell labs work in a
temporary directory and clean up after themselves.

## Related: the certificate compatibility matrix

The book's certificate work continues in a separate repository,
**[pqc-cert-matrix](https://github.com/DannyBCarrJr/pqc-cert-matrix)**: what actually
happens when a post-quantum or hybrid X.509 chain meets real client software. Eight chain
shapes across eleven client stacks, 88 cells, each a script plus captured output, plus
transport measurements from key-log-decrypted handshakes. Same evidence standard as this
repository. Written up at
[Hybrid certificates, weighed](https://carrdigital.dev/writing/hybrid-certificates-weighed/).

## The book

*Post-Quantum, Measured: migrating TLS, PKI, and application crypto with evidence you can
reproduce.*

**Get the book: https://leanpub.com/post-quantum-measured**

Also on Kindle: https://www.amazon.com/dp/B0HBW7VNSN

Free whitepaper and details: https://post-quantum-measured.pages.dev

The book is the migration: the sequencing, the tradeoffs, the failure modes, and the
judgment about what matters and when. This repository is the proof that the numbers in it
are real.

## License

Code and captured output are MIT licensed (see `LICENSE`). The book text is not in this
repository and is not covered by that license.

Third-party standards documents and vendor pages cited by the book are not redistributed
here. The book cites them by URL and access date.
