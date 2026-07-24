#!/usr/bin/env bash
# SAN-size sweep + full-chain thresholds: Ch.7 size-ledger support.
#   Part A: how SAN count moves a leaf's size (ECDSA vs ML-DSA-65) -> the PQC
#           penalty is ~constant in bytes, so the multiplier collapses as SANs grow.
#   Part B: a full 3-tier ML-DSA-65 chain at 1 vs 150 SAN, vs the TLS-record (16,384 B)
#           and TCP initcwnd (~14,600 B) thresholds the server's first flight lives under.
# Deterministic (fixed serials + validity) except the ECDSA baseline (variable-length sig).
set -euo pipefail
OSSL="$(command -v openssl)"; WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
NB="20260101000000Z"; NA="20360101000000Z"
der () { $OSSL x509 -in "$1" -outform DER | wc -c; }
sans () { local n=$1 s="DNS:host001.svc.example.com" i; for i in $(seq 2 "$n"); do s="$s,DNS:host$(printf %03d "$i").svc.example.com"; done; echo "$s"; }
genkey () { case "$1" in EC) $OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" 2>/dev/null;; *) $OSSL genpkey -algorithm "$1" -out "$2";; esac; }

echo "# $($OSSL version)"; echo "# DER (wire) bytes. Deterministic except ECDSA baseline (variable-length sig, +/-1-2 B)."; echo

# ---- Part A: SAN sweep, self-signed leaves (isolates key+sig+SAN) -------------
echo "## Part A — leaf size vs SAN count (self-signed)"
printf "%-5s %-9s %-10s %-9s %-7s\n" "SANs" "ECDSA-B" "MLDSA65-B" "PQCdelta" "ratio"
for n in 1 10 50 150; do
  genkey EC ec.key;      $OSSL req -new -x509 -key ec.key -out ec.crt  -not_before "$NB" -not_after "$NA" -set_serial 0x1 -subj "/CN=host001.svc.example.com/O=Carr Digital LLC/C=US" -addext "subjectAltName=$(sans "$n")" 2>/dev/null
  genkey ML-DSA-65 m.key; $OSSL req -new -x509 -key m.key -out m.crt   -not_before "$NB" -not_after "$NA" -set_serial 0x1 -subj "/CN=host001.svc.example.com/O=Carr Digital LLC/C=US" -addext "subjectAltName=$(sans "$n")" 2>/dev/null
  e=$(der ec.crt); m=$(der m.crt)
  printf "%-5s %-9s %-10s %-9s %-7s\n" "$n" "$e" "$m" "+$((m-e))" "$(awk "BEGIN{printf \"%.1fx\",$m/$e}")"
done
echo

# ---- Part B: full 3-tier ML-DSA-65 chain, leaf at 1 and 150 SAN --------------
echo "## Part B — full ML-DSA-65 chain (root -> ICA -> leaf) vs TLS thresholds"
genkey ML-DSA-65 root.key; genkey ML-DSA-65 ica.key
printf 'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n' > root.ext
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > ica.ext
$OSSL req -new -key root.key -out root.csr -subj "/CN=Carr Digital PQC Root/O=Carr Digital LLC/C=US"
$OSSL x509 -req -in root.csr -signkey root.key -set_serial 0x1000 -not_before "$NB" -not_after "$NA" -extfile root.ext -out root.crt 2>/dev/null
$OSSL req -new -key ica.key -out ica.csr -subj "/CN=Carr Digital PQC Issuing CA/O=Carr Digital LLC/C=US"
$OSSL x509 -req -in ica.csr -CA root.crt -CAkey root.key -set_serial 0x1001 -not_before "$NB" -not_after "$NA" -extfile ica.ext -out ica.crt 2>/dev/null
R=$(der root.crt); I=$(der ica.crt)
printf "  root=%s B   ICA=%s B\n" "$R" "$I"
printf "  %-9s %-8s %-14s %-16s %-14s\n" "leaf-SAN" "leaf-B" "wire(ICA+leaf)" "bundle(R+I+leaf)" "vs-16384/14600"
for n in 1 150; do
  genkey ML-DSA-65 leaf.key
  printf "subjectAltName=%s\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" "$(sans "$n")" > leaf.ext
  $OSSL req -new -key leaf.key -out leaf.csr -subj "/CN=host001.svc.example.com/O=Carr Digital LLC/C=US"
  $OSSL x509 -req -in leaf.csr -CA ica.crt -CAkey ica.key -set_serial 0x2001 -not_before "$NB" -not_after "$NA" -extfile leaf.ext -out leaf.crt 2>/dev/null
  L=$(der leaf.crt); wire=$((I+L)); bundle=$((R+I+L))
  rec=$([ "$wire" -gt 16384 ] && echo ">record" || echo "<record"); cwnd=$([ "$wire" -gt 14600 ] && echo ">initcwnd" || echo "<initcwnd")
  printf "  %-9s %-8s %-14s %-16s %s / %s\n" "$n" "$L" "$wire" "$bundle" "$rec" "$cwnd"
done
echo
echo "  Note: the ROOT is NOT sent on the wire (it lives in the client trust store);"
echo "  'wire' = what the server actually transmits. The full server first flight also"
echo "  carries a CertificateVerify (another ML-DSA-65 signature ~3,309 B) + the ML-KEM"
echo "  key_share (~1,088 B), so the real flight runs larger than the cert chain alone."
