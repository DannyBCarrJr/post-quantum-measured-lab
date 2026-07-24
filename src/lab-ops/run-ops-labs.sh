#!/usr/bin/env bash
# OPS labs for Ch.8: OCSP sizing, CRL sizing, cross-sign root rotation.
# Stock OpenSSL 3.5.5. All sizes measured on DER (wire) artifacts.
set -euo pipefail

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
mkdir -p out
OSSL="$(command -v openssl)"
echo "OpenSSL: $($OSSL version)"
echo "Date (host): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# ---- helper: minimal CA dir + openssl.cnf for `openssl ca` -------------------
mk_ca_dir () {
  local dir="$1"; local cacrt="$2"; local cakey="$3"
  mkdir -p "$dir"
  : > "$dir/index.txt"
  echo "1000" > "$dir/serial"
  echo "1000" > "$dir/crlnumber"
  cat > "$dir/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir             = $WORK/$dir
database        = \$dir/index.txt
serial          = \$dir/serial
crlnumber       = \$dir/crlnumber
new_certs_dir   = \$dir
certificate     = $WORK/$cacrt
private_key     = $WORK/$cakey
default_md      = default
default_crl_days= 7
policy          = pol_any
[ pol_any ]
commonName = supplied
EOF
}

# =============================================================================
# Build two CAs: ECDSA P-256 baseline and ML-DSA-65
# =============================================================================
echo "=== Building CAs ==="
# ECDSA
mkdir -p ca-ecdsa
$OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca-ecdsa/ca.key 2>/dev/null
$OSSL req -new -x509 -key ca-ecdsa/ca.key -out ca-ecdsa/ca.crt -days 3650 \
  -subj "/CN=OPS Lab ECDSA CA/O=Carr Digital LLC/C=US"
# ML-DSA-65
mkdir -p ca-mldsa
$OSSL genpkey -algorithm ML-DSA-65 -out ca-mldsa/ca.key
$OSSL req -new -x509 -key ca-mldsa/ca.key -out ca-mldsa/ca.crt -days 3650 \
  -subj "/CN=OPS Lab ML-DSA-65 CA/O=Carr Digital LLC/C=US"

mk_ca_dir ca-ecdsa ca-ecdsa/ca.crt ca-ecdsa/ca.key
mk_ca_dir ca-mldsa ca-mldsa/ca.crt ca-mldsa/ca.key
echo "  ECDSA CA cert (DER):  $($OSSL x509 -in ca-ecdsa/ca.crt -outform DER | wc -c) B"
echo "  ML-DSA CA cert (DER): $($OSSL x509 -in ca-mldsa/ca.crt -outform DER | wc -c) B"
echo

# =============================================================================
# OPS-1: OCSP response sizing (ECDSA-signed vs ML-DSA-65-signed responder)
# =============================================================================
echo "=== OPS-1: OCSP response sizing ==="
ops1_one () {
  local alg="$1"; local dir="ca-$2"
  # issue one leaf, ECDSA key (leaf key algorithm is irrelevant to OCSP size;
  # the OCSP RESPONSE is signed by the responder = the CA key)
  $OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/leaf.key" 2>/dev/null
  $OSSL req -new -key "$dir/leaf.key" -out "$dir/leaf.csr" -subj "/CN=leaf.ops.example"
  $OSSL ca -batch -config "$dir/openssl.cnf" -in "$dir/leaf.csr" -out "$dir/leaf.crt" -days 365 >/dev/null 2>&1
  # build OCSP request (uses issuer+leaf; deterministic, no nonce)
  $OSSL ocsp -issuer "$dir/ca.crt" -cert "$dir/leaf.crt" -reqout "$dir/ocsp-req.der" -no_nonce >/dev/null 2>&1
  # produce OCSP response signed by CA key (the responder)
  $OSSL ocsp -index "$dir/index.txt" -CA "$dir/ca.crt" \
    -rsigner "$dir/ca.crt" -rkey "$dir/ca.key" \
    -reqin "$dir/ocsp-req.der" -respout "$dir/ocsp-resp.der" -no_nonce -ndays 7 >/dev/null 2>&1
  local reqsz respsz
  reqsz=$(wc -c < "$dir/ocsp-req.der")
  respsz=$(wc -c < "$dir/ocsp-resp.der")
  printf "  %-10s  request=%5s B   response=%6s B\n" "$alg" "$reqsz" "$respsz"
}
ops1_one "ECDSA"     ecdsa
ops1_one "ML-DSA-65" mldsa
echo

# =============================================================================
# OPS-2: CRL sizing at 0 / 1k / 10k revoked entries (the key measurement)
# =============================================================================
echo "=== OPS-2: CRL sizing (synthesized revoked entries in index.txt) ==="
# Synthesize N revoked entries directly into index.txt, then `openssl ca -gencrl`
# signs ONE signature over the whole tbsCertList. This tests the claim that PQC
# makes CRLs balloon per-entry (it does not: the per-entry cost is serial+date,
# algorithm-independent; only the single trailing signature differs).
gen_crl () {
  local dir="ca-$1"; local n="$2"
  # rebuild index.txt with N revoked rows
  : > "$dir/index.txt"
  if [ "$n" -gt 0 ]; then
    awk -v n="$n" 'BEGIN{
      for(i=0;i<n;i++){
        # status=R  expiry  revdate  serial(hex)  file  subject
        serial=sprintf("%08X", 4096+i);
        printf "R\t300101000000Z\t260101000000Z\t%s\tunknown\t/CN=revoked-%d\n", serial, i;
      }
    }' >> "$dir/index.txt"
  fi
  $OSSL ca -gencrl -config "$dir/openssl.cnf" -out "$dir/test.crl" >/dev/null 2>&1
  $OSSL crl -in "$dir/test.crl" -outform DER -out "$dir/test.crl.der" 2>/dev/null
  wc -c < "$dir/test.crl.der"
}
printf "  %-10s  %10s  %10s  %10s\n" "signer" "0-entry" "1k-entry" "10k-entry"
for algpair in "ECDSA:ecdsa" "ML-DSA-65:mldsa"; do
  alg="${algpair%%:*}"; d="${algpair##*:}"
  s0=$(gen_crl "$d" 0); s1=$(gen_crl "$d" 1000); s10=$(gen_crl "$d" 10000)
  printf "  %-10s  %8s B  %8s B  %8s B\n" "$alg" "$s0" "$s1" "$s10"
done
# per-entry delta and signature delta, computed from the measured points
echo "  (per-entry bytes = (10k - 1k)/9000; signature delta = ML-DSA 0-entry minus ECDSA 0-entry)"
echo

# =============================================================================
# OPS-3: cross-sign root rotation (new SLH-DSA root cross-signed by old ML-DSA)
# =============================================================================
echo "=== OPS-3: cross-sign root rotation ==="
mkdir -p xsign; cd xsign
# Old root: ML-DSA-65 (the incumbent trust anchor)
$OSSL genpkey -algorithm ML-DSA-65 -out old-root.key
$OSSL req -new -x509 -key old-root.key -out old-root.crt -days 3650 \
  -subj "/CN=Bridge Root/O=Carr Digital LLC/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
# New root: SLH-DSA-128s, SAME subject DN (a re-keyed root: classic rotation)
$OSSL genpkey -algorithm SLH-DSA-SHA2-128s -out new-root.key
$OSSL req -new -x509 -key new-root.key -out new-root-self.crt -days 3650 \
  -subj "/CN=Bridge Root/O=Carr Digital LLC/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
# Cross-cert: new root's subject+pubkey, signed by OLD root.
$OSSL req -new -key new-root.key -out new-root.csr -subj "/CN=Bridge Root/O=Carr Digital LLC/C=US"
$OSSL x509 -req -in new-root.csr -CA old-root.crt -CAkey old-root.key -CAcreateserial \
  -out new-root-cross.crt -days 3650 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") 2>/dev/null
# Issuing CA under the NEW root (ML-DSA-65)
$OSSL genpkey -algorithm ML-DSA-65 -out int.key
$OSSL req -new -key int.key -out int.csr -subj "/CN=Bridge Issuing CA/O=Carr Digital LLC/C=US"
$OSSL x509 -req -in int.csr -CA new-root-self.crt -CAkey new-root.key -CAcreateserial \
  -out int.crt -days 1825 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n") 2>/dev/null
# Leaf under the issuing CA
$OSSL genpkey -algorithm ML-DSA-65 -out leaf.key
$OSSL req -new -key leaf.key -out leaf.csr -subj "/CN=service.example.com"
$OSSL x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial \
  -out leaf.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:service.example.com\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n") 2>/dev/null

echo "  Sizes (DER):"
printf "    old-root (ML-DSA-65) self-signed : %6s B\n" "$($OSSL x509 -in old-root.crt -outform DER|wc -c)"
printf "    new-root (SLH-DSA-128s) self     : %6s B\n" "$($OSSL x509 -in new-root-self.crt -outform DER|wc -c)"
printf "    new-root cross-cert (by old root): %6s B\n" "$($OSSL x509 -in new-root-cross.crt -outform DER|wc -c)"
printf "    issuing CA (ML-DSA-65)           : %6s B\n" "$($OSSL x509 -in int.crt -outform DER|wc -c)"
printf "    leaf (ML-DSA-65)                 : %6s B\n" "$($OSSL x509 -in leaf.crt -outform DER|wc -c)"
echo
echo "  Path A — relying party trusts the NEW root directly:"
$OSSL verify -CAfile new-root-self.crt -untrusted int.crt leaf.crt 2>&1 | sed 's/^/    /' || true
echo "  Path B — relying party trusts only the OLD root; new root reached via cross-cert:"
cat new-root-cross.crt int.crt > chain-b.pem
$OSSL verify -CAfile old-root.crt -untrusted chain-b.pem leaf.crt 2>&1 | sed 's/^/    /' || true
echo
echo "=== OPS labs complete ==="
