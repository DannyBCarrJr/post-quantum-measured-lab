#!/usr/bin/env bash
# Lab CA-2 / CA-3: PQC certificate chain size ledger + KEM-cert issuance mechanics.
# Reproduces evidence/research/2026-07-11-mixed-chain-lab-evidence.txt from scratch.
#
# Determinism: fixed serials (-set_serial) and fixed validity window
# (-not_before/-not_after) so the DER byte counts are stable across runs. The only
# size drivers left are the algorithm key/signature sizes and the fixed extension set.
#
# Requires: OpenSSL 3.5+ (ML-DSA / ML-KEM / SLH-DSA native). No network, no HSM.
set -euo pipefail

OSSL="$(command -v openssl)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

NB="20260101000000Z"   # fixed notBefore
NA="20360101000000Z"   # fixed notAfter (10y)

echo "# Lab evidence: PQC certificate chain size + issuance mechanics"
echo "# $($OSSL version)"
echo "# All certs: minimal realistic extensions, DER-measured, fixed serial+validity."
echo "# Deterministic except the ECDSA baseline: ECDSA signatures are variable-length DER"
echo "#   (r/s leading-zero encoding), so ecdsa-p256 sizes jitter +/-1-2 B run to run."
echo "#   PQC (ML-DSA/SLH-DSA/ML-KEM) sizes are fixed-length and reproduce exactly."
echo

# --- extension files (minimal, realistic, uniform across algorithms) ---------
cat > root.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
EOF
cat > ca.ext  <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
cat > leaf.ext <<EOF
subjectAltName=DNS:leaf.example.com
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF

der () { $OSSL x509 -in "$1" -outform DER | wc -c; }

# Build a root->int->leaf chain for a given (rootalg,subalg) and echo "int leaf".
# $1=tag $2=root-alg $3=sub-alg(int+leaf)   (algs are genpkey -algorithm args or EC:curve)
genkey () { # $1=out $2=alg
  case "$2" in
    EC:*) $OSSL genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${2#EC:}" -out "$1" 2>/dev/null ;;
    *)    $OSSL genpkey -algorithm "$2" -out "$1" ;;
  esac
}

build_chain () {
  local tag="$1" ralg="$2" salg="$3"
  genkey "$tag-root.key" "$ralg"
  genkey "$tag-int.key"  "$salg"
  genkey "$tag-leaf.key" "$salg"
  # root (self-signed)
  $OSSL req -new -key "$tag-root.key" -out "$tag-root.csr" -subj "/CN=$tag Root/O=Carr Digital LLC/C=US"
  $OSSL x509 -req -in "$tag-root.csr" -signkey "$tag-root.key" -set_serial 0x1000 \
    -not_before "$NB" -not_after "$NA" -extfile root.ext -out "$tag-root.crt" 2>/dev/null
  # int (signed by root)
  $OSSL req -new -key "$tag-int.key" -out "$tag-int.csr" -subj "/CN=$tag Issuing CA/O=Carr Digital LLC/C=US"
  $OSSL x509 -req -in "$tag-int.csr" -CA "$tag-root.crt" -CAkey "$tag-root.key" -set_serial 0x1001 \
    -not_before "$NB" -not_after "$NA" -extfile ca.ext -out "$tag-int.crt" 2>/dev/null
  # leaf (signed by int)
  $OSSL req -new -key "$tag-leaf.key" -out "$tag-leaf.csr" -subj "/CN=leaf.example.com/O=Carr Digital LLC/C=US"
  $OSSL x509 -req -in "$tag-leaf.csr" -CA "$tag-int.crt" -CAkey "$tag-int.key" -set_serial 0x1002 \
    -not_before "$NB" -not_after "$NA" -extfile leaf.ext -out "$tag-leaf.crt" 2>/dev/null
}

echo "## Chain size comparison (bytes, DER)"
printf "%-13s int=%-6s leaf=%-6s wire-chain=%-6s\n" "header" "int" "leaf" "int+leaf" >/dev/null
declare -A WIRE
for row in "ecdsa-p256:EC:P-256:EC:P-256" "mldsa65-pure:ML-DSA-65:ML-DSA-65" \
           "mldsa87-pure:ML-DSA-87:ML-DSA-87" "slh128s-root:SLH-DSA-SHA2-128s:ML-DSA-65"; do
  tag="${row%%:*}"; rest="${row#*:}"
  # rest may contain "EC:P-256:EC:P-256" or "ML-DSA-65:ML-DSA-65"
  ralg="${rest%%:ML-DSA*}"; # crude; recompute cleanly below
  # clean parse: split into fields
  IFS=':' read -r f1 f2 f3 f4 <<< "$rest"
  if [ "$f1" = "EC" ]; then ralg="EC:$f2"; salg="EC:$f4"; else ralg="$f1"; salg="$f2"; fi
  build_chain "$tag" "$ralg" "$salg"
  i=$(der "$tag-int.crt"); l=$(der "$tag-leaf.crt"); w=$((i+l)); WIRE["$tag"]=$w
  extra=""
  [ "$tag" = "slh128s-root" ] && extra="   (root.der=$(der "$tag-root.crt"))"
  printf "%-13s int=%-6s leaf=%-6s wire-chain=%-6s%s\n" "$tag" "$i" "$l" "$w" "$extra"
done
base="${WIRE[ecdsa-p256]}"
for t in mldsa65-pure mldsa87-pure slh128s-root; do
  printf "  %-13s %sx classical (wire vs ECDSA %s)\n" "$t" \
    "$(awk "BEGIN{printf \"%.1f\", ${WIRE[$t]}/$base}")" "$base"
done
echo

# --- CA-3: ML-KEM-768 leaf cert + the CSR proof-of-possession break -----------
echo "## ML-KEM-768 leaf cert (signed by ML-DSA-65 issuing CA)"
# reuse the ML-DSA-65 chain's int as issuer
$OSSL genpkey -algorithm ML-KEM-768 -out kem.key
# VERIFIED gotcha: a KEM key cannot self-sign a PKCS#10 CSR.
echo -n "## KEM key self-signs a CSR? -> "
if $OSSL req -new -key kem.key -subj "/CN=kem.example.com" -out kem.csr 2>kem.err; then
  echo "UNEXPECTED: CSR succeeded"
else
  echo "NO (expected). openssl says: $(grep -o 'operation not supported for this keytype' kem.err || tail -1 kem.err)"
fi
# Issuance path that works: force the real KEM pubkey into the cert via a dummy CSR.
$OSSL pkey -in kem.key -pubout -out kem.pub 2>/dev/null
$OSSL req -new -key mldsa65-pure-leaf.key -subj "/CN=kem.example.com" -out kemdummy.csr 2>/dev/null
cat > kem.ext <<EOF
subjectAltName=DNS:kem.example.com
keyUsage=critical,keyEncipherment
EOF
$OSSL x509 -req -in kemdummy.csr -force_pubkey kem.pub \
  -CA mldsa65-pure-int.crt -CAkey mldsa65-pure-int.key -set_serial 0x2001 \
  -not_before "$NB" -not_after "$NA" -extfile kem.ext -out kemleaf.crt 2>/dev/null
echo "## ML-KEM-768 leaf cert size: $(der kemleaf.crt) bytes DER"
echo

# --- composite support probe --------------------------------------------------
comp=$($OSSL list -public-key-algorithms 2>/dev/null | grep -ic composite || true)
echo "## OpenSSL composite signature support: $comp entries (0 = none)"
echo

# --- verification -------------------------------------------------------------
echo "## Verify outputs:"
$OSSL verify -CAfile slh128s-root-root.crt -untrusted slh128s-root-int.crt slh128s-root-leaf.crt 2>&1 | sed 's/slh128s-root-leaf.crt/mixed-chain-leaf.crt/'
$OSSL verify -CAfile mldsa65-pure-root.crt -untrusted mldsa65-pure-int.crt kemleaf.crt 2>&1
