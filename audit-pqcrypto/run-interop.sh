#!/usr/bin/env bash
# ML-KEM-768 interop: pqcrypto (pure Dart) <-> OpenSSL 3.5.5 native ML-KEM.
# Direction A: OpenSSL keygen -> Dart encap -> OpenSSL decap  (ss must match)
# Direction B: Dart keygen  -> OpenSSL encap -> Dart decap    (ss must match)
set -euo pipefail
cd "$(dirname "$0")"
D="work"; rm -rf "$D"; mkdir -p "$D"

echo "== Direction A: OpenSSL keygen -> Dart encap -> OpenSSL decap =="
openssl genpkey -algorithm ML-KEM-768 -out "$D/ossl_priv.pem"
openssl pkey -in "$D/ossl_priv.pem" -pubout -outform DER -out "$D/ossl_ek.der"
# raw ek (1184B) is the tail of the SPKI DER
tail -c 1184 "$D/ossl_ek.der" > "$D/ossl_ek.bin"
dart run mlkem_interop.dart encap "$D/ossl_ek.bin" "$D/a_ct.bin" "$D/a_ss_dart.bin"
openssl pkeyutl -decap -inkey "$D/ossl_priv.pem" -in "$D/a_ct.bin" -out "$D/a_ss_ossl.bin"
if cmp -s "$D/a_ss_dart.bin" "$D/a_ss_ossl.bin"; then
  echo "A: SHARED SECRETS MATCH ($(sha256sum < "$D/a_ss_dart.bin" | cut -c1-16)...)"
else
  echo "A: MISMATCH"; exit 1
fi

echo "== Direction B: Dart keygen -> OpenSSL encap -> Dart decap =="
dart run mlkem_interop.dart keygen "$D/dart_ek.bin" "$D/dart_dk.bin"
# Wrap the raw Dart ek into an SPKI using the constant header from Direction A
HEADER_LEN=$(( $(stat -c%s "$D/ossl_ek.der") - 1184 ))
head -c "$HEADER_LEN" "$D/ossl_ek.der" > "$D/spki_header.bin"
cat "$D/spki_header.bin" "$D/dart_ek.bin" > "$D/dart_ek.der"
openssl pkey -pubin -inform DER -in "$D/dart_ek.der" -out "$D/dart_ek.pem"
openssl pkeyutl -encap -pubin -inkey "$D/dart_ek.pem" -out "$D/b_ct.bin" -secret "$D/b_ss_ossl.bin"
dart run mlkem_interop.dart decap "$D/dart_dk.bin" "$D/b_ct.bin" "$D/b_ss_dart.bin"
if cmp -s "$D/b_ss_dart.bin" "$D/b_ss_ossl.bin"; then
  echo "B: SHARED SECRETS MATCH ($(sha256sum < "$D/b_ss_dart.bin" | cut -c1-16)...)"
else
  echo "B: MISMATCH"; exit 1
fi

echo "== Negative control: tampered ct must NOT match (implicit rejection) =="
cp "$D/b_ct.bin" "$D/b_ct_bad.bin"
printf '\x01' | dd of="$D/b_ct_bad.bin" bs=1 seek=100 count=1 conv=notrunc status=none
dart run mlkem_interop.dart decap "$D/dart_dk.bin" "$D/b_ct_bad.bin" "$D/b_ss_bad.bin"
if cmp -s "$D/b_ss_bad.bin" "$D/b_ss_ossl.bin"; then
  echo "NEGATIVE CONTROL FAILED: tampered ct produced the same ss"; exit 1
else
  echo "Negative control OK: tampered ct -> different ss (no error, implicit rejection)"
fi
echo "ALL INTEROP CHECKS PASSED"
