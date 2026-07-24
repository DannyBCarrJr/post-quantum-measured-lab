// ML-KEM-768 interop harness: pqcrypto (Dart) <-> OpenSSL 3.5.5
//
// Modes:
//   encap <ek.bin> <ct.out> <ss.out>   — encapsulate to an external public key
//   decap <dk.bin> <ct.bin> <ss.out>   — decapsulate an external ciphertext
//   keygen <ek.out> <dk.out>           — generate a keypair, write raw ek/dk
import 'dart:io';
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

void main(List<String> args) {
  final kem = PqcKem.kyber768;
  switch (args[0]) {
    case 'keygen':
      final (pk, sk) = kem.generateKeyPair();
      File(args[1]).writeAsBytesSync(pk);
      File(args[2]).writeAsBytesSync(sk);
      stderr.writeln('keygen ok: ek=${pk.length}B dk=${sk.length}B');
    case 'encap':
      final ek = Uint8List.fromList(File(args[1]).readAsBytesSync());
      final (ct, ss) = kem.encapsulate(ek);
      File(args[2]).writeAsBytesSync(ct);
      File(args[3]).writeAsBytesSync(ss);
      stderr.writeln('encap ok: ct=${ct.length}B ss=${ss.length}B');
    case 'decap':
      final dk = Uint8List.fromList(File(args[1]).readAsBytesSync());
      final ct = Uint8List.fromList(File(args[2]).readAsBytesSync());
      final ss = kem.decapsulate(dk, ct);
      File(args[3]).writeAsBytesSync(ss);
      stderr.writeln('decap ok: ss=${ss.length}B');
    default:
      stderr.writeln('unknown mode');
      exit(2);
  }
}
