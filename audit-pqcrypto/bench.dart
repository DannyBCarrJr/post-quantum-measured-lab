// ML-KEM-768 micro-benchmark on the Dart VM (JIT ≈ upper bound for AOT mobile).
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  final kem = PqcKem.kyber768;
  // Warmup
  var (pk, sk) = kem.generateKeyPair();
  for (var i = 0; i < 20; i++) {
    final (ct, _) = kem.encapsulate(pk);
    kem.decapsulate(sk, ct);
  }
  const n = 200;
  var sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    kem.generateKeyPair();
  }
  sw.stop();
  print('keygen: ${(sw.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms/op');

  sw = Stopwatch()..start();
  late dynamic lastCt;
  for (var i = 0; i < n; i++) {
    final (ct, _) = kem.encapsulate(pk);
    lastCt = ct;
  }
  sw.stop();
  print('encaps: ${(sw.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms/op');

  sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    kem.decapsulate(sk, lastCt);
  }
  sw.stop();
  print('decaps: ${(sw.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms/op');
}
