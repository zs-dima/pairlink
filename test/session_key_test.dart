import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import 'fixture.dart';

/// The attack these properties stop: a phone on the same Wi-Fi injecting a power event. It does not
/// look like an attack, it looks like the application recording one wrong reading, quietly.
///
/// Every property is stated in terms of what an uninvited peer holds, not what a function returns:
/// probing an already-established key proves nothing about the handshake.
void main() {
  const hostNonce = 'aG9zdC1ub25jZQ==';
  const guestNonce = 'Z3Vlc3Qtbm9uY2U=';

  group('PairSecret', () {
    test('a scanned secret survives the QR round trip', () {
      final secret = PairSecret.generate();

      final restored = PairSecret.fromBase64Url(secret.toBase64Url());

      expect(restored.strength, equals(PairStrength.scanned));
      expect(
        restored.deriveKey(brand: kTestIdentity.brand, hostNonce: hostNonce, guestNonce: guestNonce).sign(
          <String, Object?>{'t': 'bye'},
        ),
        equals(
          secret.deriveKey(brand: kTestIdentity.brand, hostNonce: hostNonce, guestNonce: guestNonce).sign(
            <String, Object?>{'t': 'bye'},
          ),
        ),
      );
    });

    test('generated secrets do not repeat', () {
      final seen = <String>{};
      for (var i = 0; i < 200; i++) {
        seen.add(PairSecret.generate().toBase64Url());
      }

      expect(seen, hasLength(200));
      // 16 bytes of base64url. Anything shorter is a generator that quietly failed.
      expect(seen.first.length, greaterThanOrEqualTo(22));
    });

    test('codes are four digits, zero-padded, and spread over the whole range', () {
      final codes = <String>{};
      for (var i = 0; i < 500; i++) {
        codes.add(PairSecret.newCode());
      }

      expect(codes.every((c) => RegExp(r'^\d{4}$').hasMatch(c)), isTrue);
      // 500 draws from 10 000 should land on a few hundred distinct values; a constant or a tiny
      // range would fail here rather than in the field.
      expect(codes.length, greaterThan(200));
    });

    test('the two paths are labelled differently, because they are not equally private', () {
      expect(PairSecret.generate().strength, equals(PairStrength.scanned));
      expect(PairSecret.code('7392').strength, equals(PairStrength.typed));
    });
  });

  group('SessionKey', () {
    final secret = PairSecret.generate();
    final key = secret.deriveKey(brand: kTestIdentity.brand, hostNonce: hostNonce, guestNonce: guestNonce);

    test('signs and verifies its own frames', () {
      final frame = const Power(state: .lost, atMs: 1000, seq: 1).toBody();

      expect(key.verify(frame, key.sign(frame)), isTrue);
    });

    test('neither side can fix the key alone', () {
      // If the connecting side chose the only nonce, anyone holding the secret material could
      // derive the session key unilaterally.
      final otherPanelNonce = secret.deriveKey(
        brand: kTestIdentity.brand,
        hostNonce: 'ZGlmZmVyZW50',
        guestNonce: guestNonce,
      );
      final otherOutletNonce = secret.deriveKey(
        brand: kTestIdentity.brand,
        hostNonce: hostNonce,
        guestNonce: 'ZGlmZmVyZW50',
      );
      final frame = const Bye().toBody();

      expect(key.verify(frame, otherPanelNonce.sign(frame)), isFalse);
      expect(key.verify(frame, otherOutletNonce.sign(frame)), isFalse);
    });

    test('a different secret produces a different key', () {
      final stranger = PairSecret.generate().deriveKey(
        brand: kTestIdentity.brand,
        hostNonce: hostNonce,
        guestNonce: guestNonce,
      );
      final frame = const Bye().toBody();

      expect(key.verify(frame, stranger.sign(frame)), isFalse);
    });

    test('a signature does not carry across frames', () {
      final restored = const Power(state: .restored, atMs: 1000, seq: 1).toBody();
      final lost = const Power(state: .lost, atMs: 1000, seq: 1).toBody();

      expect(key.verify(lost, key.sign(restored)), isFalse);
    });

    test('changing a single field invalidates the mac', () {
      final original = const Power(state: .lost, atMs: 1000, seq: 1).toBody();
      final mac = key.sign(original);

      for (final tampered in <Map<String, Object?>>[
        <String, Object?>{...original, 'seq': 2},
        <String, Object?>{...original, 'ts': 1001},
        <String, Object?>{...original, 'state': 'restored'},
        <String, Object?>{...original}..remove('seq'),
      ]) {
        expect(key.verify(tampered, mac), isFalse, reason: '$tampered');
      }
    });

    test('a missing, empty or nonsense mac is not a valid mac', () {
      final frame = const Bye().toBody();

      expect(key.verify(frame, null), isFalse);
      expect(key.verify(frame, ''), isFalse);
      expect(key.verify(frame, 'not base64 at all'), isFalse);
    });

    test('field order does not change the signature', () {
      // Two encoders that disagree about key order must still agree about the MAC, or a harmless
      // re-serialisation anywhere in the stack would look like tampering.
      final forward = <String, Object?>{'t': 'power', 'state': 'lost', 'ts': 1, 'seq': 1};
      final reversed = <String, Object?>{'seq': 1, 'ts': 1, 'state': 'lost', 't': 'power'};

      expect(key.sign(forward), equals(key.sign(reversed)));
    });

    test('the mac field itself is never part of what is signed', () {
      final frame = <String, Object?>{'t': 'bye'};
      final mac = key.sign(frame);

      expect(key.verify(<String, Object?>{...frame, 'mac': mac}, mac), isTrue);
    });
  });

  group('AttemptLimiter', () {
    test('opens, then closes after the budget is spent', () {
      final limiter = AttemptLimiter(maxAttempts: 3);
      expect(limiter.isOpen, isTrue);

      expect(limiter.recordFailure(), isTrue);
      // recordFailure() spends budget: this call is failure 2 of 3, not a re-assertion.
      // ignore: avoid-duplicate-test-assertions
      expect(limiter.recordFailure(), isTrue);
      expect(limiter.recordFailure(), isFalse);
      expect(limiter.isOpen, isFalse);
    });

    test('caps four digits well short of 10 000 guesses', () {
      // A typed code is only a secret while guessing is expensive: five tries out of ten thousand
      // is a 0.05% chance.
      final limiter = AttemptLimiter();
      for (var i = 0; i < 100; i++) {
        limiter.recordFailure();
      }

      expect(limiter.failures, equals(100));
      expect(limiter.isOpen, isFalse);
    });

    test('a success clears the count, so an honest fumble is not punished forever', () {
      final limiter = AttemptLimiter(maxAttempts: 3)
        ..recordFailure()
        ..recordFailure()
        ..reset();

      expect(limiter.isOpen, isTrue);
      expect(limiter.failures, isZero);
    });
  });

  group('ReplayGuard', () {
    test('accepts a normal ascending run', () {
      final guard = ReplayGuard();

      for (var seq = 1; seq <= 5; seq++) {
        expect(
          guard.accept(Power(state: .lost, atMs: seq * 1000, seq: seq)),
          isTrue,
          reason: 'seq $seq',
        );
      }
    });

    test('drops a captured frame sent again', () {
      final guard = ReplayGuard();
      const captured = Power(state: .lost, atMs: 1000, seq: 1);

      expect(guard.accept(captured), isTrue);
      expect(guard.accept(captured), isFalse, reason: 'the same frame twice is one event');
    });

    test('drops an old frame replayed after newer ones', () {
      final guard = ReplayGuard()
        ..accept(const Power(state: .lost, atMs: 1000, seq: 1))
        ..accept(const Power(state: .restored, atMs: 2000, seq: 2));

      expect(guard.accept(const Power(state: .lost, atMs: 1000, seq: 1)), isFalse);
    });

    test('drops a frame whose stamp goes backwards even with a fresh seq', () {
      final guard = ReplayGuard()..accept(const Power(state: .lost, atMs: 5000, seq: 1));

      expect(guard.accept(const Power(state: .lost, atMs: 1000, seq: 99)), isFalse);
    });

    test('a wall-clock correction cannot silence the session', () {
      // The stamp is monotonic, so an NTP step backwards the moment Wi-Fi returns does not look
      // like a replay. Ordered by the wall clock instead, every later event would be dropped while
      // power kept flipping.
      final guard = ReplayGuard()..accept(const Power(state: .lost, atMs: 900000, wallMs: 1700000000000, seq: 1));

      // Monotonic advanced by 8 s; the wall clock jumped back by an hour.
      expect(
        guard.accept(const Power(state: .restored, atMs: 908000, wallMs: 1699996400000, seq: 2)),
        isTrue,
        reason: 'ordering follows the monotonic stamp, never the wall clock',
      );
    });

    test('a reconnect replay is idempotent', () {
      final guard = ReplayGuard();
      final queue = <Power>[
        const Power(state: .lost, atMs: 1000, seq: 1),
        const Power(state: .restored, atMs: 2000, seq: 2),
        const Power(state: .lost, atMs: 9000, seq: 3),
      ];

      // The guard is stateful, so the second pass over the same queue is the replay.
      final firstPass = queue.where(guard.accept).toList();
      // Same expression, different verdicts: guard.accept already consumed these seqs.
      // ignore: avoid-duplicate-initializers
      final replayed = queue.where(guard.accept).toList();

      expect(firstPass, hasLength(3));
      expect(replayed, isEmpty, reason: 'exactly once, even though the sender resent everything');
    });

    test('a replay that overlaps new events keeps only the new ones', () {
      final guard = ReplayGuard()
        ..accept(const Power(state: .lost, atMs: 1000, seq: 1))
        ..accept(const Power(state: .restored, atMs: 2000, seq: 2));

      final resent = <Power>[
        const Power(state: .lost, atMs: 1000, seq: 1),
        const Power(state: .restored, atMs: 2000, seq: 2),
        const Power(state: .lost, atMs: 9000, seq: 3),
      ];

      expect(resent.where(guard.accept).map((f) => f.seq), equals(<int>[3]));
    });

    test('reset is for a new session, and it does forget', () {
      final guard = ReplayGuard()..accept(const Power(state: .lost, atMs: 5000, seq: 9));
      expect(guard.lastSeq, equals(9));

      guard.reset();

      expect(guard.lastSeq, equals(-1));
      expect(guard.accept(const Power(state: .lost, atMs: 1, seq: 1)), isTrue);
    });
  });
}
