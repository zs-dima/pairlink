import 'dart:convert';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import '../fixture.dart';
import 'hostile.dart';
import 'victim.dart';

/// The handshake, probed by a peer that is not the honest client.
///
/// Every probe is written against the wire: raw sockets, hand-built JSON lines, and a MAC computed
/// by this file's own HKDF. Nothing borrows [PanelSession], because an attacker built out of the
/// honest client can only do what the honest client does.
// A registration function: the branches are the probes it declares.
// ignore: avoid-high-cyclomatic-complexity
void main() {
  const code = '7392';
  late OutletVictim victim;

  Future<void> stop() => victim.stop();

  /// Reads the challenge and returns the outlet phone's nonce.
  Future<String> challengeOf(Hostile attacker) async {
    final challenge = await attacker.nextFrame();
    expect(challenge?['t'], equals('challenge'), reason: 'the outlet phone speaks first');
    return challenge!['nonce']! as String;
  }

  group('the attacker really can speak this protocol', () {
    test('control: a hand-rolled client holding the code pairs', () async {
      // Without this control, every refusal below could be a broken client rather than a defence.
      victim = await OutletVictim.start(PairSecret.code(code), device: 'Redmi Note 12');
      addTearDown(stop);

      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);

      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce, 'device': 'attacker'};
      attacker.frame(body, mac: signBody(key, body));

      final welcome = await attacker.nextFrame();
      expect(welcome?['t'], equals('welcome'));
      expect(victim.session.isPaired, isTrue, reason: 'without this every result below is vacuous');
    });

    test('control: a hand-rolled client holding the scanned secret pairs', () async {
      final secret = PairSecret.generate();
      victim = await OutletVictim.start(secret);
      addTearDown(stop);

      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);

      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(
        base64Url.decode(secret.toBase64Url()),
        hostNonce,
        guestNonce,
        brand: kTestIdentity.brand,
      );
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.frame(body, mac: signBody(key, body));

      final welcome = await attacker.nextFrame();
      expect(welcome?['t'], equals('welcome'));
    });
  });

  group('scanned path: an attacker who captured the whole handshake', () {
    test('a captured hello replayed onto a fresh connection is refused', () async {
      // The whole handshake is captured off the wire during one session and replayed at the next:
      // the same two phones, the same QR, a new socket. A new session rather than merely a new
      // connection, because a session that has paired once refuses further connections.
      final secret = PairSecret.generate();
      victim = await OutletVictim.start(secret);
      addTearDown(stop);

      final honest = await Hostile.connect(victim.port);
      final hostNonce = await challengeOf(honest);
      const guestNonce = 'aG9uZXN0';
      final key = attackerKey(
        base64Url.decode(secret.toBase64Url()),
        hostNonce,
        guestNonce,
        brand: kTestIdentity.brand,
      );
      final helloBody = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      final capturedLine = jsonEncode(<String, Object?>{...helloBody, 'mac': signBody(key, helloBody)});
      honest.line(capturedLine);
      final welcome = await honest.nextFrame();
      expect(welcome?['t'], equals('welcome'), reason: 'the capture must be of a REAL pairing');
      await honest.close();
      await victim.stop();

      // Attack: the same bytes, the same secret, the next session.
      victim = await OutletVictim.start(secret);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);
      attacker.line(capturedLine);

      final answer = await attacker.nextFrame();
      expect(answer?['t'], equals('reject'), reason: 'a recorded handshake must not pair a stranger');
      expect(answer?['reason'], equals('wrongCode'));
      expect(victim.session.isPaired, isFalse);
    });

    test("reflecting the outlet phone's own nonce back at it proves nothing", () async {
      victim = await OutletVictim.start(PairSecret.generate());
      addTearDown(stop);

      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);

      // Every MAC an uninvited peer can compute from public material alone.
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': hostNonce};
      for (final mac in <String>[
        hostNonce,
        base64Encode(utf8.encode(hostNonce)),
        signBody(utf8.encode(hostNonce), body),
        signBody(base64Decode(hostNonce), body),
        signBody(const <int>[], body),
        signBody(utf8.encode(canonical(body)), body),
      ]) {
        attacker.frame(body, mac: mac);
      }

      await Future<void>.delayed(const Duration(milliseconds: 250));
      expect(victim.session.isPaired, isFalse);
    });
  });

  group('macs an attacker can shape', () {
    setUp(() async {
      victim = await OutletVictim.start(PairSecret.code(code), limiter: AttemptLimiter(maxAttempts: 999));
    });
    tearDown(stop);

    for (final (name, mac) in <(String, String?)>[
      ('absent', null),
      ('empty', ''),
      ('one byte', 'A'),
      ('not base64', '!!!!!!!!'),
      ('a 60 KB', 'A' * 60000),
      ('an all-zero, right-length', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
    ]) {
      test('a $name mac is refused', () async {
        final attacker = await Hostile.connect(victim.port);
        addTearDown(attacker.close);
        await challengeOf(attacker);
        attacker.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': 'bm9uY2U='}, mac: mac);

        final reject = await attacker.nextFrame();
        expect(reject?['t'], equals('reject'));
        expect(victim.session.isPaired, isFalse);
      });
    }

    test('a mac computed over fewer keys than are sent is refused', () async {
      // Signed over {v,t,nonce}, sent with an extra field. If verification canonicalised only the
      // fields it understands, this would pass and every unknown field would be unauthenticated.
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);
      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      final signed = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.frame(<String, Object?>{...signed, 'device': 'injected'}, mac: signBody(key, signed));

      final reject = await attacker.nextFrame();
      expect(reject?['t'], equals('reject'), reason: 'the signed set of keys must be the received set');
    });

    test('an unknown field added after signing does not slip past the mac', () async {
      // A field this build does not model at all. If verification re-serialised the parsed frame
      // instead of covering the body that arrived, every unknown field would be unauthenticated,
      // and unknown fields are what a future protocol version adds.
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);
      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      final signed = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.frame(<String, Object?>{...signed, 'junk': 'unmodelled'}, mac: signBody(key, signed));

      final reject = await attacker.nextFrame();
      expect(reject?['t'], equals('reject'), reason: 'the mac must cover the whole body');
    });

    test('wire key order does not change the verdict', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);
      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.line('{"nonce":"$guestNonce","t":"hello","v":3,"mac":"${signBody(key, body)}"}');

      final welcome = await attacker.nextFrame();
      expect(welcome?['t'], equals('welcome'));
    });

    test('a duplicate key cannot smuggle a value past the mac', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);
      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      // Signed as nonce=guestNonce; the smuggled first value is what a first-wins parser would use
      // for key derivation while the second is what got signed.
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.line(
        '{"v":3,"t":"hello","nonce":"c211Z2dsZWQ=","nonce":"$guestNonce","mac":"${signBody(key, body)}"}',
      );

      final answer = await attacker.nextFrame();
      // Whatever the parser picks, the value it derives the key from must be the value it verified.
      // Last-wins (dart:convert) makes this a welcome; first-wins would make it a reject. Either is
      // sound. Two different values being used would not be.
      expect(answer?['t'], anyOf(equals('welcome'), equals('reject')));
    });

    test('unicode escapes decode to the same signed string', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final hostNonce = await challengeOf(attacker);
      const guestNonce = 'Z3Vlc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
      attacker.line('{"v":3,"t":"\\u0068ello","nonce":"$guestNonce","mac":"${signBody(key, body)}"}');

      final welcome = await attacker.nextFrame();
      expect(welcome?['t'], equals('welcome'));
    });

    test('a float version is refused rather than coerced', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);
      attacker.line('{"v":2.0,"t":"hello","nonce":"Zg==","mac":"AAAA"}');

      final reject = await attacker.nextFrame();
      expect(reject?['t'], equals('reject'));
    });
  });

  group('nonces the attacker controls', () {
    setUp(() async {
      victim = await OutletVictim.start(PairSecret.code(code), limiter: AttemptLimiter(maxAttempts: 999));
    });
    tearDown(stop);

    test('a zero-length nonce still needs the secret', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': ''};
      attacker.frame(body, mac: signBody(const <int>[0], body));

      final reject = await attacker.nextFrame();
      expect(reject?['t'], equals('reject'));
      expect(victim.session.isPaired, isFalse);
    });

    test('an absent nonce is malformed, not a null key', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);
      attacker.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'hello'});

      final reject = await attacker.nextFrame();
      expect(reject?['t'], equals('reject'));
      expect(victim.session.isPaired, isFalse);
    });

    test('a nonce reused across connections buys nothing', () async {
      for (var attempt = 0; attempt < 3; attempt++) {
        // A fresh connection per attempt is the property under test: reuse across connections.
        // ignore: move-variable-outside-iteration
        final attacker = await Hostile.connect(victim.port);
        addTearDown(attacker.close);
        await challengeOf(attacker);
        attacker.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': 'Zml4ZWQ='}, mac: 'AAAA');
        // The reject for this connection's reused nonce, read once per iteration.
        // ignore: move-variable-outside-iteration
        final reject = await attacker.nextFrame();
        expect(reject?['t'], equals('reject'));
      }
      expect(victim.session.isPaired, isFalse);
    });

    test('a host nonce is never reused between connections', () async {
      final seen = <String>{};
      for (var attempt = 0; attempt < 12; attempt++) {
        // Twelve separate connections, one challenge each, which is what "between connections"
        // means.
        // ignore: move-variable-outside-iteration
        final attacker = await Hostile.connect(victim.port);
        addTearDown(attacker.close);
        seen.add(await challengeOf(attacker));
        await attacker.close();
      }

      expect(seen, hasLength(12), reason: 'a repeated challenge would make a captured hello replayable');
    });
  });
}
