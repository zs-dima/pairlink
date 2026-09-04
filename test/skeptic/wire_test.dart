import 'dart:convert';
import 'dart:io';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import '../fixture.dart';
import 'hostile.dart';
import 'victim.dart';

/// The outermost surface: bytes on a socket, and a QR the camera happened to see.
///
/// Everything here is aimed at the outlet phone, which anyone on the Wi-Fi can reach with no user
/// action at all. The bar is not "handles it correctly" but "never crashes, never hangs, and is
/// still able to pair afterwards".
void main() {
  const code = '7392';
  late OutletVictim victim;

  setUp(() async {
    victim = await OutletVictim.start(PairSecret.code(code), limiter: AttemptLimiter(maxAttempts: 999));
  });
  tearDown(() => victim.stop());

  /// Pairs from a hand-rolled client: proof the phone is still usable after the probe.
  Future<bool> stillPairs() async {
    final honest = await Hostile.connect(victim.port);
    addTearDown(honest.close);
    final challenge = await honest.nextFrame(within: const Duration(seconds: 2));
    if (challenge?['t'] != 'challenge') return false;
    const guest = 'aG9uZXN0';
    final key = attackerKey(codeSecret(code), challenge!['nonce']! as String, guest, brand: kTestIdentity.brand);
    final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
    honest.frame(body, mac: signBody(key, body));
    // The frame after the challenge: nextFrame() consumes, so this is not the same value.
    // ignore: avoid-duplicate-initializers
    final answer = await honest.nextFrame(within: const Duration(seconds: 2));
    return answer?['t'] == 'welcome';
  }

  group('a line the decoder has to survive', () {
    final lines = <String, String>{
      'array nesting 32 000 deep': '${'[' * 32000}${']' * 32000}',
      'object nesting 10 000 deep': '${'{"a":' * 10000}1${'}' * 10000}',
      'an integer far past 2^63': '{"v":2,"t":"hello","nonce":"eA==","big":99999999999999999999999999}',
      'an exponent that overflows': '{"v":2,"t":"hello","nonce":"eA==","big":1e400}',
      'a negative-zero stamp': '{"t":"power","state":"lost","ts":-0.0,"seq":1}',
      'a lone surrogate escape': r'{"v":2,"t":"hello","nonce":"\ud800"}',
      'a nonce that is an object': '{"v":2,"t":"hello","nonce":{"a":1}}',
      'a type tag that is an array': '{"t":["hello"],"v":2}',
      'a whole frame that is null': 'null',
      'a bare true': 'true',
      'a mac that is an object': '{"t":"bye","mac":{"x":1}}',
      'a seq that is a string': '{"t":"power","state":"lost","ts":1,"seq":"1"}',
      'a 60 KB device name': '{"v":2,"t":"hello","nonce":"eA==","device":"${'d' * 60000}"}',
      'a v1 hello': '{"v":1,"t":"hello","code":"7392","nonce":"eA=="}',
    };

    for (final MapEntry(key: name, value: line) in lines.entries) {
      test('$name is refused, and the phone still pairs afterwards', () async {
        final attacker = await Hostile.connect(victim.port);
        addTearDown(attacker.close);
        await attacker.nextFrame();
        attacker.line(line);
        await Future<void>.delayed(const Duration(milliseconds: 300));

        expect(attacker.framesOfType('welcome'), isEmpty, reason: 'nothing here proves possession');
        expect(victim.session.isPaired, isFalse);
        await attacker.close();
        expect(await stillPairs(), isTrue, reason: 'one bad line must not cost the next pairing');
      });
    }

    test('a v1 peer is told the version is wrong, not that its code is wrong', () async {
      // An older build will meet a newer one: the outlet phone is any spare phone with the
      // application installed, and nobody updates both at once. Asserting only "refused" would pass
      // with the version check deleted, because a v1 hello has no valid mac either; the reason is
      // the property.
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      // Each call reads the next frame off the wire, not a repeated lookup.
      // ignore: prefer-moving-to-variable
      await attacker.nextFrame();
      attacker.line('{"v":1,"t":"hello","code":"$code","nonce":"eA=="}');

      // Each call reads the next frame off the wire, not a repeated lookup.
      // ignore: prefer-moving-to-variable
      final answer = await attacker.nextFrame();
      expect(answer?['t'], equals('reject'));
      expect(answer?['reason'], equals('versionMismatch'), reason: 'a stale build must be told to update');
    });

    test('a stamp that is a float is malformed, not silently truncated', () async {
      // A timestamp arriving as 1.7e12 means the sender is not this protocol, and coercing it hides
      // that (frames.dart). Asserting only "refused" would pass with the coercion added, because
      // the mac is wrong either way; the reason is the property.
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      // Each call reads the next frame off the wire, not a repeated lookup.
      // ignore: prefer-moving-to-variable
      await attacker.nextFrame();
      attacker.line('{"v":2.0,"t":"hello","nonce":"eA==","mac":"AAAA"}');

      // Each call reads the next frame off the wire, not a repeated lookup.
      // ignore: prefer-moving-to-variable
      final answer = await attacker.nextFrame();
      expect(answer?['reason'], equals('malformed'), reason: 'a float where an int belongs is a foreign protocol');
    });
  });

  group('framing', () {
    test('a valid frame split across three packets is still one frame', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final challenge = await attacker.nextFrame();
      final hostNonce = challenge!['nonce']! as String;
      const guest = 'aG9uZXN0';
      final key = attackerKey(codeSecret(code), hostNonce, guest, brand: kTestIdentity.brand);
      final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
      final full = jsonEncode(<String, Object?>{...body, 'mac': signBody(key, body)});

      // ASCII wire bytes; the JSON is split mid-token.
      // ignore: avoid-substring
      attacker.write(utf8.encode(full.substring(0, 12)));
      await Future<void>.delayed(const Duration(milliseconds: 60));
      // ASCII wire bytes; the mid-token split continues.
      // ignore: avoid-substring
      attacker.write(utf8.encode(full.substring(12, 30)));
      await Future<void>.delayed(const Duration(milliseconds: 60));
      // ASCII wire bytes; the tail of the same split.
      // ignore: avoid-substring
      attacker.write(utf8.encode('${full.substring(30)}\n'));
      await Future<void>.delayed(const Duration(milliseconds: 300));

      expect(attacker.framesOfType('welcome'), hasLength(1));
    });

    test('two frames coalesced into one packet are both seen', () async {
      // TCP is a byte stream. A hello and a bye written back to back routinely arrive as one read,
      // and a framer that assumes otherwise works on a desk and fails on a busy network.
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final challenge = await attacker.nextFrame();
      final hostNonce = challenge!['nonce']! as String;
      const guest = 'aG9uZXN0';
      final key = attackerKey(codeSecret(code), hostNonce, guest, brand: kTestIdentity.brand);
      final hello = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
      const bye = <String, Object?>{'t': 'bye'};
      final packet = StringBuffer()
        ..writeln(jsonEncode(<String, Object?>{...hello, 'mac': signBody(key, hello)}))
        ..writeln(jsonEncode(<String, Object?>{...bye, 'mac': signBody(key, bye)}));
      attacker.write(utf8.encode(packet.toString()));
      await Future<void>.delayed(const Duration(milliseconds: 400));

      expect(attacker.framesOfType('welcome'), hasLength(1));
      expect(victim.session.isPaired, isFalse, reason: 'the bye in the same packet was seen too');
    });

    test('a junk first frame ends the connection instead of being skipped', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await attacker.nextFrame();
      attacker.line('{"t":"bye"}');
      await Future<void>.delayed(const Duration(milliseconds: 300));

      final reject = attacker.framesOfType('reject');
      expect(reject, isNotEmpty);
      expect(reject.last['reason'], equals('malformed'));
    });

    test('a literal newline inside a string value cannot smuggle a second frame', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await attacker.nextFrame();
      attacker.write(utf8.encode('{"v":2,"t":"hello","nonce":"a\n{\\"t\\":\\"bye\\"}"}\n'));
      await Future<void>.delayed(const Duration(milliseconds: 300));

      expect(attacker.framesOfType('welcome'), isEmpty);
      expect(attacker.framesOfType('reject'), isNotEmpty);
    });

    test('8 MB with no newline is hung up on rather than buffered', () async {
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await attacker.nextFrame();

      final before = ProcessInfo.currentRss;
      final chunk = utf8.encode('x' * 65536);
      // Bounded by time as well as by count, and every flush has its own deadline. Once the subject
      // hits the cap it stops reading, so the flooder's socket buffer fills and `flush()` blocks:
      // backpressure working as intended, but enough to hang this test on the suite timeout.
      // Stopping early costs nothing, since the assertions below are about what the subject did.
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      for (var i = 0; i < 128 && !attacker.closedByPeer && DateTime.now().isBefore(deadline); i++) {
        attacker.write(chunk);
        await attacker.flush().timeout(const Duration(seconds: 2), onTimeout: () {});
      }
      await Future<void>.delayed(const Duration(milliseconds: 300));

      expect(attacker.closedByPeer, isTrue, reason: 'a peer that never sends a newline is hung up on');
      expect(
        ProcessInfo.currentRss - before,
        lessThan(16 * 1024 * 1024),
        reason: 'the cap bounds the buffer, not just the frame',
      );
      await attacker.close();
      expect(await stillPairs(), isTrue);
    });
  });

  group('the QR payload', () {
    test('a hostile URI never throws, whatever the camera saw', () {
      for (final raw in <String>[
        'pltest://pair?h=evil.example.com&p=443&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=10.0.0.1&p=65536&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=10.0.0.1&p=-1&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://user@pair:99?h=10.0.0.1&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=10.0.0.1&h=6.6.6.6&p=1&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'PLTEST://PAIR?h=10.0.0.1&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=10.0.0.1%00&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=${'1' * 200000}&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
        'pltest://pair?h=10.0.0.1&p=41235&k=${'A' * 200000}',
        'pltest://pair?h=10.0.0.1&p=41235&k=AA==',
      ]) {
        expect(
          () => PairInvite.tryParse(raw, identity: kTestIdentity),
          returnsNormally,
          // ASCII test URIs; a short preview slice for the failure reason is harmless.
          // ignore: avoid-substring
          reason: raw.substring(0, raw.length.clamp(0, 60)),
        );
      }
    });

    test(
      'a secret that is not 128 bits is not a scanned-strength secret',
      () {
        // `PairStrength.scanned` promises 128 random bits, from which a passive reader who captures
        // the whole handshake learns nothing, and the UI shows it as the strong path. A QR carrying
        // one byte would otherwise get the same label.
        for (final key in <String>['AA==', 'AAA=', 'AAAAAAAA']) {
          final invite = PairInvite.tryParse('pltest://pair?h=10.0.0.1&p=41235&k=$key', identity: kTestIdentity);
          expect(invite, isNull, reason: 'a $key secret must not pass as 128 bits');
        }
      },
    );
  });
}
