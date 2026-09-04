import 'dart:convert';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import '../fixture.dart';
import 'hostile.dart';
import 'victim.dart';

/// What a stranger who only opens TCP connections can do.
///
/// The subject is the accept loop as a real service runs it: each accepted socket is handed to the
/// session and the future is not awaited. That detail matters, because several of the defects these
/// tests pin live in the gap between one `attach` and the next.
void main() {
  const code = '7392';
  late OutletVictim victim;

  Future<void> stop() => victim.stop();

  /// Pairs with the subject from a hand-rolled client. Returns whether it worked.
  Future<bool> pair(OutletVictim target, {String guest = 'aG9uZXN0'}) async {
    const within = Duration(seconds: 2);
    final honest = await Hostile.connect(target.port);
    addTearDown(honest.close);
    final challenge = await honest.nextFrame(within: within);
    if (challenge?['t'] != 'challenge') return false;
    final key = attackerKey(codeSecret(code), challenge!['nonce']! as String, guest, brand: kTestIdentity.brand);
    final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
    honest.frame(body, mac: signBody(key, body));
    // The frame after the challenge: nextFrame() consumes, so this is not the same value.
    // ignore: avoid-duplicate-initializers
    final answer = await honest.nextFrame(within: within);
    return answer?['t'] == 'welcome';
  }

  group('single-peer enforcement', () {
    test('a peer that is genuinely paired cannot be displaced', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      expect(await pair(victim), isTrue);

      for (var attempt = 0; attempt < 20; attempt++) {
        // Twenty separate strangers, each a fresh connection; one reused socket would test nothing.
        // ignore: move-variable-outside-iteration
        final stranger = await Hostile.connect(victim.port);
        addTearDown(stranger.close);
        // ignore: move-variable-outside-iteration
        final answer = await stranger.nextFrame(within: const Duration(seconds: 1));
        expect(answer?['t'], equals('reject'), reason: 'attempt $attempt');
        expect(answer?['reason'], equals('alreadyPaired'), reason: 'attempt $attempt');
      }
      expect(victim.session.isPaired, isTrue, reason: 'the phone in the outlet keeps its peer');
    });

    test(
      'a stranger who only opens a socket does not deny the next pairing',
      () async {
        // The stranger sends nothing at all. Its `attach` sits on the handshake timeout; when the
        // honest phone connects, the stranger's pending attach completes false, and a `_detach()`
        // that tore down whichever transport is current by then would take the honest one with it.
        victim = await OutletVictim.start(PairSecret.code(code));
        addTearDown(stop);
        final stranger = await Hostile.connect(victim.port);
        addTearDown(stranger.close);
        await Future<void>.delayed(const Duration(milliseconds: 100));

        expect(await pair(victim), isTrue, reason: 'one silent TCP connection must not deny pairing');
      },
    );

    test(
      'a stranger connecting mid-handshake does not break it',
      () async {
        victim = await OutletVictim.start(PairSecret.code(code));
        addTearDown(stop);

        final honest = await Hostile.connect(victim.port);
        addTearDown(honest.close);
        final challenge = (await honest.nextFrame())!;
        // A second live connection: Hostile.connect dials a fresh socket.
        // ignore: avoid-duplicate-initializers
        final stranger = await Hostile.connect(victim.port); // the entire attack
        addTearDown(stranger.close);
        await Future<void>.delayed(const Duration(milliseconds: 100));

        const guest = 'aG9uZXN0';
        final key = attackerKey(codeSecret(code), challenge['nonce']! as String, guest, brand: kTestIdentity.brand);
        final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
        honest.frame(body, mac: signBody(key, body));
        await Future<void>.delayed(const Duration(milliseconds: 300));

        expect(victim.session.isPaired, isTrue);
      },
    );
  });

  group('reconnect', () {
    test(
      'the paired phone can come back after its link drops',
      () async {
        // The link drops, as it does when the router itself loses power. On a real socket `isOpen`
        // never goes false when the peer closes, so a session can stay "paired" with a dead socket
        // and answer the returning phone `alreadyPaired` forever.
        victim = await OutletVictim.start(PairSecret.code(code));
        addTearDown(stop);

        // Inline rather than through `pair`, which keeps its connection until the test ends: the
        // scenario is the first socket dying, so this test owns it and closes it. Left open, the
        // test would instead assert that a live paired peer can be displaced, which the
        // single-peer test above forbids.
        final first = await Hostile.connect(victim.port);
        final challenge = await first.nextFrame();
        final hostNonce = challenge!['nonce']! as String;
        const guest = 'Zmlyc3Q=';
        final key = attackerKey(codeSecret(code), hostNonce, guest, brand: kTestIdentity.brand);
        final hello = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
        first.frame(hello, mac: signBody(key, hello));
        // The frame after the hello: nextFrame() consumed the challenge already.
        // ignore: avoid-duplicate-initializers
        final welcome = await first.nextFrame();
        expect(welcome?['t'], equals('welcome'));
        expect(victim.events.whereType<OutletPaired>().length, equals(1));

        // The panel phone's socket goes away, the way a killed process takes it: FIN, no `bye`.
        await first.close();
        await Future<void>.delayed(const Duration(milliseconds: 200));

        expect(await pair(victim, guest: 'c2Vjb25k'), isTrue, reason: 'the same phone must be able to come back');
      },
    );

    test('a graceful bye does release the session', () async {
      // The contrast: the same teardown, announced, recovers cleanly.
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);

      final honest = await Hostile.connect(victim.port);
      addTearDown(honest.close);
      // Each call reads the next frame off the wire, not a repeated lookup.
      // ignore: prefer-moving-to-variable
      final challenge = await honest.nextFrame();
      final hostNonce = challenge!['nonce']! as String;
      const guest = 'Zmlyc3Q=';
      final key = attackerKey(codeSecret(code), hostNonce, guest, brand: kTestIdentity.brand);
      final hello = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
      honest.frame(hello, mac: signBody(key, hello));
      // The frame after the hello: nextFrame() consumed the challenge already.
      // ignore: avoid-duplicate-initializers, prefer-moving-to-variable
      final welcome = await honest.nextFrame();
      expect(welcome?['t'], equals('welcome'));

      const bye = <String, Object?>{'t': 'bye'};
      honest.frame(bye, mac: signBody(key, bye));
      await Future<void>.delayed(const Duration(milliseconds: 300));

      expect(victim.session.isPaired, isFalse, reason: 'an announced departure frees the session');
    });
  });

  group('writing to a socket whose peer is gone', () {
    test(
      'a failed write closes the transport instead of escaping',
      () async {
        // A socket write can fail once the peer is gone, which mid-session is normal (the user
        // walked out of Wi-Fi range), so SocketTransport.send closes the transport rather than
        // propagating. IOSink.writeln does not throw synchronously; it fails on the sink's own
        // stream, so an unobserved SocketException escapes as an unhandled asynchronous error.
        victim = await OutletVictim.start(PairSecret.code(code));
        addTearDown(stop);

        final honest = await Hostile.connect(victim.port);
        // Each call reads the next frame off the wire, not a repeated lookup.
        // ignore: prefer-moving-to-variable
        final challenge = await honest.nextFrame();
        final hostNonce = challenge!['nonce']! as String;
        const guest = 'aG9uZXN0';
        final key = attackerKey(codeSecret(code), hostNonce, guest, brand: kTestIdentity.brand);
        final hello = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guest};
        honest.frame(hello, mac: signBody(key, hello));
        // The frame after the hello: nextFrame() consumed the challenge already.
        // ignore: avoid-duplicate-initializers, prefer-moving-to-variable
        final welcome = await honest.nextFrame();
        expect(welcome?['t'], equals('welcome'));

        // The panel phone's socket goes away without a bye: backgrounded, killed, or the link cut.
        await honest.close();
        await Future<void>.delayed(const Duration(milliseconds: 300));

        // Power keeps flipping while the link is down: the ordinary case, not an attack.
        victim.session.report(.lost);
        await Future<void>.delayed(const Duration(seconds: 1));
        victim.session.report(.restored);
        await Future<void>.delayed(const Duration(seconds: 1));
        victim.session.report(.lost);
        await Future<void>.delayed(const Duration(seconds: 2));
      },
    );
  });

  group('the four-digit budget', () {
    test('a new TCP connection does not buy a fresh five guesses', () async {
      // The property the typed path rests on. Twelve connections, each a full separate handshake
      // with a wrong code: five are answered wrongCode and the rest are turned away.
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);

      final answers = <String?>[];
      for (var attempt = 0; attempt < 12; attempt++) {
        // Twelve connections, each a full separate handshake: one hoisted connection would spend
        // the budget once instead of twelve times.
        // ignore: move-variable-outside-iteration
        final attacker = await Hostile.connect(victim.port);
        addTearDown(attacker.close);
        // ignore: move-variable-outside-iteration
        final challenge = await attacker.nextFrame(within: const Duration(seconds: 2));
        if (challenge?['t'] != 'challenge') {
          answers.add(challenge?['reason'] as String?);
          continue;
        }
        // ignore: move-variable-outside-iteration
        final key = attackerKey(codeSecret('0000'), challenge!['nonce']! as String, 'Zw==', brand: kTestIdentity.brand);
        final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': 'Zw=='};
        attacker.frame(body, mac: signBody(key, body));
        // The answer to this connection's wrong guess: a second read off this socket.
        // ignore: avoid-duplicate-initializers, move-variable-outside-iteration
        final reject = await attacker.nextFrame(within: const Duration(seconds: 2));
        answers.add(reject?['reason'] as String?);
      }

      expect(answers.where((r) => r == 'wrongCode'), hasLength(5), reason: 'exactly the budget, and not one more');
      expect(answers.skip(5).every((r) => r == 'tooManyAttempts'), isTrue);
      expect(victim.session.isAcceptingConnections, isFalse);
    });

    test('guesses pipelined into one packet are not cheaper than one per connection', () async {
      // Twenty signed hellos in a single write. If each were evaluated the budget would be gone in
      // one packet; if several were evaluated per connection the cap would be per-connection rather
      // than per-session.
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final challenge = await attacker.nextFrame();
      final hostNonce = challenge!['nonce']! as String;

      const body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': 'Zw=='};
      final packet = StringBuffer();
      for (var guess = 0; guess < 20; guess++) {
        final key = attackerKey(
          codeSecret(guess.toString().padLeft(4, '0')),
          hostNonce,
          'Zw==',
          brand: kTestIdentity.brand,
        );
        packet.writeln(jsonEncode(<String, Object?>{...body, 'mac': signBody(key, body)}));
      }
      attacker.write(utf8.encode(packet.toString()));
      await Future<void>.delayed(const Duration(milliseconds: 500));

      expect(victim.session.failedAttempts, lessThanOrEqualTo(1), reason: 'one connection, one guess');
      expect(victim.session.isPaired, isFalse);
    });

    test('a stranger who never speaks does not spend the budget either', () async {
      // The mirror of the test above: the limiter must not be a lever a silent peer can pull.
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      for (var i = 0; i < 5; i++) {
        // Five separate silent strangers: each connect() opens its own socket.
        // ignore: move-variable-outside-iteration
        final stranger = await Hostile.connect(victim.port);
        addTearDown(stranger.close);
      }
      await Future<void>.delayed(const Duration(milliseconds: 300));

      expect(victim.session.isAcceptingConnections, isTrue);
    });
  });

  group('resource exhaustion', () {
    test('400 connect-and-reset leave the phone able to pair', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);

      for (var i = 0; i < 400; i++) {
        // 400 separate connects: each iteration opens its own socket and resets it.
        // ignore: move-variable-outside-iteration
        final churn = await Hostile.connect(victim.port);
        churn.close().ignore();
      }
      await Future<void>.delayed(const Duration(milliseconds: 500));

      expect(await pair(victim), isTrue);
    });
  });
}
