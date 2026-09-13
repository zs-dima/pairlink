import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import '../fixture.dart';
import 'hostile.dart';
import 'victim.dart';

/// The application messages ([Shared] and [Signal]), probed by a peer that is not the honest client.
///
/// They carry the application's controls rather than its observations, which makes them the most
/// attractive frames on the wire: an unsigned `shared` accepted here would let anyone on the Wi-Fi
/// flip a consumer's state. Every probe is written against the wire, with this suite's own HKDF.
void main() {
  const code = '7392';
  late OutletVictim victim;

  Future<void> stop() => victim.stop();

  Future<String> challengeOf(Hostile attacker) async {
    final challenge = await attacker.nextFrame();
    expect(challenge?['t'], equals('challenge'), reason: 'the outlet phone speaks first');
    return challenge!['nonce']! as String;
  }

  /// Pairs a hand-rolled peer and hands back its key, so a probe can sign or decline to sign.
  Future<List<int>> pair(Hostile attacker) async {
    final hostNonce = await challengeOf(attacker);
    const guestNonce = 'Z3Vlc3Q=';
    final key = attackerKey(codeSecret(code), hostNonce, guestNonce, brand: kTestIdentity.brand);
    final body = <String, Object?>{'v': kPairlinkVersion, 't': 'hello', 'nonce': guestNonce};
    attacker.frame(body, mac: signBody(key, body));
    final welcome = await attacker.nextFrame();
    expect(welcome?['t'], equals('welcome'));
    return key;
  }

  Map<String, Object?> sharedBody(Object value, int n) => <String, Object?>{
    't': 'shared',
    'key': 'relocating',
    'value': value,
    'n': n,
  };

  Map<String, Object?> signalBody(String name, int n) => <String, Object?>{'t': 'signal', 'name': name, 'n': n};

  /// Real sockets carry these frames, so a microtask pump proves nothing once more than a line or
  /// two is in flight.
  Future<void> waitFor(bool Function() done) async {
    final deadline = DateTime.now().add(const Duration(seconds: 3));
    while (!done() && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
  }

  /// Long enough that a frame which was going to arrive has. Every "nothing happened" assertion
  /// needs it, or it passes by being early rather than right.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 200));

  group('the attacker really can speak these frames', () {
    test('control: a signed shared from the paired peer lands', () async {
      // Without this control every refusal below could be a broken attacker rather than a defence.
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);

      final key = await pair(attacker);
      final body = sharedBody(true, 1);
      attacker.frame(body, mac: signBody(key, body));
      await settle();

      expect(
        victim.events.whereType<OutletPeerShared>().map((e) => (e.key, e.value)),
        equals(<(String, Object?)>[('relocating', true)]),
        reason: 'without this every result below is vacuous',
      );
    });

    test('control: a signed signal from the paired peer fires', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);

      final key = await pair(attacker);
      final body = signalBody('siren', 1);
      attacker.frame(body, mac: signBody(key, body));
      await settle();

      expect(victim.events.whereType<OutletPeerSignal>().map((e) => e.name), equals(<String>['siren']));
    });
  });

  group('unsigned application messages', () {
    test('an unsigned shared as the FIRST frame is refused and costs no budget', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);

      attacker.frame(sharedBody(true, 1));

      final answer = await attacker.nextFrame();
      expect(answer?['t'], equals('reject'));
      expect(answer?['reason'], equals('malformed'), reason: 'a frame out of order is not a guess at the code');
      expect(
        victim.session.failedAttempts,
        isZero,
        reason: 'spending budget on a malformed frame hands an uninvited peer a free lockout',
      );
      expect(victim.events.whereType<OutletPeerShared>(), isEmpty);
    });

    test('an unsigned signal as the FIRST frame is refused and costs no budget', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await challengeOf(attacker);

      attacker.frame(signalBody('siren', 1));

      final answer = await attacker.nextFrame();
      expect(answer?['t'], equals('reject'));
      expect(answer?['reason'], equals('malformed'));
      expect(victim.session.failedAttempts, isZero);
      expect(victim.events.whereType<OutletPeerSignal>(), isEmpty);
    });

    test('a flood of unsigned application messages emits nothing and spends nothing', () async {
      victim = await OutletVictim.start(PairSecret.code(code), limiter: AttemptLimiter(maxAttempts: 999));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);

      final key = await pair(attacker);
      for (var i = 1; i <= 50; i++) {
        attacker
          ..frame(sharedBody(i.isEven, i))
          ..frame(signalBody('siren', i));
      }
      await settle();

      expect(victim.events.whereType<OutletPeerShared>(), isEmpty, reason: 'none of them was signed');
      expect(victim.events.whereType<OutletPeerSignal>(), isEmpty);
      expect(victim.session.failedAttempts, isZero);
      expect(victim.session.isPaired, isTrue, reason: 'garbage on a paired link is dropped, not a teardown');

      // And the link still works afterwards: a drop, not a silent death.
      final body = sharedBody(true, 1);
      attacker.frame(body, mac: signBody(key, body));
      await waitFor(() => victim.events.any((e) => e is OutletPeerShared));
      expect(victim.events.whereType<OutletPeerShared>(), hasLength(1));
    });
  });

  group('signed by the wrong key', () {
    test("a shared signed with a stranger's key is dropped and the session survives", () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      await pair(attacker);

      // The WRONG code over the right nonces: perfect shape, wrong secret.
      final wrong = attackerKey(codeSecret('0000'), 'c3RyYW5nZXI=', 'Z3Vlc3Q=', brand: kTestIdentity.brand);
      final body = sharedBody(true, 1);
      attacker.frame(body, mac: signBody(wrong, body));
      await settle();

      expect(victim.events.whereType<OutletPeerShared>(), isEmpty);
      expect(victim.session.isPaired, isTrue, reason: 'a bad signature on a paired link is not an eviction');
    });
  });

  group('replay within one connection', () {
    test('a counter at or below the last accepted one is refused', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final key = await pair(attacker);

      for (final (value, n) in <(bool, int)>[(true, 5), (false, 4), (false, 5)]) {
        final body = sharedBody(value, n);
        attacker.frame(body, mac: signBody(key, body));
      }
      await settle();

      expect(
        victim.events.whereType<OutletPeerShared>().map((e) => e.value),
        equals(<Object?>[true]),
        reason: 'only the first counter is new; 4 is older and 5 is the same frame again',
      );
    });

    test('a replayed signal does not fire twice', () async {
      victim = await OutletVictim.start(PairSecret.code(code));
      addTearDown(stop);
      final attacker = await Hostile.connect(victim.port);
      addTearDown(attacker.close);
      final key = await pair(attacker);

      // The exact bytes again. A siren firing twice is the mild case; a command replayed an hour
      // later is the real one.
      final body = signalBody('siren', 1);
      final mac = signBody(key, body);
      attacker
        ..frame(body, mac: mac)
        ..frame(body, mac: mac);
      await settle();

      expect(victim.events.whereType<OutletPeerSignal>(), hasLength(1));
    });
  });
}
