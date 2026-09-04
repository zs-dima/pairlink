import 'dart:async';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import '../fixture.dart';
import 'hostile.dart';
import 'victim.dart';

/// The panel phone against a server that is not the outlet phone.
///
/// The panel phone connects to whatever it was pointed at. On the QR path that is an address the
/// user photographed; on the code path it is whatever answered an mDNS browse, which anyone on the
/// Wi-Fi can answer. A hostile server is the code path's ordinary case, not a thought experiment.
void main() {
  const code = '7392';

  /// Runs [script] against the first connection the panel phone makes, and returns what the panel
  /// did with it.
  Future<({PanelVictim victim, bool paired})> against(
    PairSecret secret,
    Future<void> Function(Hostile peer) script, {
    Duration settle = const Duration(milliseconds: 400),
    bool endWithReject = true,
  }) async {
    final server = await HostileServer.start();
    addTearDown(server.stop);
    final finished = Completer<void>();
    unawaited(
      server.sessions.first.then((socket) async {
        final peer = Hostile.wrap(socket);
        addTearDown(peer.close);
        await script(peer);
        // A refusal ends the handshake immediately. Without it every probe that (correctly) fails
        // to pair costs the full ten-second timeout, and the suite is minutes of waiting.
        if (endWithReject) peer.frame(<String, Object?>{'t': 'reject', 'reason': 'malformed'});
        if (!finished.isCompleted) finished.complete();
      }),
    );

    final connected = await PanelVictim.connect(server.port, secret);
    addTearDown(connected.victim.stop);
    await finished.future.timeout(const Duration(seconds: 20), onTimeout: () {});
    await Future<void>.delayed(settle);
    return connected;
  }

  group('a server holding no secret', () {
    test('cannot pair, whatever it puts in the mac', () async {
      final connected = await against(PairSecret.generate(), (peer) async {
        peer.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': fakeNonce()});
        await peer.nextFrame();
        for (final mac in <String?>[null, '', 'AAAA', 'A' * 44, 'A' * 43 + '=']) {
          peer.frame(<String, Object?>{'t': 'welcome', 'device': 'not the outlet phone'}, mac: mac);
        }
      });

      expect(connected.paired, isFalse);
      expect(connected.victim.session.isPaired, isFalse);
    });

    test('cannot inject a power event', () async {
      // The attack the scheme exists to stop. It does not look like an attack: it looks like the
      // application recording one wrong reading, quietly.
      final connected = await against(PairSecret.generate(), (peer) async {
        peer.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': fakeNonce(2)});
        await peer.nextFrame();
        final stranger = attackerKey(codeSecret('0000'), fakeNonce(2), 'Zw==', brand: kTestIdentity.brand);
        for (final mac in <String?>[null, '', 'AAAA', signBody(stranger, <String, Object?>{})]) {
          peer.frame(<String, Object?>{'t': 'power', 'state': 'lost', 'ts': 9999, 'seq': 1}, mac: mac);
        }
      });

      expect(connected.victim.delivered, isEmpty, reason: 'no forged event may reach the map');
    });

    test('cannot inject a power event before the challenge either', () async {
      final connected = await against(PairSecret.generate(), (peer) async {
        peer
          ..frame(<String, Object?>{'t': 'power', 'state': 'lost', 'ts': 1, 'seq': 1})
          ..frame(<String, Object?>{'t': 'welcome'})
          ..frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': fakeNonce(4)});
        await peer.nextFrame();
        peer.frame(<String, Object?>{'t': 'power', 'state': 'lost', 'ts': 2, 'seq': 2});
      });

      expect(connected.paired, isFalse);
      expect(connected.victim.delivered, isEmpty);
    });

    test('a silent server times out cleanly instead of hanging', () async {
      final started = DateTime.now();
      final connected = await against(
        PairSecret.generate(),
        (_) async {},
        settle: .zero,
        endWithReject: false,
      );
      final elapsed = DateTime.now().difference(started);

      expect(connected.paired, isFalse);
      expect(elapsed, lessThan(const Duration(seconds: 20)));
      expect(elapsed, greaterThan(const Duration(seconds: 5)), reason: 'it really waited, then gave up');
    });
  });

  group('a server holding the four digits (which mDNS advertises in the clear)', () {
    /// Pairs the panel phone with a hostile server that knows the code, then runs [after].
    Future<({PanelVictim victim, bool paired})> paired(Future<void> Function(Hostile peer, List<int> key) after) =>
        against(
          PairSecret.code(code),
          endWithReject: false,
          (peer) async {
            const hostNonce = 'aG9zdC1ub25jZS0xNg==';
            peer.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': hostNonce});
            final hello = (await peer.nextFrame())!;
            final key = attackerKey(codeSecret(code), hostNonce, hello['nonce']! as String, brand: kTestIdentity.brand);
            final welcome = <String, Object?>{'t': 'welcome', 'device': 'attacker'};
            peer.frame(welcome, mac: signBody(key, welcome));
            await Future<void>.delayed(const Duration(milliseconds: 150));
            await after(peer, key);
          },
        );

    test('pairs, and can inject a power event: the typed path as it is', () async {
      final connected = await paired((peer, key) async {
        const frame = <String, Object?>{'t': 'power', 'state': 'lost', 'ts': 5000, 'seq': 1};
        peer.frame(frame, mac: signBody(key, frame));
        await Future<void>.delayed(const Duration(milliseconds: 200));
      });

      expect(connected.paired, isTrue, reason: 'four digits are worth four digits');
      expect(connected.victim.delivered.single.state, equals(PowerState.lost));
    });

    test('a verbatim replay is still one event', () async {
      final connected = await paired((peer, key) async {
        const frame = <String, Object?>{'t': 'power', 'state': 'lost', 'ts': 5000, 'seq': 1};
        final line = signBody(key, frame);
        peer.frame(frame, mac: line);
        await Future<void>.delayed(const Duration(milliseconds: 150));
        for (var i = 0; i < 5; i++) {
          peer.frame(frame, mac: line);
        }
        await Future<void>.delayed(const Duration(milliseconds: 200));
      });

      expect(connected.victim.delivered, hasLength(1));
    });

    test('a stamp that goes backwards is dropped even with a fresh seq', () async {
      // A validly signed frame, from the peer actually paired with, carrying an event from minutes
      // ago.
      final connected = await paired((peer, key) async {
        const first = <String, Object?>{'t': 'power', 'state': 'lost', 'ts': 5000, 'seq': 1};
        peer.frame(first, mac: signBody(key, first));
        await Future<void>.delayed(const Duration(milliseconds: 150));

        const backwards = <String, Object?>{'t': 'power', 'state': 'restored', 'ts': 1000, 'seq': 99};
        const staleSeq = <String, Object?>{'t': 'power', 'state': 'restored', 'ts': 9000, 'seq': 1};
        peer
          ..frame(backwards, mac: signBody(key, backwards))
          ..frame(staleSeq, mac: signBody(key, staleSeq));
        await Future<void>.delayed(const Duration(milliseconds: 200));
      });

      expect(connected.victim.delivered.map((e) => e.seq), equals(<int>[1]));
    });

    test(
      'an unsigned challenge mid-session must not replace the session key',
      () async {
        // One unauthenticated frame. Answered with a fresh hello, it would replace the panel's key,
        // and every properly signed event from the phone it is paired with would then be dropped.
        final connected = await paired((peer, key) async {
          const first = <String, Object?>{'t': 'power', 'state': 'lost', 'ts': 5000, 'seq': 1};
          peer.frame(first, mac: signBody(key, first));
          await Future<void>.delayed(const Duration(milliseconds: 150));

          peer.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': 'aW5qZWN0ZWQtbm9uY2UtIQ=='});
          await Future<void>.delayed(const Duration(milliseconds: 200));

          const second = <String, Object?>{'t': 'power', 'state': 'restored', 'ts': 20000, 'seq': 2};
          peer.frame(second, mac: signBody(key, second));
          await Future<void>.delayed(const Duration(milliseconds: 200));
        });

        expect(
          connected.victim.delivered.map((e) => e.seq),
          equals(<int>[1, 2]),
          reason: 'an unsigned frame must not be able to silence the link',
        );
      },
    );
  });

  group('garbage from the server', () {
    test('never crashes the panel phone and never fabricates an event', () async {
      final connected = await against(PairSecret.generate(), (peer) async {
        peer.frame(<String, Object?>{'v': kPairlinkVersion, 't': 'challenge', 'nonce': fakeNonce(5)});
        await peer.nextFrame();
        for (final line in <String>[
          'not json at all',
          '[]',
          'null',
          'true',
          '{"t":null}',
          '{"t":"power","state":"lost","ts":"soon","seq":1}',
          '{"t":"power","state":"lost","ts":1,"seq":{"nested":true}}',
          '{"t":"power","state":"lost","ts":1,"seq":[1]}',
          '{"t":"welcome","device":[1,2,3]}',
          '{"t":"power","state":"lost","ts":99999999999999999999999,"seq":1}',
          '{"t":"power","state":"lost","ts":1e400,"seq":1}',
          '${'[' * 20000}${']' * 20000}',
          ' ',
          '',
        ]) {
          peer.line(line);
          await Future<void>.delayed(const Duration(milliseconds: 20));
        }
      });

      expect(connected.paired, isFalse);
      expect(connected.victim.delivered, isEmpty);
    });
  });
}
