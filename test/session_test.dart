import 'dart:async';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import 'fixture.dart';

/// The whole protocol, driven over two in-memory transports wired to each other.
///
/// No sockets here: ports and timing make CI flaky, and none of the rules under test are about TCP.
/// What is about TCP lives in `socket_transport_test.dart`.
///
/// Topology: the outlet phone stays in the socket, listens, and displays the QR code; the panel
/// phone connects. Power events flow from outlet to panel whichever side opened the connection.
void main() {
  /// The QR path: 128 bits the panel phone scanned off the outlet phone's screen.
  PairSecret scanned() => .generate();

  /// A pair of transports that deliver to each other, with a controllable link.
  ({_Wire outlet, _Wire panel}) wire() {
    final outlet = _Wire('outlet');
    final panel = _Wire('panel');
    outlet.peer = panel;
    panel.peer = outlet;
    return (outlet: outlet, panel: panel);
  }

  /// Lets queued microtasks and the in-memory hops settle.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 10));

  /// Collects everything a session emits, cancelling when the test ends.
  List<T> collect<T>(Stream<T> stream) {
    final events = <T>[];
    final subscription = stream.listen(events.add);
    addTearDown(subscription.cancel);
    return events;
  }

  group('handshake', () {
    test('a shared secret pairs both sides', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret, device: 'Redmi Note 12');
      final panel = PanelSession(identity: kTestIdentity, secret: secret, device: 'Pixel 9a');
      final outletEvents = collect(outlet.events);
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      final paired = await panel.attach(link.panel);
      await settle();

      expect(paired, isTrue);
      expect(outlet.isPaired, isTrue);
      expect(panelEvents.whereType<PanelPaired>().single.device, equals('Redmi Note 12'));
      expect(outletEvents.whereType<OutletPaired>().single.device, equals('Pixel 9a'));
    });

    test('the outlet phone speaks first, and the secret never travels', () async {
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: PairSecret.code('7392'));
      final panel = PanelSession(identity: kTestIdentity, secret: PairSecret.code('7392'));

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await settle();

      expect(link.outlet.sent.first, isA<Challenge>(), reason: 'the challenge is what makes the key joint');

      final onWire = <String>[
        ...link.outlet.sent.map(FrameCodec.encode),
        ...link.panel.sent.map(FrameCodec.encode),
      ].join();
      expect(
        onWire.contains('7392'),
        isFalse,
        reason: 'v1 put the code in every hello, so sniffing the LAN handed it over',
      );
    });

    test('a wrong code is refused, and the panel phone is told why', () async {
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: PairSecret.code('7392'));
      final panel = PanelSession(identity: kTestIdentity, secret: PairSecret.code('0000'));
      final refusals = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      final paired = await panel.attach(link.panel);
      await settle();

      expect(paired, isFalse);
      expect(outlet.isPaired, isFalse);
      expect(refusals.whereType<PanelRefused>().single.reason, equals(RejectReason.wrongCode));
    });

    test('a stranger choosing their own nonce cannot pair', () async {
      // If the connecting side chose the only nonce, anyone with the secret material could derive
      // the session key alone. The outlet phone's nonce is folded into the key, and this peer holds
      // no secret at all.
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: scanned());
      final events = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await settle();

      const attackerNonce = 'YXR0YWNrZXItY2hvc2Vu';
      final attackerKey = PairSecret.generate().deriveKey(
        brand: kTestIdentity.brand,
        hostNonce: 'YW55',
        guestNonce: attackerNonce,
      );
      const forged = Hello(nonce: attackerNonce, device: 'attacker');
      link.panel.send(forged, mac: attackerKey.sign(forged.toBody()));
      await settle();

      expect(outlet.isPaired, isFalse, reason: 'v1 answered true here');
      expect(events.whereType<OutletRejectedPeer>().last.reason, equals(RejectReason.wrongCode));
    });

    test('an unsigned hello is refused', () async {
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: PairSecret.code('7392'));
      final refusals = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await settle();
      link.panel.send(const Hello(nonce: 'bm9uY2U='));
      await settle();

      expect(outlet.isPaired, isFalse);
      expect(refusals.whereType<OutletRejectedPeer>().last.reason, equals(RejectReason.wrongCode));
    });

    test('a peer that connects and says something else is refused', () async {
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: PairSecret.code('7392'));
      final refusals = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await settle();
      link.panel.send(const Power(state: .lost, atMs: 1, seq: 1));
      await settle();

      expect(outlet.isPaired, isFalse);
      expect(refusals.whereType<OutletRejectedPeer>().last.detail, contains('expected hello'));
    });

    test('a hello captured from an earlier connection cannot be replayed onto a new one', () async {
      // The outlet phone's nonce is fresh per connection, so a recording of a legitimate handshake
      // is worthless the moment the socket is remade.
      final secret = scanned();
      final first = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      collect(outlet.events);

      unawaited(outlet.attach(first.outlet));
      await panel.attach(first.panel);
      await settle();
      final capturedHello = first.panel.sent.whereType<Hello>().single;
      await first.outlet.close();

      // The replay lands on a new connection: wire() mints a fresh transport pair.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      unawaited(outlet.attach(second.outlet));
      await settle();
      second.panel.replayFrom(first.panel, capturedHello);
      await settle();

      expect(outlet.isPaired, isFalse);
    });
  });

  group('power delivery', () {
    test('an event reaches the panel phone and is acknowledged', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final outletEvents = collect(outlet.events);
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      outlet.report(.lost);
      await settle();

      expect(panelEvents.whereType<PanelPowerEvent>().single.state, equals(PowerState.lost));
      expect(outletEvents.whereType<OutletDelivered>().last.seq, equals(1));
      expect(outlet.queuedCount, isZero, reason: 'an acknowledged event is off the queue');
    });

    test('both stamps survive the trip', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      outlet.report(.lost, atMs: 900000, wallMs: 1700000000000);
      await settle();

      final event = events.whereType<PanelPowerEvent>().single;
      expect(event.atMs, equals(900000), reason: 'monotonic, for ordering');
      expect(event.wallMs, equals(1700000000000), reason: 'wall clock, for display only');
    });

    test('a forged power frame is dropped', () async {
      // A forged event does not look like an attack: it looks like the application recording one
      // wrong reading, quietly.
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await settle();

      const forged = Power(state: .lost, atMs: 9999999, seq: 500);
      final strangerKey = PairSecret.generate().deriveKey(
        brand: kTestIdentity.brand,
        hostNonce: 'YQ==',
        guestNonce: 'Yg==',
      );
      link.outlet.send(forged, mac: strangerKey.sign(forged.toBody()));
      await settle();

      expect(events.whereType<PanelPowerEvent>(), isEmpty, reason: 'no forged event may reach the map');
    });

    test('an unsigned power frame is dropped', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      link.outlet.send(const Power(state: .lost, atMs: 5, seq: 7));
      await settle();

      expect(events.whereType<PanelPowerEvent>(), isEmpty);
    });

    test('a captured frame replayed verbatim is dropped', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      outlet.report(.lost);
      await settle();
      final captured = link.outlet.sent.whereType<Power>().single;

      // Byte for byte, signature and all: the strongest form of this attack.
      link.outlet.replay(captured);
      await settle();

      expect(events.whereType<PanelPowerEvent>(), hasLength(1), reason: 'a replay is still one event');
    });

    test('mid-session garbage does not end the session', () async {
      // One corrupt line is far more likely to be a truncated write than an attack, and dropping
      // the pairing over it would cost the user their session.
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      link.panel.sendRaw(const FrameError(.malformed, 'truncated'));
      await settle();

      expect(outlet.isPaired, isTrue);

      outlet.report(.lost);
      await settle();
      // Re-checked after a report(): the session must still work once garbage has arrived.
      // ignore: avoid-duplicate-test-assertions
      expect(outlet.isPaired, isTrue);
    });
  });

  group('a stranger on the same Wi-Fi', () {
    test('a second peer cannot displace the phone that is already paired', () async {
      // If the newest connection won, anyone who read the code off the screen could take over
      // midway and the user would see nothing.
      final secret = PairSecret.code('7392');
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await settle();
      expect(outlet.isPaired, isTrue);

      // The intruder dials in on its own fresh connection: wire() mints a new pair.
      // ignore: avoid-duplicate-initializers
      final intruderLink = wire();
      final intruder = PanelSession(identity: kTestIdentity, secret: secret);
      final refused = await outlet.attach(intruderLink.outlet);
      final joined = await intruder.attach(intruderLink.panel);

      expect(refused, isFalse);
      expect(joined, isFalse);
      expect(outlet.isPaired, isTrue, reason: 'the original peer keeps the session');
      expect(events.whereType<OutletRejectedPeer>().last.reason, equals(RejectReason.alreadyPaired));
    });

    test('guessing is capped well short of ten thousand tries', () async {
      // Four digits is only a secret while guessing is expensive.
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: PairSecret.code('7392'),
        limiter: AttemptLimiter(maxAttempts: 3),
      );
      final events = collect(outlet.events);

      final wrongKey = PairSecret.code('0000')
          .deriveKey(brand: kTestIdentity.brand, hostNonce: 'eA==', guestNonce: 'd3Jvbmc=');
      for (var attempt = 0; attempt < 3; attempt++) {
        // `wire()` mints a fresh transport; each guess must arrive over its own connection.
        // ignore: move-variable-outside-iteration
        final link = wire();
        unawaited(outlet.attach(link.outlet));
        await settle();
        const wrong = Hello(nonce: 'd3Jvbmc=');
        link.panel.send(wrong, mac: wrongKey.sign(wrong.toBody()));
        await settle();
      }

      expect(outlet.isAcceptingConnections, isFalse);
      expect(outlet.failedAttempts, greaterThanOrEqualTo(3));

      // The door is shut even for a peer with the right secret: the user has to regenerate, which
      // is also how they learn somebody was trying.
      final honest = wire();
      expect(await outlet.attach(honest.outlet), isFalse);
      expect(events.whereType<OutletRejectedPeer>().last.reason, equals(RejectReason.tooManyAttempts));
    });

    test('a connection that dies does not spend the budget; only a wrong guess does', () async {
      // Which teardown a dying socket produces is the operating system's choice: a reset arrives as
      // an error on the frame stream, a clean hang-up as `done`. Counting a reset as a failed
      // attempt would let six connect-and-resets, with no guessing and no secret, lock the user out
      // of pairing with their own phone until they fetched a new code. Linux resets where Windows
      // is silent, so the property is asserted rather than the platform.
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: PairSecret.code('7392'),
        limiter: AttemptLimiter(maxAttempts: 3),
      );

      for (var attempt = 0; attempt < 6; attempt++) {
        // Six connect-and-reset cycles need six live links: a broken one cannot break again.
        // ignore: move-variable-outside-iteration
        final link = wire();
        unawaited(outlet.attach(link.outlet));
        await settle();
        link.panel.breakLink();
        await settle();
      }

      expect(outlet.failedAttempts, isZero, reason: 'nobody guessed anything');
      expect(outlet.isAcceptingConnections, isTrue, reason: 'and the user can still pair');
    });

    test('an honest fumble does not spend the budget forever', () async {
      final secret = PairSecret.code('7392');
      final outlet = OutletSession(identity: kTestIdentity, secret: secret, limiter: AttemptLimiter(maxAttempts: 3));

      final wrongLink = wire();
      unawaited(outlet.attach(wrongLink.outlet));
      await settle();
      const wrong = Hello(nonce: 'd3Jvbmc=');
      final wrongKey = PairSecret.code('1111')
          .deriveKey(brand: kTestIdentity.brand, hostNonce: 'eA==', guestNonce: 'd3Jvbmc=');
      wrongLink.panel.send(wrong, mac: wrongKey.sign(wrong.toBody()));
      await settle();
      expect(outlet.failedAttempts, equals(1));

      // The honest retry arrives over its own fresh connection: wire() mints a new pair.
      // ignore: avoid-duplicate-initializers
      final goodLink = wire();
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      unawaited(outlet.attach(goodLink.outlet));
      await panel.attach(goodLink.panel);
      await settle();

      expect(outlet.isPaired, isTrue);
      expect(outlet.failedAttempts, isZero, reason: 'a success clears the count');
    });
  });

  group('how the pairing was made', () {
    test('a scanned session says so, and a typed one says so too', () async {
      for (final (secret, expected) in <(PairSecret, PairStrength)>[
        (PairSecret.generate(), PairStrength.scanned),
        (PairSecret.code('7392'), PairStrength.typed),
      ]) {
        // Each secret pairs over its own fresh transport: a used link cannot attach twice.
        // ignore: move-variable-outside-iteration
        final link = wire();
        final outlet = OutletSession(identity: kTestIdentity, secret: secret);
        final panel = PanelSession(identity: kTestIdentity, secret: secret);
        final outletEvents = collect(outlet.events);
        final panelEvents = collect(panel.events);

        unawaited(outlet.attach(link.outlet));
        await panel.attach(link.panel);
        await settle();

        // Carried all the way to the UI: the two paths differ by 124 bits and the screen must not
        // pretend they are the same.
        expect(outletEvents.whereType<OutletPaired>().single.strength, equals(expected));
        expect(panelEvents.whereType<PanelPaired>().single.strength, equals(expected));
      }
    });
  });

  group('reconnect', () {
    test('events observed while the link is down are replayed exactly once', () async {
      // Why the outlet phone queues: power keeps flipping during a Wi-Fi drop, so events keep
      // happening with nowhere to go.
      final secret = scanned();
      final first = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(first.outlet));
      await panel.attach(first.panel);
      outlet.report(.lost);
      await settle();
      expect(events.whereType<PanelPowerEvent>(), hasLength(1));

      // The link drops, as it does when the router itself loses power.
      await first.outlet.close();
      await settle();

      outlet
        ..report(.restored)
        ..report(.lost);
      expect(outlet.queuedCount, equals(2), reason: 'nothing may be lost while the link is down');

      // The reconnect happens over a new connection: wire() mints a fresh transport pair.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      unawaited(outlet.attach(second.outlet));
      await panel.attach(second.panel);
      await settle();

      expect(events.whereType<PanelPowerEvent>().map((e) => e.seq), equals(<int>[1, 2, 3]));
      expect(outlet.queuedCount, isZero);
    });

    test('a reconnect does not re-deliver what already arrived', () async {
      final secret = scanned();
      final first = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(first.outlet));
      await panel.attach(first.panel);
      outlet.report(.lost);
      await settle();

      // The ack is swallowed, so the outlet phone still believes seq 1 is outstanding.
      first.panel.dropOutgoing = <String>{'ack'};
      outlet.report(.restored);
      await settle();
      expect(outlet.queuedCount, greaterThan(0));

      await first.outlet.close();
      // The reconnect happens over a new connection: wire() mints a fresh transport pair.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      unawaited(outlet.attach(second.outlet));
      await panel.attach(second.panel);
      await settle();

      expect(
        events.whereType<PanelPowerEvent>().map((e) => e.seq),
        equals(<int>[1, 2]),
        reason: 'the panel phone de-duplicates, so an over-eager replay costs a frame and nothing else',
      );
    });

    test('a dropped link is reported on both sides so the screens can show a banner', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final outletEvents = collect(outlet.events);
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await link.panel.close();
      await settle();

      expect(outletEvents.whereType<OutletPeerLeft>().single.graceful, isFalse);
      expect(panelEvents.whereType<PanelDisconnected>(), isNotEmpty);
    });

    test('and reported ONCE — the idle timer does not report the same drop again', () async {
      // `onDone` used to emit without detaching, so the idle timer stayed armed and fired again a
      // few seconds later. A consumer that answers a drop with a BOUNDED retry loop got the second
      // copy after it had finished with the first, and started over with a fresh budget: the
      // "stopped trying to reconnect, then connected on its own" shape BreakerSonar saw on two
      // phones, 2026-09-05.
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret, idleTimeout: const Duration(days: 1));
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        idleTimeout: const Duration(milliseconds: 60),
      );
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await link.panel.close();
      // Well past the idle timeout, which is where the second report used to come from.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      await settle();

      expect(panelEvents.whereType<PanelDisconnected>(), hasLength(1), reason: 'one socket, one report');
      expect(panel.isPaired, isFalse, reason: 'and it detached with the report');
    });

    test('a graceful bye is distinguishable from a drop', () async {
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await panel.close();
      await settle();

      expect(events.whereType<OutletPeerLeft>().first.graceful, isTrue);
    });

    test('the panel phone tells an outlet bye from a drop too', () async {
      // The mirror of the test above. Collapsing `bye` into a plain disconnect on the panel side
      // makes the reconnect owner spend its whole budget against a peer that has said goodbye.
      final link = wire();
      final secret = scanned();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      final panel = PanelSession(identity: kTestIdentity, secret: secret);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      await panel.attach(link.panel);
      await outlet.close();
      await settle();

      expect(events.whereType<PanelDisconnected>().first.graceful, isTrue);
    });
  });
}

/// An in-memory [PairTransport] wired to a peer, with a link that can be cut or made lossy.
final class _Wire implements PairTransport {
  _Wire(this.name);

  /// Single-subscription, not broadcast: a broadcast controller drops anything sent before a
  /// listener attaches, while a socket queues bytes written before the far side reads. Broadcast
  /// would make this double more forgiving than the transport it stands in for.
  final StreamController<ReceivedFrame> _inbox = StreamController<ReceivedFrame>();

  final List<String> _sentLines = <String>[];

  bool _closed = false;

  final String name;

  /// Frame types this side silently fails to transmit: a lossy link, without timing games.
  Set<String> dropOutgoing = const <String>{};

  /// Everything this side put on the wire, for tests that need to replay a real captured frame.
  final List<PairFrame> sent = <PairFrame>[];
  late _Wire peer;

  @override
  Stream<ReceivedFrame> get frames => _inbox.stream;

  @override
  bool get isOpen => !_closed;

  @override
  void send(PairFrame frame, {String? mac}) {
    if (_closed || peer._closed) return;
    if (dropOutgoing.contains(frame.type)) return;

    sent.add(frame);
    final line = FrameCodec.encode(frame, mac: mac);
    _sentLines.add(line);
    // Encode and decode for real, so a field this codec cannot carry fails here rather than on a
    // phone.
    peer._deliver(line);
  }

  /// Re-sends a frame exactly as it went out the first time, signature included.
  void replay(PairFrame frame) {
    final index = sent.indexOf(frame);
    if (index >= 0) peer._deliver(_sentLines[index]);
  }

  /// Replays a frame captured on another wire, byte for byte: a recorded handshake arriving on a
  /// fresh connection.
  void replayFrom(_Wire source, PairFrame frame) {
    final index = source.sent.indexOf(frame);
    if (index >= 0) peer._deliver(source._sentLines[index]);
  }

  /// Kills the link the way a reset does: an error on the peer's stream rather than a clean end.
  ///
  /// Which of the two a dying socket produces is the operating system's choice, and the session
  /// must treat them the same.
  void breakLink() {
    if (!peer._inbox.isClosed) peer._inbox.addError(Exception('connection reset by peer'));
    _closed = true;
  }

  /// Puts a decode failure on the peer's stream, as a truncated line would.
  void sendRaw(FrameError error) {
    if (!peer._inbox.isClosed) peer._inbox.addError(error);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    // Not awaited: `close()` completes only once the done event has been delivered, so on a
    // controller nobody listened to it never completes. This matches SocketTransport; a double
    // more forgiving than the real thing hides the bugs it should find.
    if (!_inbox.isClosed) _inbox.close().ignore();
    if (!peer._inbox.isClosed) peer._inbox.close().ignore();
  }

  void _deliver(String line) {
    if (_inbox.isClosed) return;
    try {
      _inbox.add(FrameCodec.decode(line));
    } on FrameError catch (error) {
      _inbox.addError(error);
    }
  }
}
