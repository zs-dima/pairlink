import 'dart:async';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import 'fixture.dart';

/// Heartbeats, idle deadlines, staleness-gated takeover, the queue ring and the monotonic default
/// clock: the machinery that answers a peer killed without a FIN, as a router power cut kills it.
/// With no deadline of its own the outlet holds its single-peer slot until the operating system's
/// TCP keepalive fires, roughly two hours later, answering every returning attach `alreadyPaired`.
///
/// In-memory wires, millisecond-scale injected durations; a fake clock drives staleness where
/// waiting would make CI slow or flaky.
void main() {
  ({_Wire outlet, _Wire panel}) wire() {
    final outlet = _Wire();
    final panel = _Wire();
    outlet.peer = panel;
    panel.peer = outlet;
    return (outlet: outlet, panel: panel);
  }

  Future<void> settle([int ms = 10]) => Future<void>.delayed(Duration(milliseconds: ms));

  List<T> collect<T>(Stream<T> stream) {
    final events = <T>[];
    final subscription = stream.listen(events.add);
    addTearDown(subscription.cancel);
    return events;
  }

  group('heartbeat', () {
    test('a quiet but healthy link never false-disconnects, and pongs flow', () async {
      final link = wire();
      final secret = PairSecret.generate();
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: secret,
        idleTimeout: const Duration(milliseconds: 120),
      );
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(milliseconds: 30),
        idleTimeout: const Duration(milliseconds: 120),
      );
      addTearDown(outlet.close);
      addTearDown(panel.close);
      final outletEvents = collect(outlet.events);
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);

      // Four idle windows with no application traffic: only pings and pongs keep it alive.
      await settle(500);

      expect(outlet.isPaired, isTrue, reason: 'the outlet declared a live pinging peer dead');
      expect(panel.isPaired, isTrue, reason: 'the panel declared a live ponging outlet dead');
      expect(outletEvents.whereType<OutletPeerLeft>(), isEmpty);
      expect(panelEvents.whereType<PanelDisconnected>(), isEmpty);
      expect(link.outlet.sent.whereType<Pong>(), isNotEmpty, reason: 'no pong ever went out');
    });

    test('outlet idle timeout frees the slot when the panel goes silent, and a fresh attach pairs', () async {
      final link = wire();
      final secret = PairSecret.generate();
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: secret,
        idleTimeout: const Duration(milliseconds: 80),
      );
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(milliseconds: 20),
        idleTimeout: const Duration(days: 1), // not under test here
      );
      addTearDown(outlet.close);
      addTearDown(panel.close);
      final outletEvents = collect(outlet.events);

      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);

      // The panel falls silent without a FIN: its pings and acks stop arriving.
      link.panel.dropOutgoing = {'ping', 'ack', 'bye'};
      await settle(300);

      expect(
        outletEvents.whereType<OutletPeerLeft>().where((e) => !e.graceful),
        isNotEmpty,
        reason: 'silence past the idle timeout must free the slot',
      );
      expect(outlet.isPaired, isFalse);

      // The slot is genuinely free: a fresh connection with the same secret pairs. wire() mints a
      // new transport pair, since the dead link cannot carry the retry.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      final panel2 = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(milliseconds: 20),
      );
      addTearDown(panel2.close);
      unawaited(outlet.attach(second.outlet));
      expect(await panel2.attach(second.panel), isTrue, reason: 'the freed slot refused an honest peer');
    });

    test('panel idle timeout notices a dead outlet: dropped pongs end in PanelDisconnected', () async {
      final link = wire();
      final secret = PairSecret.generate();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret, idleTimeout: const Duration(days: 1));
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(milliseconds: 20),
        idleTimeout: const Duration(milliseconds: 80),
      );
      addTearDown(outlet.close);
      addTearDown(panel.close);
      final panelEvents = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);

      link.outlet.dropOutgoing = {'pong'};
      await settle(300);

      expect(panelEvents.whereType<PanelDisconnected>(), isNotEmpty);
      expect(panel.isPaired, isFalse);
    });
  });

  group('takeover', () {
    test('a fully valid handshake evicts a QUIET peer; a live one is refused as before', () async {
      var now = 100000;
      final secret = PairSecret.generate();
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: secret,
        clock: () => now,
        idleTimeout: const Duration(days: 1), // takeover must win, not the idle timer
      );
      addTearDown(outlet.close);
      final outletEvents = collect(outlet.events);

      final first = wire();
      final panelA = PanelSession(identity: kTestIdentity, secret: secret, heartbeatInterval: const Duration(days: 1));
      addTearDown(panelA.close);
      unawaited(outlet.attach(first.outlet));
      expect(await panelA.attach(first.panel), isTrue);

      // A live peer: a second holder of the secret is refused, which is the displacement invariant.
      // The second connection gets its own transport pair from wire().
      // ignore: avoid-duplicate-initializers
      final liveAttempt = wire();
      final panelLive = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(days: 1),
      );
      addTearDown(panelLive.close);
      unawaited(outlet.attach(liveAttempt.outlet));
      expect(await panelLive.attach(liveAttempt.panel), isFalse, reason: 'a live peer must not be displaced');

      // The peer goes quiet: the fake clock jumps past kTakeoverAfter with no verified frame.
      now += kTakeoverAfter.inMilliseconds + 1;

      // The takeover arrives over its own fresh connection: wire() mints a new pair.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      final panelB = PanelSession(identity: kTestIdentity, secret: secret, heartbeatInterval: const Duration(days: 1));
      addTearDown(panelB.close);
      unawaited(outlet.attach(second.outlet));
      expect(await panelB.attach(second.panel), isTrue, reason: 'a quiet slot must yield to a proven peer');
      await settle();

      expect(outletEvents.whereType<OutletPeerLeft>().where((e) => !e.graceful), isNotEmpty);
      expect(outletEvents.whereType<OutletPaired>().length, equals(2));
      expect(outlet.isPaired, isTrue);
      expect(first.outlet.isOpen, isFalse, reason: "the evicted peer's transport must be closed");
    });

    test('a wrong-secret hello against a quiet slot spends budget and does not evict', () async {
      var now = 100000;
      final secret = PairSecret.code('7392');
      final outlet = OutletSession(
        identity: kTestIdentity,
        secret: secret,
        clock: () => now,
        idleTimeout: const Duration(days: 1),
      );
      addTearDown(outlet.close);

      final first = wire();
      final panelA = PanelSession(identity: kTestIdentity, secret: secret, heartbeatInterval: const Duration(days: 1));
      addTearDown(panelA.close);
      unawaited(outlet.attach(first.outlet));
      expect(await panelA.attach(first.panel), isTrue);

      now += kTakeoverAfter.inMilliseconds + 1;

      // The wrong guess arrives over its own fresh connection: wire() mints a new pair.
      // ignore: avoid-duplicate-initializers
      final second = wire();
      final wrong = PanelSession(
        identity: kTestIdentity,
        secret: PairSecret.code('0000'),
        heartbeatInterval: const Duration(days: 1),
      );
      addTearDown(wrong.close);
      unawaited(outlet.attach(second.outlet));
      expect(await wrong.attach(second.panel), isFalse);

      expect(outlet.failedAttempts, equals(1), reason: 'a wrong guess against a quiet slot still costs budget');
      expect(outlet.isPaired, isTrue, reason: 'eviction is reachable only behind a verified handshake');
    });
  });

  group('queue ring', () {
    test('caps at the newest 64 and the replay still lands', () async {
      final secret = PairSecret.generate();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      addTearDown(outlet.close);

      for (var i = 0; i < 100; i++) {
        outlet.report(i.isEven ? .lost : .restored, atMs: i + 1000);
      }

      expect(outlet.queuedCount, equals(kMaxQueuedEvents));
      expect(outlet.droppedCount, equals(100 - kMaxQueuedEvents));

      final link = wire();
      final panel = PanelSession(identity: kTestIdentity, secret: secret, heartbeatInterval: const Duration(days: 1));
      addTearDown(panel.close);
      final received = collect(panel.events);
      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);
      await settle(50);

      final powers = received.whereType<PanelPowerEvent>().toList();
      expect(powers, hasLength(kMaxQueuedEvents), reason: 'the ring replays exactly what it holds');
      expect(powers.last.seq, equals(100), reason: 'the NEWEST event is the one the ring must never drop');
      // ReplayGuard demands strictly increasing seq; the gap left by evicted events sits in front
      // of the replay and is therefore fine.
      expect(powers.first.seq, equals(100 - kMaxQueuedEvents + 1));
    });
  });

  group('default clock', () {
    test('a bare report() stamps uptime, not the wall', () async {
      final secret = PairSecret.generate();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret);
      addTearDown(outlet.close);

      outlet.report(.lost);

      final link = wire();
      final panel = PanelSession(identity: kTestIdentity, secret: secret, heartbeatInterval: const Duration(days: 1));
      addTearDown(panel.close);
      final received = collect(panel.events);
      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);
      await settle();

      final stamp = received.whereType<PanelPowerEvent>().single.atMs;
      // Uptime is minutes; the wall clock is ~1.7e12. `atMs` is the field the replay guard treats
      // as monotonic, so the default clock must not be the wall clock.
      expect(stamp, lessThan(1000 * 60 * 60 * 24), reason: 'the default clock must be process uptime');
    });
  });

  group('unsigned reject window', () {
    test('an unsigned mid-session reject is a stranger frame: ignored, link stays paired', () async {
      final link = wire();
      final secret = PairSecret.generate();
      final outlet = OutletSession(identity: kTestIdentity, secret: secret, idleTimeout: const Duration(days: 1));
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: secret,
        heartbeatInterval: const Duration(days: 1),
        idleTimeout: const Duration(days: 1),
      );
      addTearDown(outlet.close);
      addTearDown(panel.close);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isTrue);

      // One unauthenticated line, as anyone who can reach the TCP stream could write it. Acted on,
      // it would flap the UI into "connecting" on a link that is fine.
      link.outlet.deliverRaw('{"t":"reject","reason":"alreadyPaired"}');
      await settle();

      expect(events.whereType<PanelRefused>(), isEmpty, reason: 'a stranger frame reached the UI');
      expect(panel.isPaired, isTrue);
    });

    test('an unsigned wrongCode refusal still reaches the user while the handshake is open', () async {
      // The window cannot be narrower than "handshake unresolved": a panel with the wrong code has
      // already derived a wrong key when the refusal arrives, so the refusal is unsignable.
      final link = wire();
      final outlet = OutletSession(identity: kTestIdentity, secret: PairSecret.code('7392'));
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: PairSecret.code('0000'),
        heartbeatInterval: const Duration(days: 1),
      );
      addTearDown(outlet.close);
      addTearDown(panel.close);
      final events = collect(panel.events);

      unawaited(outlet.attach(link.outlet));
      expect(await panel.attach(link.panel), isFalse);
      await settle();

      expect(events.whereType<PanelRefused>().single.reason, equals(RejectReason.wrongCode));
    });
  });

  group('version mismatch', () {
    test('a v2 challenge surfaces as PanelRefused(versionMismatch), not a silent timeout', () async {
      final link = wire();
      final panel = PanelSession(
        identity: kTestIdentity,
        secret: PairSecret.generate(),
        heartbeatInterval: const Duration(days: 1),
      );
      addTearDown(panel.close);
      final events = collect(panel.events);

      final attachResult = panel.attach(link.panel);
      await settle();
      // A v2 outlet speaks first with a v2 challenge; this build's codec refuses it locally.
      link.outlet.deliverRaw('{"v":2,"t":"challenge","nonce":"bm9uY2U="}');
      await settle();

      expect(
        events.whereType<PanelRefused>().where((e) => e.reason == .versionMismatch),
        isNotEmpty,
        reason: 'the one silent mismatch direction must still say "update the app"',
      );
      expect(await attachResult, isFalse);
    });
  });
}

/// Minimal in-memory [PairTransport] pair; see `session_test.dart` for the full-featured one.
final class _Wire implements PairTransport {
  final StreamController<ReceivedFrame> _inbox = StreamController<ReceivedFrame>();

  bool _closed = false;

  /// Frame types this side silently fails to transmit: a lossy link without timing games.
  Set<String> dropOutgoing = const <String>{};

  /// Everything this side put on the wire.
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
    deliverRaw(FrameCodec.encode(frame, mac: mac));
  }

  /// Delivers one raw line as a socket would: decoded here, a codec failure becomes a stream error,
  /// the way `SocketTransport` reports it.
  void deliverRaw(String line) {
    if (peer._inbox.isClosed) return;
    try {
      peer._inbox.add(FrameCodec.decode(line));
    } on FrameError catch (error) {
      peer._inbox.addError(error);
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    if (!_inbox.isClosed) _inbox.close().ignore();
  }
}
