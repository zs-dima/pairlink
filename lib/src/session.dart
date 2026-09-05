import 'dart:async';

import 'package:meta/meta.dart';
import 'package:pairlink/src/frames.dart';
import 'package:pairlink/src/identity.dart';
import 'package:pairlink/src/session_key.dart';
import 'package:pairlink/src/transport.dart';

/// How long a handshake may take before a session gives up on a peer.
///
/// Generous for a LAN, and finite: a peer that opens the socket and then says nothing would
/// otherwise hold the outlet phone waiting indefinitely.
const Duration kHandshakeTimeout = Duration(seconds: 10);

/// How many unproven connections the outlet phone will hold at once.
///
/// A bound on memory, not a security rule: possession is still proved per connection. Eight is
/// more than a home has phones and less than a flood needs.
const int kMaxPendingConnections = 8;

/// How often the panel phone pings once paired.
///
/// The panel drives the heartbeat because it already owns reconnection. Five seconds bounds
/// detection, not delivery, since power events are pushed; two ~40-byte frames per interval cost
/// little, and a shorter interval would buy only detection latency at the price of radio wakeups.
const Duration kHeartbeatInterval = Duration(seconds: 5);

/// How long either side tolerates silence on a paired connection before declaring the peer dead.
///
/// Three missed pings: one may be lost, one may be late behind a GC pause, three in a row is a
/// verdict. Without it, a peer killed without a FIN (a router losing power, for example) holds the
/// outlet's single peer slot until the OS TCP keepalive fires roughly two hours later, answering
/// the returning panel `alreadyPaired` throughout. Any MAC-verified frame counts as life.
const Duration kIdleTimeout = Duration(seconds: 15);

/// How quiet the paired connection must have been before a fully valid handshake may evict it.
///
/// Two missed pings: strictly more than one interval plus jitter, so a live peer can never look
/// this quiet, and strictly less than [kIdleTimeout], or the idle timer always wins first. Both
/// hold the same secret, so cryptography cannot separate the panel returning from a peer that read
/// the code off the screen; silence can, so eviction is gated on staleness.
const Duration kTakeoverAfter = Duration(seconds: 10);

/// Cap on the outlet's undelivered-event queue: a ring of the newest 64, drop-oldest.
///
/// The newest state is what matters, and drop-oldest keeps it by construction. 64 covers the full
/// reconnect budget in an ~8 KB replay burst; unbounded, a session that bound but never paired
/// grows one frame per transition indefinitely. Lost/restored pairs are not coalesced, which would
/// falsify the transition count in logs for no memory benefit at this cap.
const int kMaxQueuedEvents = 64;

/// Milliseconds. Injectable so tests do not have to wait for real time to pass.
typedef Clock = int Function();

int _systemClock() => DateTime.now().millisecondsSinceEpoch;

/// The default monotonic clock: process uptime, not the wall clock.
///
/// Stamps are only compared within one session, so an uptime scale is enough; a wall-clock
/// default would re-introduce the clock-step problem the monotonic stamps prevent.
final Stopwatch _uptime = Stopwatch()..start();
int _monotonicClock() => _uptime.elapsedMilliseconds;

// ---------------------------------------------------------------------------------------------
// The outlet phone: the stationary one. It listens, and it sends power events.
// ---------------------------------------------------------------------------------------------

/// {@template outlet_event}
/// Something the outlet phone's session wants the app to know.
/// {@endtemplate}
@immutable
sealed class OutletEvent {
  /// {@macro outlet_event}
  const OutletEvent();
}

/// A panel phone completed the handshake.
final class OutletPaired extends OutletEvent {
  /// {@macro outlet_event}
  const OutletPaired({required this.strength, this.device});

  /// The panel phone's model name, when it sent one.
  final String? device;

  /// How the secret was shared, so the UI can distinguish a typed pairing from a scanned one.
  final PairStrength strength;
}

/// A connection attempt was refused, and why. Surfaced so an application can log probes.
final class OutletRejectedPeer extends OutletEvent {
  /// {@macro outlet_event}
  const OutletRejectedPeer(this.reason, this.detail);

  /// Machine-readable cause.
  final RejectReason reason;

  /// What was wrong, for diagnostics. Not intended for display.
  final String detail;
}

/// The panel phone went away. [graceful] separates "End session" from a Wi-Fi drop.
final class OutletPeerLeft extends OutletEvent {
  /// {@macro outlet_event}
  const OutletPeerLeft({required this.graceful, required this.queued});

  /// Whether the peer said `bye` first.
  final bool graceful;

  /// How many events are waiting to be delivered when the link comes back.
  final int queued;
}

/// Everything up to [seq] is safely on the panel phone.
final class OutletDelivered extends OutletEvent {
  /// {@macro outlet_event}
  const OutletDelivered(this.seq);

  /// Highest acknowledged sequence.
  final int seq;
}

/// The outlet phone's half of a pairing session: the listening side.
///
/// It listens because it is the phone that stays put, and a client that reconnects to a fixed
/// address is far simpler than a server that follows one around.
///
/// The session outlives the connection: while the link is down the application keeps observing
/// events, so they are queued until acknowledged and replayed on the next [attach]. The panel
/// phone's replay guard makes that idempotent, so this side never has to know what arrived.
final class OutletSession {
  /// Creates an [OutletSession].
  OutletSession({
    required this.identity,
    required this.secret,
    this.device,
    Clock? clock,
    Clock? wallClock,
    AttemptLimiter? limiter,
    this.idleTimeout = kIdleTimeout,
    this.takeoverAfter = kTakeoverAfter,
  }) : _clock = clock ?? _monotonicClock,
       _wallClock = wallClock ?? _systemClock,
       _limiter = limiter ?? AttemptLimiter();

  final Clock _clock;

  final Clock _wallClock;

  final AttemptLimiter _limiter;

  final StreamController<OutletEvent> _controller = StreamController<OutletEvent>.broadcast();

  final List<Power> _queue = <Power>[];

  /// Connections that have been challenged but have proved nothing yet.
  ///
  /// A list, not a single slot: an unproven peer has no standing to exclude anyone, and with one
  /// slot a peer that merely opened a socket and stayed silent displaces the honest handshake.
  /// They race, the first to prove possession wins, and the rest are told `alreadyPaired`.
  // Every element is settled and closed in [close]; the rule only recognizes a direct field call.
  // ignore: dispose-class-fields
  final List<_Connection> _pending = <_Connection>[];

  /// The one connection that has proved it holds the secret.
  _Connection? _paired;

  /// Arms while a peer is paired; every MAC-verified inbound frame rewinds it.
  Timer? _idleTimer;
  int _seq = 0;

  /// See [kIdleTimeout]; injectable so a test can drive staleness without waiting.
  final Duration idleTimeout;

  /// See [kTakeoverAfter].
  final Duration takeoverAfter;

  /// The application's identity on the wire; its `brand` is bound into every session key.
  final PairIdentity identity;

  /// The pairing secret: 128 bits behind the QR code this phone displays, or the four digits the
  /// user typed here after reading them off the panel phone.
  final PairSecret secret;

  /// This phone's model, sent in `welcome`.
  final String? device;

  /// Events dropped off the front of the ring since the session began, for diagnostics.
  int droppedCount = 0;

  /// Everything the app needs to react to.
  Stream<OutletEvent> get events => _controller.stream;

  /// Whether a peer is currently connected and authenticated.
  bool get isPaired => switch (_paired) {
    _Connection(:final key, :final transport) => key != null && transport.isOpen,
    null => false,
  };

  /// Whether this session is still willing to accept connections.
  ///
  /// False once the attempt limit is spent: the caller stops listening and asks the user for a new
  /// code, rather than handing an attacker the rest of the code space.
  bool get isAcceptingConnections => _limiter.isOpen;

  /// Failed handshakes so far, so an application can tell the user that somebody is trying.
  int get failedAttempts => _limiter.failures;

  /// Events observed but not yet acknowledged by the panel phone.
  int get queuedCount => _queue.length;

  /// Whether the paired connection has been silent long enough that a fully valid handshake may
  /// replace it. False when nothing is paired.
  bool get _pairedIsQuiet => switch (_paired) {
    final _Connection paired => _clock() - paired.lastVerifiedAtMs >= takeoverAfter.inMilliseconds,
    null => false,
  };

  /// Takes over an accepted connection, runs the handshake on it, and replays the queue.
  ///
  /// Returns true when the peer is paired. A false return has already told the peer why and closed
  /// the transport, so the caller goes back to listening. Safe to call concurrently: every
  /// connection carries its own nonce, its own key and its own deadline.
  Future<bool> attach(PairTransport transport) async {
    // Fail closed first: a spent attempt budget refuses everyone, takeover included.
    if (!_limiter.isOpen) {
      transport.send(const Reject(.tooManyAttempts));
      _emit(const OutletRejectedPeer(.tooManyAttempts, 'attempt limit spent; the user must regenerate'));
      await transport.close();
      return false;
    }
    // A session paired to a live peer refuses a second one outright. A quiet peer does not block
    // the door: the candidate falls through to the challenge, and eviction happens only if its
    // handshake fully verifies (see _acceptHello). Silence is what separates a panel returning
    // after a network drop from a peer that read the code off the screen; the MAC cannot.
    if (isPaired && !_pairedIsQuiet) {
      transport.send(const Reject(.alreadyPaired));
      _emit(const OutletRejectedPeer(.alreadyPaired, 'a second peer tried to join a paired session'));
      await transport.close();
      return false;
    }
    // A transport whose stream has already finished never delivers `onDone` to a listener that
    // arrives afterwards, so waiting on it would burn the full handshake timeout for nothing.
    if (!transport.isOpen) {
      await transport.close();
      return false;
    }
    if (_pending.length >= kMaxPendingConnections) {
      // Answered with silence rather than a frame: a flood gets no feedback. Each pending
      // connection dies at its own deadline, so the list drains on its own.
      _emit(const OutletRejectedPeer(.malformed, 'too many half-open connections; dropped'));
      await transport.close();
      return false;
    }

    final connection = _Connection(transport, PairSecret.newNonce());
    _pending.add(connection);
    connection.subscription = transport.frames.listen(
      (received) => _onFrame(received, connection),
      onError: (Object error) => _onFrameError(error, connection),
      onDone: () => _onDone(connection),
    );

    // This side speaks first. Its nonce is what the peer must fold into the key, so a handshake
    // recorded from an earlier connection cannot be replayed onto this one.
    transport.send(Challenge(nonce: connection.hostNonce));

    final paired = await connection.handshake.future.timeout(
      kHandshakeTimeout,
      onTimeout: () {
        // Not counted against the attempt budget: silence is not a guess, and counting it would
        // let any peer force a lockout with five connections.
        _emit(const OutletRejectedPeer(.malformed, 'peer connected but never answered the challenge'));
        return false;
      },
    );
    _pending.remove(connection);

    if (!paired) {
      await connection.close();
      return false;
    }

    _limiter.reset();
    // The rest raced for a seat that is now taken. They are told rather than dropped, because a
    // panel phone that lost the race reads `alreadyPaired` in its reconnect loop.
    for (final loser in _pending.toList(growable: false)) {
      loser.transport.send(const Reject(.alreadyPaired));
      loser.settle(false);
      await loser.close();
    }

    // Everything the panel phone has not acknowledged goes again. It de-duplicates on `seq`, so
    // sending an event it already has costs a frame and nothing else.
    for (final queued in _queue) {
      _send(queued);
    }
    return true;
  }

  /// Records a power transition and sends it if the link is up.
  ///
  /// Always queued first: the outlet phone keeps observing while the network is down, so an event
  /// seen during a drop has to survive to be delivered later.
  void report(PowerState state, {int? atMs, int? wallMs}) {
    final frame = Power(state: state, atMs: atMs ?? _clock(), seq: ++_seq, wallMs: wallMs ?? _wallClock());
    if (_queue.length >= kMaxQueuedEvents) {
      _queue.removeAt(0);
      droppedCount += 1;
    }
    _queue.add(frame);
    _send(frame);
  }

  /// Ends the session for good.
  Future<void> close() async {
    _send(const Bye());
    await _detach();
    for (final connection in _pending.toList(growable: false)) {
      connection.settle(false);
      await connection.close();
    }
    _pending.clear();
    if (!_controller.isClosed) await _controller.close();
  }

  void _onFrame(ReceivedFrame received, _Connection connection) {
    final frame = received.frame;
    final key = connection.key;

    // Before this connection has proved itself, exactly one frame is acceptable.
    if (key == null) {
      if (frame is! Hello) {
        _refuse(.malformed, 'first frame was ${frame.type}, expected hello', connection);
        return;
      }
      _acceptHello(frame, received, connection);
      return;
    }

    // After that, every frame must carry a valid signature: this is the line a peer that does not
    // hold the pairing secret cannot cross.
    if (!key.verify(received.body, received.mac)) {
      _emit(OutletRejectedPeer(.wrongCode, '${frame.type} failed verification'));
      return;
    }

    // Proof of life: only a verified frame counts. An unsigned line must never keep a dead peer's
    // slot warm, or any peer could hold the session open with garbage.
    connection.lastVerifiedAtMs = _clock();
    if (identical(connection, _paired)) _armIdleTimer();

    switch (frame) {
      case Ack():
        _queue.removeWhere((queued) => queued.seq <= frame.seq);
        _emit(OutletDelivered(frame.seq));

      case Ping():
        _send(Pong(frame.n));

      case Bye():
        _emit(OutletPeerLeft(graceful: true, queued: _queue.length));
        _detach().ignore();

      case Hello():
      case Challenge():
      case Welcome():
      case Reject():
      case Power():
      case Pong():
        // Frames only the other role sends: ignored rather than treated as a protocol error, so a
        // future version can add senders.
        break;
    }
  }

  void _acceptHello(Hello hello, ReceivedFrame received, _Connection connection) {
    final key = secret.deriveKey(brand: identity.brand, hostNonce: connection.hostNonce, guestNonce: hello.nonce);
    if (!key.verify(received.body, received.mac)) {
      // One answer for every kind of failure to prove possession: distinguishing "wrong code"
      // from "bad signature" would tell a peer which half of its guess was right.
      _refuseGuess(.wrongCode, 'hello did not prove possession of the pairing secret', connection);
      return;
    }
    // Two candidates can both hold the secret, most often the panel phone reconnecting while its
    // previous connection is still finishing; the first one here wins, and this method runs to
    // completion without an await, so there is no window between the check and the assignment.
    // Re-checked after verification because the paired peer may have revived during the handshake:
    // a live peer refuses the newcomer and spends no budget, a quiet one is evicted. Eviction sits
    // behind a full `key.verify`, so exhaustive guessing can only lock itself out, never displace.
    if (_paired != null) {
      if (!_pairedIsQuiet) {
        _refuse(.alreadyPaired, 'proved the secret, but another peer got there first', connection);
        return;
      }
      final stale = _paired;
      _paired = null;
      _idleTimer?.cancel();
      _idleTimer = null;
      _emit(OutletPeerLeft(graceful: false, queued: _queue.length));
      stale?.settle(false);
      stale?.close().ignore();
    }

    connection
      ..key = key
      ..lastVerifiedAtMs = _clock();
    _paired = connection;
    _armIdleTimer();
    final welcome = Welcome(device: device);
    connection.transport.send(welcome, mac: key.sign(welcome.toBody()));
    _emit(OutletPaired(device: hello.device, strength: secret.strength));
    connection.settle(true);
  }

  /// (Re)starts the silence deadline for the paired connection.
  void _armIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = Timer(idleTimeout, () {
      // Free the slot, keep the session: the queue and the sequence survive, so the returning
      // phone re-attaches and the replay lands exactly once.
      _emit(OutletPeerLeft(graceful: false, queued: _queue.length));
      _detach().ignore();
    });
  }

  void _onFrameError(Object error, _Connection connection) {
    final reason = error is FrameError ? error.reason : RejectReason.malformed;
    final detail = error is FrameError ? error.detail : '$error';
    if (connection.key == null) {
      _refuse(reason, detail, connection);
      return;
    }
    // Mid-session garbage does not end the session: one corrupt line is more likely a truncated
    // write than an attack, and dropping the pairing would cost the user the session.
    _emit(OutletRejectedPeer(reason, detail));
  }

  void _onDone(_Connection connection) {
    if (!connection.handshake.isCompleted) {
      _emit(const OutletRejectedPeer(.malformed, 'peer disconnected during the handshake'));
      connection.settle(false);
      return;
    }
    if (!identical(_paired, connection)) return;

    _emit(OutletPeerLeft(graceful: false, queued: _queue.length));
    // Release the slot: a peer that dies without a `bye` must not hold the session, or the
    // returning phone is answered `alreadyPaired` every time. The queue and the sequence are
    // per-session and survive; this ends one connection.
    _detach().ignore();
  }

  /// Refuses one connection without spending the attempt budget. See [_refuseGuess].
  void _refuse(RejectReason reason, String detail, _Connection connection) {
    connection.transport.send(Reject(reason));
    _emit(OutletRejectedPeer(reason, detail));
    connection.settle(false);
  }

  /// Refuses a connection that guessed the secret and got it wrong, and spends one attempt.
  ///
  /// Only a `hello` that fails to verify is a guess. Counting anything else (a socket that reset,
  /// a peer that connected and said nothing, a garbled line) turns the protection into the attack:
  /// five connect-and-resets lock the user out of their own pairing. Which teardown a vanished
  /// peer produces is the operating system's choice, a reset on some platforms and a clean `done`
  /// on others, so such a rule also fires on one platform and not another.
  void _refuseGuess(RejectReason reason, String detail, _Connection connection) {
    _limiter.recordFailure();
    _refuse(reason, detail, connection);
  }

  void _send(PairFrame frame) {
    final connection = _paired;
    if (connection == null) return;
    connection.transport.send(frame, mac: connection.key?.sign(frame.toBody()));
  }

  void _emit(OutletEvent event) {
    if (!_controller.isClosed) _controller.add(event);
  }

  /// Ends the paired connection, leaving the session, its queue and its sequence intact.
  Future<void> _detach() async {
    // Ownership is taken before awaiting: a detach can overlap with a new peer being installed,
    // and clearing the field afterwards would disconnect a phone that had just paired.
    _idleTimer?.cancel();
    _idleTimer = null;
    final connection = _paired;
    _paired = null;
    connection?.settle(false);
    await connection?.close();
  }
}

/// One accepted connection, from the socket arriving to whatever ends it.
///
/// State is held per connection rather than on the session, so two overlapping connections cannot
/// trample each other: pairing is a race with one winner rather than a slot with an occupant.
final class _Connection {
  _Connection(this.transport, this.hostNonce);

  final PairTransport transport;

  /// This side's nonce, folded into the key so a recorded handshake cannot be replayed onto
  /// another connection.
  final String hostNonce;

  /// Completes true once this connection has proved it holds the secret.
  final Completer<bool> handshake = Completer<bool>();

  /// Set exactly once, when the peer's `hello` verifies.
  SessionKey? key;

  /// The session clock's reading at the last MAC-verified frame from this peer.
  ///
  /// Read by both the takeover gate and the idle deadline, and stamped through the session's
  /// injectable clock so a test can drive staleness without waiting.
  int lastVerifiedAtMs = 0;

  // ignore: cancel_subscriptions, cancelled in close(), which every exit path calls.
  StreamSubscription<ReceivedFrame>? subscription;

  /// Settles the handshake, once. Several paths can race to finish it.
  void settle(bool paired) {
    if (!handshake.isCompleted) handshake.complete(paired);
  }

  Future<void> close() async {
    final sub = subscription;
    subscription = null;
    await sub?.cancel();
    await transport.close();
  }
}

// ---------------------------------------------------------------------------------------------
// The panel phone: the one being carried. It connects, and it receives power events.
// ---------------------------------------------------------------------------------------------

/// {@template panel_event}
/// Something the panel phone's session wants the app to know.
/// {@endtemplate}
@immutable
sealed class PanelEvent {
  /// {@macro panel_event}
  const PanelEvent();
}

/// The outlet phone accepted this session.
final class PanelPaired extends PanelEvent {
  /// {@macro panel_event}
  const PanelPaired({required this.strength, this.device});

  /// The outlet phone's model.
  final String? device;

  /// See [OutletPaired.strength].
  final PairStrength strength;
}

/// A power transition, as reported by the outlet phone.
///
/// The timestamps are the outlet phone's and are not reconciled with this phone's clock: events
/// are matched by arrival, a reconnect is ordered by [seq], and the stamps are for the record.
final class PanelPowerEvent extends PanelEvent {
  /// {@macro panel_event}
  const PanelPowerEvent({required this.state, required this.atMs, required this.seq, this.wallMs});

  /// What the outlet phone saw.
  final PowerState state;

  /// The outlet phone's monotonic stamp. Comparable only with other stamps from that same phone.
  final int atMs;

  /// The outlet phone's wall clock at the same instant, for display.
  final int? wallMs;

  /// Position in the session: the key that makes replay idempotent.
  final int seq;
}

/// The outlet phone refused the handshake, with a reason the screen can explain.
final class PanelRefused extends PanelEvent {
  /// {@macro panel_event}
  const PanelRefused(this.reason);

  /// Why.
  final RejectReason reason;
}

/// The connection dropped. [graceful] separates the outlet phone's "End session" from a Wi-Fi
/// drop: it mirrors [OutletPeerLeft.graceful] and is the reconnect owner's cue, because a peer
/// that said `bye` is not coming back and retrying against it would misreport the state.
final class PanelDisconnected extends PanelEvent {
  /// {@macro panel_event}
  const PanelDisconnected({this.graceful = false});

  /// Whether the peer said `bye` first.
  final bool graceful;
}

/// The link is over for good: either the whole retry budget was spent without the outlet phone
/// answering, or the outlet phone ended the session itself ([peerEnded]).
///
/// Terminal, unlike [PanelDisconnected]: no retry loop is running any more. Emitted by whoever
/// owns reconnection, not by the session, which has no retry budget of its own.
final class PanelGaveUp extends PanelEvent {
  /// {@macro panel_event}
  const PanelGaveUp({this.peerEnded = false});

  /// Whether the outlet phone ended the session itself, as opposed to going silent.
  final bool peerEnded;
}

/// The panel phone's half of a pairing session: the connecting side.
///
/// It outlives the connection too: a Wi-Fi drop or a rebooted router ends a socket, not a session.
/// Reconnect by calling [attach] again with a fresh transport. The replay guard is kept, which is
/// what makes the outlet phone's replay land exactly once.
final class PanelSession {
  /// Creates a [PanelSession].
  PanelSession({
    required this.identity,
    required this.secret,
    this.device,
    this.heartbeatInterval = kHeartbeatInterval,
    this.idleTimeout = kIdleTimeout,
  });

  final ReplayGuard _guard = ReplayGuard();

  final StreamController<PanelEvent> _controller = StreamController<PanelEvent>.broadcast();

  SessionKey? _key;

  PairTransport? _transport;

  /// Ticks every [heartbeatInterval] once welcomed; each tick sends a signed [Ping].
  Timer? _pingTimer;

  /// Rewound by every MAC-verified inbound frame; firing means the outlet phone is gone.
  Timer? _idleTimer;

  /// Per-connection ping counter: reset on every [attach], echoed back in [Pong].
  int _pingCounter = 0;

  // Cancelled in _detach(), through a local: ownership is taken before the first await, so a
  // reconnect cannot be torn down by the old teardown finishing after it.
  // ignore: cancel_subscriptions
  StreamSubscription<ReceivedFrame>? _subscription;

  Completer<bool>? _handshake;

  /// See [kHeartbeatInterval]; injectable for tests.
  final Duration heartbeatInterval;

  /// See [kIdleTimeout].
  final Duration idleTimeout;

  /// The application's identity on the wire; its `brand` is bound into every session key.
  final PairIdentity identity;

  /// The pairing secret, scanned from the outlet phone's QR code or built from the typed digits.
  final PairSecret secret;

  /// This phone's model, sent in `hello`.
  final String? device;

  /// Everything the app needs to react to.
  Stream<PanelEvent> get events => _controller.stream;

  /// Whether this session is connected and authenticated.
  bool get isPaired => _key != null && (_transport?.isOpen ?? false);

  /// Connects this session over [transport] and answers the outlet phone's challenge.
  ///
  /// Returns true once the outlet phone has said `welcome`.
  Future<bool> attach(PairTransport transport) async {
    // See OutletSession.attach: a finished stream never says `done` to a late listener.
    if (!transport.isOpen) {
      await transport.close();
      return false;
    }

    await _detach();
    _transport = transport;
    _key = null;
    _pingCounter = 0;

    final handshake = _handshake = Completer<bool>();
    _subscription = transport.frames.listen(
      (received) => _onFrame(received, handshake),
      onError: (Object error) {
        // An older outlet's challenge fails the version check inside the codec on this side, so
        // the mismatch never arrives as a wire Reject. Without this it surfaces as a handshake
        // timeout rather than a version error, so it is reported with the same event.
        if (error is FrameError && error.reason == .versionMismatch) {
          _emit(const PanelRefused(.versionMismatch));
        }
        if (!handshake.isCompleted) handshake.complete(false);
      },
      onDone: () {
        // A handshake that never completed is not a DROP: `attach` reports that by returning
        // false, and the peer that hung up mid-handshake was never paired. Emitting a disconnect
        // there made a failed reconnect attempt look like a fresh outage.
        if (!handshake.isCompleted) {
          handshake.complete(false);
          return;
        }
        _emit(const PanelDisconnected());
        // Detach with the report, the way the `bye` and idle paths do. Without this the idle
        // timer stayed armed and fired fifteen seconds later, so ONE dropped socket was reported
        // TWICE — and the second report arrived after the consumer had finished reacting to the
        // first, which bought a second reconnect budget (BreakerSonar, found on hardware
        // 2026-09-05).
        _detach().ignore();
      },
    );

    // Nothing is sent until the outlet phone has issued its challenge: the key cannot be derived
    // before then, and an unsigned frame would go to an unauthenticated peer.
    final paired = await handshake.future.timeout(kHandshakeTimeout, onTimeout: () => false);
    if (!paired) {
      await _detach();
      return false;
    }
    return true;
  }

  /// Says goodbye and stops.
  Future<void> close() async {
    _send(const Bye());
    await _detach();
    _key = null;
    if (!_controller.isClosed) await _controller.close();
  }

  // One branch per frame type; splitting the dispatcher would hide the protocol's shape.
  // ignore: avoid-high-cyclomatic-complexity
  void _onFrame(ReceivedFrame received, Completer<bool> handshake) {
    final frame = received.frame;

    // Exactly two frames are accepted unsigned. `challenge`, because the key does not exist until
    // it arrives; and `reject`, because a refusal often means the outlet phone could not derive a
    // key at all, so requiring a signature would hide every refusal behind a handshake timeout.
    switch (frame) {
      case Challenge():
        // Only before a key exists. A challenge is unsigned by necessity, so accepting one
        // mid-session would let a single unauthenticated frame re-key this side, after which every
        // properly signed event from the real peer is dropped. The outlet half has the same
        // property: a late `hello` falls through to MAC verification and is ignored.
        if (_key == null) _onChallenge(frame);
        return;

      case Reject():
        // Accepted unsigned only while this handshake is unresolved. `_key == null` is the wrong
        // gate: a panel holding the wrong code has already derived a key from the challenge by the
        // time `wrongCode` arrives, and a reconnect's `alreadyPaired` comes from an outlet that
        // never keyed this connection, so neither refusal is signable. Once paired the window
        // closes, or one unauthenticated line could tear down a healthy link.
        if (!handshake.isCompleted) {
          _emit(PanelRefused(frame.reason));
          handshake.complete(false);
        }
        return;

      case Hello():
      case Welcome():
      case Power():
      case Ack():
      case Ping():
      case Pong():
      case Bye():
        break;
    }

    final key = _key;
    if (key == null || !key.verify(received.body, received.mac)) return;

    // Proof of life: verified frames only, for the same reason as the outlet half.
    _armIdleTimer();

    switch (frame) {
      case Welcome():
        _startHeartbeat();
        _emit(PanelPaired(device: frame.device, strength: secret.strength));
        if (!handshake.isCompleted) handshake.complete(true);

      case Power():
        _onPower(frame);

      case Bye():
        _emit(const PanelDisconnected(graceful: true));
        _detach().ignore();

      // Pong is expected traffic: liveness was stamped above and its counter is only for logs.
      // The rest are frames this role does not receive.
      case Pong():
      case Hello():
      case Challenge():
      case Reject():
      case Ack():
      case Ping():
        break;
    }
  }

  /// Sends a signed [Ping] every [heartbeatInterval] for the life of the connection.
  void _startHeartbeat() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(heartbeatInterval, (_) => _send(Ping(++_pingCounter)));
  }

  /// (Re)starts the silence deadline. Firing means the peer died without a FIN.
  void _armIdleTimer() {
    _idleTimer?.cancel();
    _idleTimer = Timer(idleTimeout, () {
      _emit(const PanelDisconnected());
      _detach().ignore();
    });
  }

  /// Answers the outlet phone's challenge, which is the first moment a key can exist.
  void _onChallenge(Challenge challenge) {
    final guestNonce = PairSecret.newNonce();
    final key = _key = secret.deriveKey(brand: identity.brand, hostNonce: challenge.nonce, guestNonce: guestNonce);
    final hello = Hello(nonce: guestNonce, device: device);
    _transport?.send(hello, mac: key.sign(hello.toBody()));
  }

  void _onPower(Power frame) {
    if (!_guard.accept(frame)) return;

    _emit(PanelPowerEvent(state: frame.state, atMs: frame.atMs, wallMs: frame.wallMs, seq: frame.seq));
    // Acked only after the event has been handed to the application, so a crash between the two
    // replays the event rather than losing it.
    _send(Ack(frame.seq));
  }

  void _send(PairFrame frame) => _transport?.send(frame, mac: _key?.sign(frame.toBody()));

  void _emit(PanelEvent event) {
    if (!_controller.isClosed) _controller.add(event);
  }

  Future<void> _detach() async {
    _pingTimer?.cancel();
    _pingTimer = null;
    _idleTimer?.cancel();
    _idleTimer = null;
    final handshake = _handshake;
    if (handshake != null && !handshake.isCompleted) handshake.complete(false);
    _handshake = null;

    // Same ownership rule as the outlet half: clear the fields before awaiting, so a reconnect
    // that installs a new transport cannot be torn down by the old one finishing its teardown.
    final subscription = _subscription;
    final transport = _transport;
    _subscription = null;
    _transport = null;

    await subscription?.cancel();
    await transport?.close();
  }
}
