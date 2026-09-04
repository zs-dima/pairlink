import 'dart:convert';

import 'package:meta/meta.dart';

/// Wire protocol version, carried in [Challenge] and [Hello] and checked on receipt.
///
/// Bumped whenever a frame changes shape. Devices running different application versions will
/// meet, so a mismatch has to be a clean [RejectReason.versionMismatch] rather than a mis-parse.
///
/// Version 2 moved the first word to the outlet phone ([Challenge]), took the pairing secret off
/// the wire and added a monotonic stamp to [Power]; version 3 added heartbeats ([Ping]/[Pong])
/// and staleness-gated takeover. The bump is strict, with no capability negotiation: pairing is
/// ephemeral so nothing persisted needs migrating, and negotiation would switch the newer
/// protections off for the most likely mixed pair, an old spare device left in the outlet.
const int kPairlinkVersion = 3;

/// What the outlet phone observed.
enum PowerState {
  /// Mains power went away.
  lost,

  /// Mains power came back.
  restored,
}

/// Why a handshake was refused. Sent in [Reject] so the outlet phone can say something true.
enum RejectReason {
  /// The peer could not prove it holds the pairing secret: a wrong code, or a stale QR.
  ///
  /// A bad signature is answered with this same reason, so a refusal never reveals which part of
  /// a guess was closer.
  wrongCode,

  /// The other side speaks a different protocol version.
  versionMismatch,

  /// A session is already paired with a different device. Sent so a second peer cannot displace
  /// the paired one part way through a session.
  alreadyPaired,

  /// Too many failed attempts. The listening side accepts nothing further until the user asks for
  /// a new code, which is also how they find out somebody was trying.
  tooManyAttempts,

  /// The frame was not understood at all.
  malformed,
}

/// {@template pair_frame}
/// One message on the pairlink wire.
///
/// Sealed, so every receiver switches exhaustively and an added frame type becomes a compile error
/// at each site rather than an ignored message.
/// {@endtemplate}
@immutable
sealed class PairFrame {
  /// {@macro pair_frame}
  const PairFrame();

  /// Frame type tag, the `t` field.
  String get type;

  /// Frame body without the `mac` field: this is what gets signed and verified.
  ///
  /// Signing the body rather than the serialized line keeps the MAC independent of key order and
  /// whitespace, so a re-encode on either side cannot invalidate a valid frame.
  Map<String, Object?> toBody();
}

/// The outlet phone speaks first, before the peer has proved anything.
///
/// Unsigned, and not secret: a nonce guarantees freshness, not confidentiality. Sending it first
/// is what makes the session key unchoosable by either side alone, and what stops a handshake
/// captured on one connection from being replayed onto the next.
final class Challenge extends PairFrame {
  /// {@macro pair_frame}
  const Challenge({required this.nonce, this.version = kPairlinkVersion});

  /// Protocol version the outlet phone speaks.
  final int version;

  /// Base64 of 16 random bytes, fresh for this connection.
  final String nonce;

  @override
  String get type => 'challenge';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'v': version, 't': type, 'nonce': nonce};
}

/// The panel phone's answer: its own nonce, and a MAC proving it holds the pairing secret.
///
/// The pairing secret itself is not in here in any form: possession is proved by the signature
/// over both nonces, so a passive listener on the LAN learns nothing it could pair with.
final class Hello extends PairFrame {
  /// {@macro pair_frame}
  const Hello({required this.nonce, this.version = kPairlinkVersion, this.device});

  /// Protocol version the sender speaks.
  final int version;

  /// Base64 of 16 random bytes, fresh for this connection.
  final String nonce;

  /// Human-readable model name, for display and diagnostics. Never an identifier.
  final String? device;

  @override
  String get type => 'hello';

  @override
  Map<String, Object?> toBody() => <String, Object?>{
    'v': version,
    't': type,
    'nonce': nonce,
    if (device case final String d) 'device': d,
  };
}

/// The outlet phone accepted the handshake.
final class Welcome extends PairFrame {
  /// {@macro pair_frame}
  const Welcome({this.device});

  /// The outlet phone's model, shown on the panel phone.
  final String? device;

  @override
  String get type => 'welcome';

  @override
  Map<String, Object?> toBody() => <String, Object?>{
    't': type,
    if (device case final String d) 'device': d,
  };
}

/// The outlet phone refused, with a reason the UI can turn into copy.
final class Reject extends PairFrame {
  /// {@macro pair_frame}
  const Reject(this.reason);

  /// Why.
  final RejectReason reason;

  @override
  String get type => 'reject';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'t': type, 'reason': reason.name};
}

/// A power transition observed by the outlet phone.
final class Power extends PairFrame {
  /// {@macro pair_frame}
  const Power({required this.state, required this.atMs, required this.seq, this.wallMs});

  /// What happened.
  final PowerState state;

  /// The outlet phone's monotonic clock when the platform saw it: milliseconds since that device
  /// booted, not since 1970.
  ///
  /// Monotonic because the value is ordered, compared and replay-checked, and a device coming
  /// back online often corrects its wall clock backwards by seconds, which a wall-clock rule
  /// cannot tell from a replay. Android's `elapsedRealtime` counts through deep sleep while iOS's
  /// `systemUptime` pauses, so "since boot" is literal only on Android; ordering is unaffected,
  /// since a stamp is only compared with neighbours from the same source.
  final int atMs;

  /// The outlet phone's wall clock at the same instant, for display and diagnostics only.
  ///
  /// Never used for ordering or replay rejection: it exists so an event can be shown with a time
  /// of day rather than a millisecond count since the other device booted.
  final int? wallMs;

  /// Monotonic per-session counter. Carries three jobs at once: replay rejection, ordering, and
  /// exactly-once delivery after a reconnect.
  final int seq;

  @override
  String get type => 'power';

  @override
  Map<String, Object?> toBody() => <String, Object?>{
    't': type,
    'state': state.name,
    'ts': atMs,
    'seq': seq,
    'wall': ?wallMs,
  };
}

/// The panel phone confirms it has stored everything up to and including [seq].
final class Ack extends PairFrame {
  /// {@macro pair_frame}
  const Ack(this.seq);

  /// Highest sequence number safely stored.
  final int seq;

  @override
  String get type => 'ack';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'t': type, 'seq': seq};
}

/// Panel to outlet: proof of life, sent every [kHeartbeatInterval] once paired.
///
/// The panel drives the heartbeat because it already owns reconnection. One ping direction gives
/// symmetric detection, since the outlet proves itself with the [Pong]. Signed like every
/// post-handshake frame; an unsigned ping is unauthenticated and resets nothing.
final class Ping extends PairFrame {
  /// {@macro pair_frame}
  const Ping(this.n);

  /// Per-connection monotonic counter, which rejects same-connection pong replay.
  final int n;

  @override
  String get type => 'ping';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'t': type, 'n': n};
}

/// Outlet to panel: the echo of a [Ping], carrying the same counter.
final class Pong extends PairFrame {
  /// {@macro pair_frame}
  const Pong(this.n);

  /// Echo of [Ping.n].
  final int n;

  @override
  String get type => 'pong';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'t': type, 'n': n};
}

/// Orderly close. Advisory only: the session must survive the socket dying without one.
final class Bye extends PairFrame {
  /// {@macro pair_frame}
  const Bye();

  @override
  String get type => 'bye';

  @override
  Map<String, Object?> toBody() => <String, Object?>{'t': type};
}

/// A decoded frame together with the signature it arrived with and the bytes that signature
/// covers. Verification needs all three, and for [Hello] the key cannot be derived until the
/// nonce inside `frame` has been read.
typedef ReceivedFrame = ({PairFrame frame, String? mac, Map<String, Object?> body});

/// A frame that could not be decoded, and why.
@immutable
final class FrameError implements Exception {
  /// Creates a [FrameError].
  const FrameError(this.reason, this.detail);

  /// Machine-readable cause, so the caller can answer with a [Reject].
  final RejectReason reason;

  /// What was wrong, for diagnostics. Not intended for display.
  final String detail;

  @override
  String toString() => 'FrameError(${reason.name}: $detail)';
}

/// Encodes and decodes [PairFrame]s as JSON lines.
///
/// Every decode path assumes untrusted input: anyone on the same Wi-Fi can open the socket and
/// write bytes. Each field is read through a checked accessor, and every failure comes back as a
/// [FrameError] with a reason the caller can put on the wire.
abstract final class FrameCodec {
  /// Serializes [frame] to a single line, with [mac] appended when the session is authenticated.
  static String encode(PairFrame frame, {String? mac}) {
    final body = frame.toBody();
    return jsonEncode(<String, Object?>{...body, 'mac': ?mac});
  }

  /// Parses one line. Returns the frame and the MAC that came with it, if any.
  ///
  /// The MAC is returned rather than verified: verification needs the session key, and for
  /// [Hello] the key is not derivable until the nonce inside the frame has been parsed.
  static ReceivedFrame decode(String line) {
    final json = _parseJson(line);
    if (json is! Map<String, Object?>) {
      throw const FrameError(.malformed, 'top level is not an object');
    }

    final mac = json['mac'];
    if (mac != null && mac is! String) {
      throw const FrameError(.malformed, 'mac is not a string');
    }
    // The signed body is everything except the signature itself.
    final body = <String, Object?>{...json}..remove('mac');

    final frame = switch (_string(json, 't')) {
      'challenge' => _challenge(json),
      'hello' => _hello(json),
      'welcome' => Welcome(device: _optionalString(json, 'device')),
      'reject' => Reject(_enumValue(RejectReason.values, _string(json, 'reason'), 'reason')),
      'power' => Power(
        state: _enumValue(PowerState.values, _string(json, 'state'), 'state'),
        atMs: _int(json, 'ts'),
        seq: _int(json, 'seq'),
        wallMs: _optionalInt(json, 'wall'),
      ),
      'ack' => Ack(_int(json, 'seq')),
      'ping' => Ping(_int(json, 'n')),
      'pong' => Pong(_int(json, 'n')),
      'bye' => const Bye(),
      final t => throw FrameError(.malformed, 'unknown frame type "$t"'),
    };

    return (frame: frame, mac: mac as String?, body: body);
  }

  static Challenge _challenge(Map<String, Object?> json) =>
      .new(version: _requireVersion(json, 'challenge'), nonce: _string(json, 'nonce'));

  static Hello _hello(Map<String, Object?> json) => .new(
    version: _requireVersion(json, 'hello'),
    nonce: _string(json, 'nonce'),
    device: _optionalString(json, 'device'),
  );

  /// Checked before any other field of a handshake frame is trusted: a frame from another version
  /// has already been parsed under this version's rules, so anything read out of it is a guess.
  static int _requireVersion(Map<String, Object?> json, String frame) {
    final version = _int(json, 'v');
    if (version != kPairlinkVersion) {
      throw FrameError(.versionMismatch, '$frame v$version, this build speaks v$kPairlinkVersion');
    }
    return version;
  }

  /// Converts a JSON syntax error into the protocol's own error type.
  ///
  /// The original stack trace is dropped: it points into `dart:convert`, while [FrameError]
  /// carries the reason that goes back on the wire.
  // `Object?`, not `Object`: `jsonDecode('null')` returns null and a peer can send that line, so
  // the caller's `is! Map` check turns it into `malformed` instead of a TypeError here.
  // ignore: avoid-unnecessary-nullable-return-type
  static Object? _parseJson(String line) {
    try {
      return jsonDecode(line);
    } on FormatException catch (e) {
      // Intentional conversion to a domain error; the dropped trace is explained above.
      // ignore: avoid_throw_in_catch_block, avoid-throw-in-catch-block
      throw FrameError(.malformed, 'not JSON: ${e.message}');
    }
  }

  static String _string(Map<String, Object?> json, String key) {
    final value = json[key];
    if (value is String) return value;
    if (value == null) throw FrameError(.malformed, 'missing "$key"');
    throw FrameError(.malformed, '"$key" is ${value.runtimeType}, want String');
  }

  static String? _optionalString(Map<String, Object?> json, String key) {
    final value = json[key];
    if (value == null) return null;
    if (value is String) return value;
    throw FrameError(.malformed, '"$key" is ${value.runtimeType}, want String');
  }

  static int _int(Map<String, Object?> json, String key) {
    final value = json[key];
    // A double that happens to be integral is not accepted: a timestamp arriving as 1.7e12 means
    // the sender is not speaking this protocol, and coercing it hides that.
    if (value is int) return value;
    if (value == null) throw FrameError(.malformed, 'missing "$key"');
    throw FrameError(.malformed, '"$key" is ${value.runtimeType}, want int');
  }

  static int? _optionalInt(Map<String, Object?> json, String key) {
    final value = json[key];
    if (value == null) return null;
    if (value is int) return value;
    throw FrameError(.malformed, '"$key" is ${value.runtimeType}, want int');
  }

  static T _enumValue<T extends Enum>(List<T> values, String raw, String key) {
    for (final value in values) {
      if (value.name == raw) return value;
    }
    throw FrameError(.malformed, 'unknown "$key" value "$raw"');
  }
}
