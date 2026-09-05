import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:meta/meta.dart';
import 'package:pairlink/src/frames.dart';
import 'package:pairlink/src/identity.dart';

/// How the two phones came to share a secret, and therefore how strong the pairing is.
///
/// Reported up to the UI: the two paths differ by 124 bits, so an application should not present
/// them as equivalent.
enum PairStrength {
  /// The secret was carried by the QR code: 128 random bits, never on the wire, never on screen
  /// long enough to read. Someone who records the whole handshake learns nothing.
  scanned,

  /// The secret is the four-digit code the user typed: 10 000 possibilities. Exhaustive guessing
  /// is capped by [AttemptLimiter]; reading the code off the screen is capped by nothing.
  typed,
}

/// The shared secret the two phones pair with.
///
/// QR path: the outlet phone generates 128 bits and displays them, so the phone that shows the QR
/// is the phone that listens. Typed path: the panel phone generates the four digits and the user
/// types them on the outlet phone.
///
/// Either way the secret travels out of band only and is never sent over the network in any form;
/// the handshake proves possession with a MAC, so a passive listener does not learn the code.
@immutable
final class PairSecret {
  /// Length in bytes of a generated secret. The QR path's strength claim rests on this number.
  static const int kScannedBytes = 16;

  /// How many digits a typed code has. The entry field, the generator and [AttemptLimiter] are
  /// all sized against it.
  static const int kCodeLength = 4;

  /// Length in bytes of [pairId]. Four is enough to tell one home's pairing from another's on a
  /// shared network, and short enough to stay inside a TXT record without inviting anyone to read
  /// it as a fingerprint.
  static const int kPairIdBytes = 4;

  const PairSecret._(this._material, this.strength);

  /// 128 random bits, for the QR path.
  factory PairSecret.generate() {
    final random = Random.secure();
    return PairSecret._(
      Uint8List.fromList(<int>[for (var i = 0; i < kScannedBytes; i++) random.nextInt(256)]),
      .scanned,
    );
  }

  /// The four-digit fallback, for a user who cannot or will not scan.
  factory PairSecret.code(String code) => PairSecret._(Uint8List.fromList(utf8.encode(code)), .typed);

  /// Restores a scanned secret from the QR payload.
  ///
  /// Throws a [FormatException] on anything that is not exactly [kScannedBytes] bytes: without
  /// the length check a one-byte `k=` would parse and come back labelled [PairStrength.scanned],
  /// which is a claim about strength the payload does not support.
  factory PairSecret.fromBase64Url(String encoded) {
    final material = base64Url.decode(encoded);
    if (material.length != kScannedBytes) {
      throw FormatException('a scanned secret must be $kScannedBytes bytes, got ${material.length}');
    }
    return PairSecret._(Uint8List.fromList(material), .scanned);
  }

  final Uint8List _material;

  /// How this secret was shared, and therefore what the pairing is worth.
  final PairStrength strength;

  /// A fresh four-digit code, uniformly distributed.
  ///
  /// [Random.secure] even for four digits: the default generator is seeded from the clock, which
  /// makes the code predictable from the time it was shown.
  static String newCode() => Random.secure().nextInt(10000).toString().padLeft(kCodeLength, '0');

  /// A fresh nonce for one connection: 16 random bytes, base64.
  static String newNonce() {
    final random = Random.secure();
    return base64Encode(Uint8List.fromList(<int>[for (var i = 0; i < 16; i++) random.nextInt(256)]));
  }

  /// The QR payload form. Only meaningful for a generated secret.
  String toBase64Url() => base64Url.encode(_material);

  /// A public name for this pairing: the first [kPairIdBytes] of HMAC-SHA256 over the secret, hex.
  ///
  /// Null for a typed code, BY CONSTRUCTION and not by policy. Thirty-two bits of a keyed hash
  /// over 128 random bits say nothing about the key; the same hash over four digits is a
  /// ten-thousand-row lookup table anyone could build, which is the finding that took the code
  /// out of the TXT record in the first place (`docs/skeptic-m2.md`, finding 6).
  ///
  /// What it is for: two phones that remember each other can recognise each other before they
  /// connect. Publishing it costs nothing a passive listener does not already have — it is
  /// unlinkable to the secret — and it saves every OTHER phone on the network from spending an
  /// attempt on a handshake that could never verify.
  String? pairId({required String brand}) => switch (strength) {
    .typed => null,
    .scanned =>
      Hmac(sha256, _material)
          .convert(utf8.encode('$brand-pairlink-id'))
          .bytes
          .take(kPairIdBytes)
          .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
          .join(),
  };

  /// Derives the key for one connection, binding both nonces and the application's brand
  /// ([PairIdentity.brand]).
  ///
  /// [hostNonce] is the one the listening phone sends in its `challenge`; [guestNonce] comes back
  /// in the `hello`. Because the host's nonce comes first and is fresh per connection, neither
  /// side can fix the key alone and a captured handshake cannot be replayed onto another one.
  SessionKey deriveKey({required String brand, required String hostNonce, required String guestNonce}) => ._(
    _hkdf(
      secret: _material,
      salt: utf8.encode('$hostNonce|$guestNonce'),
      info: utf8.encode('$brand-pairlink-v$kPairlinkVersion'),
    ),
  );

  /// HKDF-SHA256 (RFC 5869), extract-then-expand, one output block. Written out rather than taken
  /// from a dependency, so the shape of the derivation stays readable.
  static List<int> _hkdf({required List<int> secret, required List<int> salt, required List<int> info}) {
    final prk = Hmac(sha256, salt).convert(secret).bytes;
    return Hmac(sha256, prk).convert(<int>[...info, 0x01]).bytes;
  }
}

/// Authenticates every frame of one connection.
///
/// Every frame after the challenge carries an HMAC over its body with a key neither side could
/// choose alone. With a [PairStrength.scanned] secret that is a genuine defence: a peer that
/// watches the whole handshake cannot derive the key, because the 128-bit secret never travelled.
/// With a [PairStrength.typed] secret the key is worth four digits, so a peer that reads the code
/// off the screen can pair; the countermeasures there are [AttemptLimiter] and the rule that an
/// already paired session refuses a second peer.
@immutable
final class SessionKey {
  const SessionKey._(this._key);

  final List<int> _key;

  /// Signs a frame body.
  ///
  /// The body is canonicalised first (keys sorted), so two encoders that disagree about field
  /// order still produce the same MAC and a re-serialisation does not read as a forgery.
  ///
  /// The canonicalisation is top-level only, so every frame body must stay flat: scalar values, no
  /// nested objects or lists. The assert keeps a future frame with a nested map from producing a
  /// non-deterministic signature that makes valid frames fail verification.
  String sign(Map<String, Object?> body) {
    assert(
      body.values.every((value) => value == null || value is num || value is String || value is bool),
      'frame bodies must be flat: top-level-only canonicalisation cannot sign nested structures',
    );
    return base64Encode(Hmac(sha256, _key).convert(utf8.encode(_canonical(body))).bytes);
  }

  /// Whether [mac] is this key's signature over [body].
  ///
  /// Constant-time comparison: a byte-by-byte early return leaks how much of a forged MAC was
  /// correct, which over enough attempts is a way to construct one.
  bool verify(Map<String, Object?> body, String? mac) {
    if (mac == null) return false;
    final expected = utf8.encode(sign(body));
    final actual = utf8.encode(mac);
    if (expected.length != actual.length) return false;

    var difference = 0;
    for (final (index, byte) in expected.indexed) {
      difference |= byte ^ actual[index];
    }
    return difference == 0;
  }

  /// Deterministic JSON: keys in sorted order, `mac` never included.
  static String _canonical(Map<String, Object?> body) {
    final keys = body.keys.where((key) => key != 'mac').toList()..sort();
    return jsonEncode(<String, Object?>{for (final key in keys) key: body[key]});
  }
}

/// {@template attempt_limiter}
/// Caps how many times a stranger may guess.
/// {@endtemplate}
///
/// The four-digit path has 10 000 possibilities, which over a LAN socket is seconds of exhaustive
/// guessing. After [maxAttempts] failures the listening phone stops accepting connections until
/// the user regenerates the code, which also tells them somebody was trying. Not a per-second
/// throttle: a slow drip of 10 000 guesses over an hour would still succeed.
final class AttemptLimiter {
  /// {@macro attempt_limiter}
  AttemptLimiter({this.maxAttempts = 5});

  /// How many failures are tolerated before the door closes.
  final int maxAttempts;

  /// Whether the listening phone should still accept connections.
  bool get isOpen => _failures < maxAttempts;

  int _failures = 0;

  /// Failed attempts so far.
  int get failures => _failures;

  /// Records a failure. Returns whether the door is still open afterwards.
  bool recordFailure() {
    _failures++;
    return isOpen;
  }

  /// Called when a peer pairs successfully, and when the user regenerates the code.
  void reset() => _failures = 0;
}

/// Rejects replayed and out-of-order [Power] frames.
///
/// `seq` must strictly increase, which drops a frame captured off the wire and sent again and
/// makes the reconnect replay idempotent, since the outlet phone re-sends its queue without
/// knowing what arrived. The monotonic stamp must not go backwards either, because a recorded
/// frame replayed later still carries its original stamp.
///
/// That rule reads the monotonic clock, not the wall clock, which is why [Power] carries both: a
/// device coming back online often corrects its wall clock backwards by seconds, and a wall-clock
/// rule would then drop every remaining event of the session.
final class ReplayGuard {
  int _lastAtMs = -1;
  int _lastSeq = -1;

  /// Highest sequence accepted so far; `-1` before the first frame.
  int get lastSeq => _lastSeq;

  /// Whether [frame] is new. Accepting it advances the guard; rejecting leaves it untouched.
  bool accept(Power frame) {
    if (frame.seq <= _lastSeq) return false;
    if (frame.atMs < _lastAtMs) return false;
    _lastSeq = frame.seq;
    _lastAtMs = frame.atMs;
    return true;
  }

  /// Forgets everything. Called when a new session starts, never on reconnect: a reconnect must
  /// keep the history, or the replay it triggers would be accepted twice.
  void reset() {
    _lastSeq = -1;
    _lastAtMs = -1;
  }
}
