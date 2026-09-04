/// An uninvited peer's own implementation of the pairlink wire format.
///
/// Nothing here calls `PanelSession` or `OutletSession`, and the crypto is re-derived from RFC 5869
/// rather than reused from `session_key.dart`: an attacker built out of the honest client can only
/// do what the honest client does, and so proves nothing.
// Shared probe harness, imported by the skeptic tests; its members are public by design.
// ignore_for_file: avoid-top-level-members-in-tests
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pairlink/pairlink.dart' show kPairlinkVersion;

/// HKDF-SHA256, extract-then-expand, one block, written independently of the product's copy.
List<int> hkdf({required List<int> secret, required List<int> salt, required List<int> info}) {
  final prk = Hmac(sha256, salt).convert(secret).bytes;
  return Hmac(sha256, prk).convert(<int>[...info, 0x01]).bytes;
}

/// The session key an uninvited peer derives when they hold the secret material.
///
/// The HKDF is re-derived from RFC 5869 above rather than reused. [brand] is not an algorithm to
/// model: it is the application's identity on the wire, read off the binary by anyone targeting it,
/// so the tests pass the same value the victim runs under.
List<int> attackerKey(
  List<int> secret,
  String hostNonce,
  String guestNonce, {
  required String brand,
  int version = kPairlinkVersion,
}) => hkdf(
  secret: secret,
  salt: utf8.encode('$hostNonce|$guestNonce'),
  info: utf8.encode('$brand-pairlink-v$version'),
);

/// The canonical form the product signs: keys sorted, `mac` excluded.
String canonical(Map<String, Object?> body) {
  final keys = body.keys.where((key) => key != 'mac').toList()..sort();
  return jsonEncode(<String, Object?>{for (final key in keys) key: body[key]});
}

/// Signs a body the way the product does.
String signBody(List<int> key, Map<String, Object?> body) =>
    base64Encode(Hmac(sha256, key).convert(utf8.encode(canonical(body))).bytes);

/// The four digits, as `PairSecret.code` encodes them.
List<int> codeSecret(String code) => utf8.encode(code);

/// 16 bytes of nonce-shaped material, base64.
String fakeNonce([int seed = 7]) =>
    base64Encode(Uint8List.fromList(<int>[for (var i = 0; i < 16; i++) (seed * 31 + i * 17) & 0xFF]));

/// An uninvited peer speaking JSON lines over a raw socket, in either direction.
///
/// One persistent subscription, never cancelled mid-conversation: cancelling a subscription on a
/// `Socket` destroys the socket, which would end the probe rather than the subject.
final class Hostile {
  Hostile._(this._socket) {
    _lines = _socket
        .cast<List<int>>()
        .transform(const Utf8Decoder(allowMalformed: true))
        .transform(const LineSplitter())
        .listen(_onLine, onError: (Object _) {}, onDone: _onDone);
    // A subject that hangs up mid-write surfaces the failure on `done`, not on `add`. Unhandled, it
    // takes the uninvited peer down instead of the subject.
    _socket.done.then<void>((_) {}, onError: (Object _) => closedByPeer = true).ignore();
  }

  /// Takes over an accepted socket: the uninvited peer as server.
  factory Hostile.wrap(Socket socket) => Hostile._(socket);

  final Socket _socket;

  late final StreamSubscription<String> _lines;
  Completer<String?>? _waiting;
  int _consumed = 0;

  /// Every line the subject sent, in order.
  final List<String> received = <String>[];

  /// Whether the subject hung up.
  bool closedByPeer = false;

  /// Everything the subject has said so far, as decoded objects (undecodable lines skipped).
  List<Map<String, Object?>> get frames => <Map<String, Object?>>[
    for (final line in received)
      if (_tryJson(line) case final Map<String, Object?> json) json,
  ];

  /// Opens a hostile connection to [port] on loopback: the uninvited peer as client.
  static Future<Hostile> connect(int port) async => Hostile._(await Socket.connect(InternetAddress.loopbackIPv4, port));

  /// The next unconsumed line, or null when the subject hangs up or says nothing in [within].
  Future<String?> next({Duration within = const Duration(seconds: 3)}) async {
    if (_consumed < received.length) return received[_consumed++];
    if (closedByPeer) return null;
    final waiting = _waiting = Completer<String?>();
    final line = await waiting.future.timeout(within, onTimeout: () => null);
    if (line != null) _consumed++;
    return line;
  }

  /// The next line decoded as JSON, or null.
  Future<Map<String, Object?>?> nextFrame({Duration within = const Duration(seconds: 3)}) async {
    final line = await next(within: within);
    if (line == null) return null;
    final json = _tryJson(line);
    return json is Map<String, Object?> ? json : null;
  }

  /// Frames of one type.
  List<Map<String, Object?>> framesOfType(String type) => frames.where((frame) => frame['t'] == type).toList();

  /// Writes one line exactly as given, with no encoder in the way.
  void line(String raw) => write(utf8.encode('$raw\n'));

  /// Writes a JSON object as one line.
  void frame(Map<String, Object?> body, {String? mac}) => line(jsonEncode(<String, Object?>{...body, 'mac': ?mac}));

  /// Writes raw bytes with no newline and no framing at all.
  ///
  /// Swallows the write failure a hung-up subject causes: half these probes are about getting hung
  /// up on, and the uninvited peer crashing is not the result under test.
  void write(List<int> raw) {
    try {
      _socket.add(raw);
    } on Object {
      closedByPeer = true;
    }
  }

  /// Waits for everything written so far to reach the kernel.
  Future<void> flush() async {
    try {
      await _socket.flush();
    } on Object {
      closedByPeer = true;
    }
  }

  Future<void> close() async {
    await _lines.cancel();
    _socket.destroy();
  }

  void _onLine(String line) {
    received.add(line);
    _wake(line);
  }

  void _onDone() {
    closedByPeer = true;
    _wake(null);
  }

  void _wake(String? line) {
    final waiting = _waiting;
    if (waiting == null || waiting.isCompleted) return;
    _waiting = null;
    waiting.complete(line);
  }

  static Object? _tryJson(String line) {
    try {
      return jsonDecode(line);
    } on FormatException {
      return null;
    }
  }
}
