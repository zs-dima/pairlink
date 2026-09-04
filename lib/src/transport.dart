import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pairlink/src/frames.dart';

/// The longest line the framer will assemble before giving up on a peer.
///
/// Without a cap, a peer that sends bytes and never a newline is an out-of-memory kill from one
/// connection. Real frames are a few hundred bytes.
const int kMaxFrameBytes = 64 * 1024;

/// A bidirectional stream of frames, with no opinion about how they travel.
///
/// The protocol logic is written against this, not against `Socket`, so it can be tested with two
/// transports wired to each other in memory. [SocketTransport] is the only part needing a real
/// socket.
abstract interface class PairTransport {
  /// Frames arriving from the peer. Closes when the peer goes away.
  Stream<ReceivedFrame> get frames;

  /// Whether the connection is still usable.
  bool get isOpen;

  /// Sends one frame, signed with [mac] when the session is authenticated.
  void send(PairFrame frame, {String? mac});

  /// Closes the connection. Safe to call twice.
  Future<void> close();
}

/// [PairTransport] over a TCP socket, JSON lines.
final class SocketTransport implements PairTransport {
  /// Wraps an established [socket].
  SocketTransport(this._socket) {
    _subscription = _socket
        .cast<List<int>>()
        .transform(const _BoundedLineSplitter())
        .listen(_onLine, onError: _onError, onDone: _onDone, cancelOnError: true);
    // Where an asynchronous write failure lands: `IOSink.writeln` does not throw on a dead peer,
    // it fails on the sink's own stream, so the `try` in [send] catches nothing.
    _socket.done.then<void>((_) => close().ignore(), onError: (Object _) => close().ignore());
  }

  final Socket _socket;
  final StreamController<ReceivedFrame> _controller = StreamController<ReceivedFrame>();
  StreamSubscription<String>? _subscription;
  bool _closed = false;

  /// The peer's address, for diagnostics. Not intended for display.
  String get peer => '${_socket.remoteAddress.address}:${_socket.remotePort}';

  @override
  Stream<ReceivedFrame> get frames => _controller.stream;

  @override
  bool get isOpen => !_closed;

  @override
  void send(PairFrame frame, {String? mac}) {
    if (_closed) return;
    // A synchronous throw once the peer is gone is ordinary mid-session, so it closes the
    // transport rather than propagating.
    try {
      _socket.writeln(FrameCodec.encode(frame, mac: mac));
    } on Object {
      close().ignore();
    }
  }

  /// Tears the connection down. Never waits on the peer for anything.
  ///
  /// `destroy()` rather than `await close()`, and the subscription cancelled without awaiting and
  /// only after the socket is destroyed: both `Socket.close()` and `cancel()` on a socket-backed
  /// stream complete only once the far end hangs up, so awaiting either hangs this method.
  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;

    try {
      _socket.destroy();
    } on Object {
      // Already gone; nothing to do.
    }
    _subscription?.cancel().ignore();
    _subscription = null;
    // Also not awaited: `StreamController.close()` completes only once the done event has been
    // delivered, so on a controller nobody listened to it never completes at all. That is the
    // ordinary case for a connection refused before the session subscribed.
    if (!_controller.isClosed) _controller.close().ignore();
  }

  void _onLine(String line) {
    if (line.trim().isEmpty) return;
    try {
      _controller.add(FrameCodec.decode(line));
    } on FrameError catch (error) {
      // A malformed frame is data, not a crash: surfaced on the stream so the session can answer
      // with a `reject` and decide whether to keep the connection.
      if (!_controller.isClosed) _controller.addError(error);
    }
  }

  /// The peer hung up cleanly.
  ///
  /// Marks the transport closed rather than only closing the frame stream: a peer-initiated FIN
  /// must leave `isOpen` false, or the session holds a dead socket with no timeout anywhere and
  /// answers every reconnection `alreadyPaired`.
  void _onDone() {
    if (!_controller.isClosed) _controller.close().ignore();
    close().ignore();
  }

  void _onError(Object error, StackTrace stackTrace) {
    if (!_controller.isClosed) _controller.addError(error, stackTrace);
    close().ignore();
  }
}

/// Splits a byte stream into UTF-8 lines, refusing to buffer more than [kMaxFrameBytes] bytes.
///
/// The cap counts bytes before any UTF-8 decode: counting decoded UTF-16 code units would let a
/// peer sending three-byte characters buffer roughly three times the intended cap.
///
/// An over-cap line is a flood, so it surfaces on the transport's error path and closes the
/// connection. A malformed but bounded line is caught in `_onLine` and surfaced as data instead,
/// so the connection survives mid-session garbage.
class _BoundedLineSplitter extends StreamTransformerBase<List<int>, String> {
  static const int _lf = 0x0A;

  static const int _cr = 0x0D;

  const _BoundedLineSplitter();

  @override
  Stream<String> bind(Stream<List<int>> stream) {
    final buffer = BytesBuilder(copy: true);

    return stream.transform(
      StreamTransformer<List<int>, String>.fromHandlers(
        handleData: (chunk, sink) {
          var start = 0;
          while (start < chunk.length) {
            final newline = chunk.indexOf(_lf, start);
            final end = newline == -1 ? chunk.length : newline;
            if (end > start) buffer.add(chunk.sublist(start, end));

            if (buffer.length >= kMaxFrameBytes) {
              buffer.clear();
              sink.addError(const FrameError(.malformed, 'frame exceeded $kMaxFrameBytes bytes'));
              return;
            }
            if (newline == -1) return;

            var bytes = buffer.takeBytes();
            // CRLF, from a peer that terminates with it. A literal CR inside a JSON string is
            // invalid JSON anyway, so only the terminator is stripped.
            if (bytes.isNotEmpty && bytes.last == _cr) bytes = bytes.sublist(0, bytes.length - 1);
            sink.add(const Utf8Decoder(allowMalformed: true).convert(bytes));
            start = newline + 1;
          }
        },
        handleDone: (sink) {
          if (buffer.isNotEmpty) {
            sink.add(const Utf8Decoder(allowMalformed: true).convert(buffer.takeBytes()));
          }
          sink.close();
        },
      ),
    );
  }
}
