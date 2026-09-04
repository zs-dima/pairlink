import 'dart:async';
import 'dart:io';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

/// The protocol itself is proven in `session_test.dart` over in-memory transports. This file covers
/// only what needs a real socket: frames surviving TCP's freedom to split and coalesce writes, a
/// peer disappearing as an ordinary end rather than a crash, and a flood without a newline failing
/// to exhaust the outlet phone.
void main() {
  late ServerSocket server;

  setUp(() async => server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0));
  tearDown(() async => server.close());

  /// A connected pair of transports over real loopback TCP.
  Future<({SocketTransport client, SocketTransport host, Socket rawClient})> connect() async {
    final accepted = server.first;
    // The transport takes ownership of the socket and closes it; the analyzer cannot see that.
    // ignore: close_sinks
    final rawClient = await Socket.connect(InternetAddress.loopbackIPv4, server.port);
    final host = SocketTransport(await accepted);
    final client = SocketTransport(rawClient);
    // Both are closed here rather than by each test: half of these tests exist because one side
    // went away, and a teardown that assumed a tidy exit would hide that.
    addTearDown(host.close);
    addTearDown(client.close);
    return (client: client, host: host, rawClient: rawClient);
  }

  test('a frame written on one side arrives on the other', () async {
    final link = await connect();
    final received = link.host.frames.first;

    link.client.send(const Power(state: .lost, atMs: 1700000000000, seq: 1), mac: 'c2ln');

    final frame = await received.timeout(const Duration(seconds: 5));
    expect(frame.frame, isA<Power>());
    expect((frame.frame as Power).seq, equals(1));
    expect(frame.mac, equals('c2ln'));
  });

  test('frames survive being coalesced into one packet', () async {
    // TCP is a byte stream, not a message stream. Three quick writes routinely arrive as one read,
    // and a framer that assumes otherwise works on a desk and fails on a busy network.
    final link = await connect();
    final received = link.host.frames.take(3).toList();

    for (var seq = 1; seq <= 3; seq++) {
      link.client.send(Power(state: .lost, atMs: seq * 1000, seq: seq));
    }

    final frames = await received.timeout(const Duration(seconds: 5));
    expect(frames.map((f) => (f.frame as Power).seq), equals(<int>[1, 2, 3]));
  });

  test('a frame split across packets is reassembled', () async {
    final link = await connect();
    final received = link.host.frames.first;

    // Half a line, a pause long enough to guarantee two reads, then the rest.
    final line = FrameCodec.encode(const Ack(42)).codeUnits;
    final half = line.length ~/ 2;
    link.rawClient.add(line.take(half).toList());
    await link.rawClient.flush();
    await Future<void>.delayed(const Duration(milliseconds: 50));
    link.rawClient
      ..add(line.skip(half).toList())
      ..writeln();

    final frame = await received.timeout(const Duration(seconds: 5));
    expect((frame.frame as Ack).seq, equals(42));
  });

  test('the peer hanging up ends the stream instead of throwing', () async {
    final link = await connect();
    final done = Completer<void>();
    final subscription = link.host.frames.listen(null, onDone: done.complete);
    addTearDown(subscription.cancel);

    await link.client.close();

    await expectLater(done.future.timeout(const Duration(seconds: 5)), completes);
  });

  test('sending after the peer is gone does not throw', () async {
    // Mid-session this is normal: the user walked out of Wi-Fi range holding the panel phone.
    final link = await connect();
    await link.host.close();
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(() => link.client.send(const Bye()), returnsNormally);
  });

  test('a flood with no newline is refused, and the flooder is hung up on', () async {
    // A stranger on the LAN can open this socket and never write a newline. With no cap that is an
    // out-of-memory kill on the outlet phone, from a single peer. The cap turns it into a refusal,
    // and the connection goes with it.
    final link = await connect();
    final error = link.host.frames.first.then<Object?>((_) => null).onError<Object>((e, _) => e);
    // The hang-up as the flooder sees it: its inbound stream ends. Read side, not write side, since
    // whether a write into a destroyed peer reports failure is the operating system's socket buffer
    // talking and Windows loopback swallows megabytes. (`rawClient` is already listened to by the
    // client transport, so this goes through that.)
    //
    // `handleError` matters: the host hangs up with `destroy()`, and destroying a socket with bytes
    // still unread in its receive queue sends RST instead of FIN, so the flooder may read
    // `Connection reset by peer` rather than a clean close, and a bare `drain()` would rethrow it.
    // Either teardown means hung up on.
    final hungUp = link.client.frames.handleError((Object _) {}).drain<void>();

    // The flooder's own write failure is asynchronous: `IOSink.write` fails on the sink's stream,
    // not at the call, so it needs a handler or it escapes the test as an uncaught error.
    unawaited(link.rawClient.done.then<void>((_) {}, onError: (Object _) {}));

    var refused = false;
    unawaited(error.then((_) => refused = true));
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (!refused && DateTime.now().isBefore(deadline)) {
      try {
        link.rawClient.write('x' * 8192);
        await link.rawClient.flush();
      } on Object {
        break;
      }
    }

    expect(await error.timeout(const Duration(seconds: 10)), isA<FrameError>());
    expect(link.host.isOpen, isFalse, reason: 'the phone in the outlet drops a peer that floods it');
    await expectLater(
      hungUp.timeout(const Duration(seconds: 10)),
      completes,
      reason: 'a peer that floods gets hung up on, not merely ignored',
    );
  });

  test('the frame cap counts bytes, so a multibyte flood cannot overshoot it threefold', () async {
    // Counting UTF-16 code units against `kMaxFrameBytes` would let a peer sending three-byte
    // characters buffer ~192 KiB before a 64 KiB cap trips. The count is bytes, taken before any
    // decode.
    final link = await connect();
    final error = link.host.frames.first.then<Object?>((_) => null).onError<Object>((e, _) => e);
    unawaited(link.rawClient.done.then<void>((_) {}, onError: (Object _) {}));

    // ~80 KiB of three-byte euro signs, no newline: past the byte cap, and far under what a
    // code-unit cap would need (~192 KiB of these) to fire.
    final flood = '€' * (kMaxFrameBytes ~/ 2);
    try {
      link.rawClient.write(flood);
      await link.rawClient.flush();
    } on Object {
      // The refusal can race the write; either way the assertion below is the contract.
    }

    expect(await error.timeout(const Duration(seconds: 10)), isA<FrameError>());
    expect(link.host.isOpen, isFalse);
  });

  test('a malformed line is an error on the stream, not a dead connection', () async {
    final link = await connect();
    final errors = <Object>[];
    final frames = <ReceivedFrame>[];
    final subscription = link.host.frames.listen(frames.add, onError: errors.add);
    addTearDown(subscription.cancel);

    link.rawClient.writeln('{"t":"nonsense"}');
    await link.rawClient.flush();
    await Future<void>.delayed(const Duration(milliseconds: 100));
    link.client.send(const Ack(1));
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(errors.single, isA<FrameError>());
    expect(frames.single.frame, isA<Ack>(), reason: 'one bad line must not cost the whole session');
  });
}
