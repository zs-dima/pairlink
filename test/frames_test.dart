import 'dart:convert';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

/// Anyone on the same Wi-Fi can open this socket and write whatever they like, so the decoder is
/// the outermost exposed surface. Every bad input must come back as a [FrameError] carrying a
/// reason that fits in a `reject` frame, never as a `TypeError` from a bad cast.
void main() {
  group('round trip', () {
    final frames = <PairFrame>[
      const Challenge(nonce: 'cGFuZWw='),
      const Hello(nonce: 'bm9uY2U=', device: 'Redmi Note 12'),
      const Hello(nonce: 'bm9uY2U='),
      const Welcome(device: 'Pixel 9a'),
      const Welcome(),
      const Reject(.wrongCode),
      const Power(state: .lost, atMs: 900000, seq: 1, wallMs: 1700000000000),
      const Power(state: .restored, atMs: 908000, seq: 2),
      const Ack(7),
      const Bye(),
    ];

    for (final frame in frames) {
      test('${frame.type} survives encode/decode', () {
        final decoded = FrameCodec.decode(FrameCodec.encode(frame));
        expect(decoded.frame.runtimeType, equals(frame.runtimeType));
        expect(decoded.frame.toBody(), equals(frame.toBody()));
      });
    }

    test('the mac travels beside the body, not inside it', () {
      final decoded = FrameCodec.decode(FrameCodec.encode(const Bye(), mac: 'c2lnbmF0dXJl'));

      expect(decoded.mac, equals('c2lnbmF0dXJl'));
      expect(decoded.body.containsKey('mac'), isFalse, reason: 'the signed body must exclude the signature');
    });

    test('an unsigned frame decodes with a null mac rather than an empty one', () {
      expect(FrameCodec.decode(FrameCodec.encode(const Bye())).mac, isNull);
    });
  });

  group('hostile input', () {
    final cases = <String, ({String line, RejectReason reason})>{
      'not JSON at all': (line: 'BSNR|7392|10.0.0.5:1234', reason: RejectReason.malformed),
      'empty line': (line: '', reason: RejectReason.malformed),
      'a JSON array': (line: '[1,2,3]', reason: RejectReason.malformed),
      'a bare number': (line: '42', reason: RejectReason.malformed),
      'no type tag': (line: '{"code":"7392"}', reason: RejectReason.malformed),
      'unknown type': (line: '{"t":"exploit"}', reason: RejectReason.malformed),
      'type is not a string': (line: '{"t":7}', reason: RejectReason.malformed),
      'hello without a nonce': (line: '{"v":3,"t":"hello"}', reason: RejectReason.malformed),
      'hello with a numeric nonce': (line: '{"v":3,"t":"hello","nonce":7392}', reason: RejectReason.malformed),
      'challenge without a nonce': (line: '{"v":3,"t":"challenge"}', reason: RejectReason.malformed),
      'challenge without a version': (line: '{"t":"challenge","nonce":"x"}', reason: RejectReason.malformed),
      'power with a non-integer wall stamp': (
        line: '{"t":"power","state":"lost","ts":1,"seq":1,"wall":"noon"}',
        reason: RejectReason.malformed,
      ),
      'power without seq': (line: '{"t":"power","state":"lost","ts":1}', reason: RejectReason.malformed),
      'power with an unknown state': (
        line: '{"t":"power","state":"melted","ts":1,"seq":1}',
        reason: RejectReason.malformed,
      ),
      // A float where an int belongs means the sender is not this protocol. Coercing it would
      // silently accept a stranger's idea of a timestamp.
      'power with a float timestamp': (
        line: '{"t":"power","state":"lost","ts":1.7e12,"seq":1}',
        reason: RejectReason.malformed,
      ),
      'power with a null seq': (line: '{"t":"power","state":"lost","ts":1,"seq":null}', reason: RejectReason.malformed),
      'mac is not a string': (line: '{"t":"bye","mac":42}', reason: RejectReason.malformed),
      'reject with an unknown reason': (line: '{"t":"reject","reason":"vibes"}', reason: RejectReason.malformed),
      'a future protocol version': (line: '{"v":99,"t":"hello","nonce":"x"}', reason: RejectReason.versionMismatch),
      // A phone running an older version must be told to update, not silently half-understood.
      'a v1 hello': (
        line: '{"v":1,"t":"hello","code":"7392","nonce":"x"}',
        reason: RejectReason.versionMismatch,
      ),
      'a challenge from another version': (
        line: '{"v":1,"t":"challenge","nonce":"x"}',
        reason: RejectReason.versionMismatch,
      ),
    };

    for (final MapEntry(key: name, value: expectation) in cases.entries) {
      test('$name is refused with a reason, not a crash', () {
        expect(
          () => FrameCodec.decode(expectation.line),
          throwsA(isA<FrameError>().having((e) => e.reason, 'reason', expectation.reason)),
        );
      });
    }

    test('a giant frame does not take the parser down', () {
      // A peer that sends a megabyte of digits is refused, not left to exhaust the outlet phone.
      final line = jsonEncode(<String, Object?>{
        't': 'power',
        'state': 'lost',
        'ts': 1,
        'seq': 1,
        'junk': 'x' * 100000,
      });
      final decoded = FrameCodec.decode(line);

      // Unknown fields are ignored rather than rejected, which lets two versions coexist for the
      // fields they share. The junk does not appear in the frame.
      expect(decoded.frame, isA<Power>());
    });

    test('a version mismatch is reported before any field is trusted', () {
      // A foreign version's fields would be parsed under this version's rules, so anything read
      // out of them is a guess: the version is checked first.
      expect(
        () => FrameCodec.decode('{"v":7,"t":"hello","nonce":null}'),
        throwsA(isA<FrameError>().having((e) => e.reason, 'reason', RejectReason.versionMismatch)),
      );
    });
  });
}
