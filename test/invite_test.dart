import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

import 'fixture.dart';

/// The QR payload is the primary pairing path, so its parser is pointed at whatever a camera
/// happens to see. Every rejection below is something a lens really lands on (a Wi-Fi QR, a URL, a
/// product barcode), and none of them may reach the user as an exception.
void main() {
  const endpoint = PairEndpoint(host: '192.168.88.24', port: 41235);

  group('PairInvite', () {
    test('round-trips through the QR payload', () {
      final invite = PairInvite(identity: kTestIdentity, endpoint: endpoint, secret: PairSecret.generate());

      final scanned = PairInvite.tryParse(invite.toUri().toString(), identity: kTestIdentity);

      expect(scanned?.endpoint, equals(endpoint));
      expect(scanned?.secret.toBase64Url(), equals(invite.secret.toBase64Url()));
      expect(scanned?.secret.strength, equals(PairStrength.scanned));
    });

    test('the payload opens this app, not a browser', () {
      final uri = PairInvite(identity: kTestIdentity, endpoint: endpoint, secret: PairSecret.generate()).toUri();

      expect(uri.scheme, equals(kTestIdentity.scheme));
      expect(uri.host, equals('pair'));
    });

    test('the scanned secret really is the one that pairs', () {
      final invite = PairInvite(identity: kTestIdentity, endpoint: endpoint, secret: PairSecret.generate());
      final scanned = PairInvite.tryParse(invite.toUri().toString(), identity: kTestIdentity)!;
      const frame = <String, Object?>{'t': 'bye'};

      final panelKey = invite.secret.deriveKey(brand: kTestIdentity.brand, hostNonce: 'cA==', guestNonce: 'bw==');
      final outletKey = scanned.secret.deriveKey(brand: kTestIdentity.brand, hostNonce: 'cA==', guestNonce: 'bw==');

      expect(panelKey.verify(frame, outletKey.sign(frame)), isTrue);
    });

    test('survives the base64url characters that break a naive parser', () {
      // The payload uses base64url rather than base64: a `+` or `/` in a query string is a
      // different value by the time it comes back.
      for (var attempt = 0; attempt < 200; attempt++) {
        final invite = PairInvite(identity: kTestIdentity, endpoint: endpoint, secret: PairSecret.generate());
        final scanned = PairInvite.tryParse(invite.toUri().toString(), identity: kTestIdentity);

        expect(scanned?.secret.toBase64Url(), equals(invite.secret.toBase64Url()), reason: invite.toUri().toString());
      }
    });

    final rejected = <String, String>{
      'a web address': 'https://example.com/pair?h=1&p=2&k=3',
      'a Wi-Fi QR code': 'WIFI:T:WPA;S:HomeNet;P:hunter2;;',
      'plain text': 'Kitchen counter',
      'empty': '',
      'our scheme but another action': 'pltest://latency?h=10.0.0.1&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA==',
      'no address': 'pltest://pair?p=41235&k=AAAAAAAAAAAAAAAAAAAAAA',
      'no port': 'pltest://pair?h=10.0.0.1&k=AAAAAAAAAAAAAAAAAAAAAA',
      'no key': 'pltest://pair?h=10.0.0.1&p=41235',
      'port is not a number': 'pltest://pair?h=10.0.0.1&p=telnet&k=AAAAAAAAAAAAAAAAAAAAAA',
      'port out of range': 'pltest://pair?h=10.0.0.1&p=70000&k=AAAAAAAAAAAAAAAAAAAAAA',
      'port zero': 'pltest://pair?h=10.0.0.1&p=0&k=AAAAAAAAAAAAAAAAAAAAAA',
      'empty address': 'pltest://pair?h=&p=41235&k=AAAAAAAAAAAAAAAAAAAAAA',
      'key is not base64': 'pltest://pair?h=10.0.0.1&p=41235&k=!!!!',
    };

    for (final MapEntry(key: name, value: payload) in rejected.entries) {
      test('$name is not a pairing code', () {
        expect(PairInvite.tryParse(payload, identity: kTestIdentity), isNull);
      });
    }
  });
}
