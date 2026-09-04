import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

/// The QR carries whatever [pickPairingAddress] chooses. Interface enumeration order is arbitrary,
/// so a plain "first non-loopback IPv4" rule picks the cellular or VPN address as readily as the
/// Wi-Fi one, and the panel phone then cannot reach an outlet phone that is right there.
void main() {
  test('Wi-Fi beats cellular regardless of enumeration order', () {
    final picked = pickPairingAddress([
      (name: 'rmnet0', addresses: ['10.213.44.7']),
      (name: 'wlan0', addresses: ['192.168.1.23']),
    ]);

    expect(picked, equals('192.168.1.23'));
  });

  test('Wi-Fi beats a VPN tunnel that enumerates first', () {
    final picked = pickPairingAddress([
      (name: 'tun0', addresses: ['10.8.0.2']),
      (name: 'wlan0', addresses: ['192.168.1.23']),
    ]);

    expect(picked, equals('192.168.1.23'));
  });

  test('carrier-grade NAT is excluded outright, not merely deprioritised', () {
    // 100.64.0.0/10 is unreachable from any peer by definition; an interface holding only such an
    // address must yield to anything else, and on its own must yield null.
    final picked = pickPairingAddress([
      (name: 'rmnet_data1', addresses: ['100.72.11.5']),
      (name: 'ccmni0', addresses: ['100.127.1.1']),
    ]);

    expect(picked, isNull);
  });

  test('100.x outside the CGNAT block is an ordinary address', () {
    final picked = pickPairingAddress([
      (name: 'eth0', addresses: ['100.128.0.1']),
    ]);

    expect(picked, equals('100.128.0.1'));
  });

  test('an unknown interface name still wins over a tunnel', () {
    final picked = pickPairingAddress([
      (name: 'utun3', addresses: ['10.8.0.2']),
      (name: 'bridge100', addresses: ['192.168.64.1']),
    ]);

    expect(picked, equals('192.168.64.1'));
  });

  test('a tunnel is still better than nothing', () {
    final picked = pickPairingAddress([
      (name: 'tun0', addresses: ['10.8.0.2']),
    ]);

    expect(picked, equals('10.8.0.2'));
  });

  test('link-local and loopback never make it into a QR', () {
    final picked = pickPairingAddress([
      (name: 'wlan0', addresses: ['169.254.12.1', '127.0.0.1']),
    ]);

    expect(picked, isNull);
  });
}
