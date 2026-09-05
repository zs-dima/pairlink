import 'dart:async';
import 'dart:io';

import 'package:meta/meta.dart';

/// Where the outlet phone can be reached, and which pairing it belongs to.
@immutable
final class PairEndpoint {
  /// Creates a [PairEndpoint].
  const PairEndpoint({required this.host, required this.port, this.id});

  /// Address on this LAN.
  final String host;

  /// TCP port the outlet phone is listening on.
  final int port;

  /// Public name of the PAIRING this listener is waiting for, or null when it does not say.
  ///
  /// [PairSecret.pairId] derives it, and only a scanned secret has one. It is not a credential
  /// and proves nothing: it lets a phone that remembers a pairing skip the listeners that are
  /// waiting for somebody else, so a wrong guess never costs a stranger one of their five
  /// attempts — and it lets a typed-code search skip the ones it could never satisfy.
  final String? id;

  @override
  int get hashCode => Object.hash(host, port, id);

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is PairEndpoint && other.host == host && other.port == port && other.id == id;

  @override
  String toString() => id == null ? '$host:$port' : '$host:$port#$id';
}

/// Publishes where the outlet phone can be reached.
///
/// Needed only on the code path: a QR carries the address itself, so a session paired by scanning
/// never advertises and never browses.
///
/// mDNS / DNS-SD through the system responder (`NsdManager`, Bonjour) needs no entitlement on
/// either platform. UDP broadcast works on Android and desktop, but since iOS 14.5 it requires
/// `com.apple.developer.networking.multicast`, granted per application and unavailable to
/// development builds, so a beacon is a fallback rather than the primary path.
abstract interface class PairAdvertiser {
  /// Starts publishing [endpoint].
  Future<void> start(PairEndpoint endpoint);

  /// Stops publishing and releases the platform resources.
  Future<void> stop();
}

/// Finds outlet phones on this LAN.
///
/// See [PairAdvertiser] for why there is more than one implementation.
abstract interface class PairDiscovery {
  /// Endpoints as they are found. May repeat: a service that re-announces is normal, and the
  /// caller de-duplicates on [PairEndpoint] equality.
  Stream<PairEndpoint> get endpoints;

  /// Starts looking. An advertisement says an outlet phone is here and, when it is waiting for a
  /// remembered pairing, which pairing that is ([PairEndpoint.id]) — never anything about the
  /// secret. The caller filters on that if it can and lets the handshake decide the rest.
  Future<void> start();

  /// Stops looking.
  Future<void> stop();

  /// The first match, or null when nothing answers within [timeout].
  Future<PairEndpoint?> first({Duration timeout});
}

/// This device's address on the local network, or null when it is not on one.
///
/// Loopback and link-local are skipped: an invitation advertising 127.0.0.1 tells the peer to
/// connect to itself.
Future<String?> localAddress() async {
  final interfaces = await NetworkInterface.list(type: .IPv4, includeLoopback: false);
  return pickPairingAddress([
    for (final interface in interfaces)
      (name: interface.name, addresses: [for (final address in interface.addresses) address.address]),
  ]);
}

/// Chooses the address the QR should carry, from every interface the OS reports.
///
/// "First non-loopback IPv4" is not enough: Android routinely has Wi-Fi and cellular up at once
/// and enumeration order is undefined, so the QR could carry an `rmnet` carrier address or a `tun`
/// VPN address no LAN peer can reach. Carrier-grade NAT (100.64.0.0/10) is excluded outright and
/// interfaces are ranked by name, Wi-Fi-shaped first and tunnel or cellular last. Pure and
/// injectable, so the ranking is testable without real interfaces.
String? pickPairingAddress(List<({String name, List<String> addresses})> interfaces) {
  int rank(String name) {
    final lower = name.toLowerCase();
    // Wi-Fi / LAN: Android `wlan*`/`ap*`, iOS `en*`, desktops `eth*`/`wi-fi`/`wlp*`.
    for (final prefix in const ['wlan', 'ap', 'en', 'eth', 'wlp', 'wi-fi', 'wifi']) {
      if (lower.startsWith(prefix)) return 0;
    }
    // Tunnels and cellular: rarely reachable by a LAN peer, but kept as a last resort so a device
    // with no better interface still yields an address.
    for (final prefix in const ['tun', 'tap', 'utun', 'ipsec', 'ppp', 'rmnet', 'pdp', 'ccmni', 'vpn']) {
      if (lower.startsWith(prefix)) return 2;
    }
    return 1;
  }

  bool isCandidate(String address) {
    if (address.startsWith('127.')) return false;
    if (address.startsWith('169.254.')) return false;
    // Carrier-grade NAT, 100.64.0.0/10: a cellular address no peer can ever connect to.
    if (RegExp(r'^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.').hasMatch(address)) return false;
    return true;
  }

  String? best;
  var bestRank = 3;
  for (final interface in interfaces) {
    final r = rank(interface.name);
    if (r >= bestRank) continue;
    for (final address in interface.addresses) {
      if (isCandidate(address)) {
        best = address;
        bestRank = r;
        break;
      }
    }
  }
  return best;
}
