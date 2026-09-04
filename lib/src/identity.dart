import 'package:meta/meta.dart';

/// The application's identity on the wire.
///
/// Two devices pair only when both carry the same [brand]: it is half of the HKDF `info` string,
/// so applications built on this protocol each get their own key space. None of the three values
/// is a secret; all three ship in the binary.
@immutable
final class PairIdentity {
  /// Creates a [PairIdentity].
  const PairIdentity({required this.brand, required this.serviceType, required this.scheme});

  /// Half of the HKDF `info` string (`<brand>-pairlink-v<version>`).
  final String brand;

  /// The mDNS service type both devices agree on, `_name._tcp`.
  ///
  /// RFC 6763: the name is at most 15 characters, lower case, with no underscores beyond the two
  /// the format requires.
  final String serviceType;

  /// URI scheme of the QR payload: the application's own deep-link scheme, so a device that scans
  /// the code with its system camera opens the application rather than a browser.
  final String scheme;

  @override
  int get hashCode => Object.hash(brand, serviceType, scheme);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PairIdentity && brand == other.brand && serviceType == other.serviceType && scheme == other.scheme;

  @override
  String toString() => 'PairIdentity($brand, $serviceType, $scheme)';
}
