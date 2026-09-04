import 'package:meta/meta.dart';
import 'package:pairlink/src/discovery.dart';
import 'package:pairlink/src/identity.dart';
import 'package:pairlink/src/session_key.dart';

/// Everything the outlet phone needs, in one QR code.
///
/// The QR is the primary pairing path. It carries the outlet phone's address, so no discovery is
/// needed at all, plus a 128-bit secret that never reaches the network and is not guessable. The
/// phone that displays the code is the phone that listens.
///
/// On the fallback code path the panel phone shows four digits, the user types them on the outlet
/// phone, and the outlet phone advertises over mDNS so the panel can find it. Same topology,
/// weaker secret, reported as `PairStrength`.
@immutable
final class PairInvite {
  /// Host of the pairing URI. `<scheme>://pair?...` reads as an action and cannot collide with a
  /// route name.
  static const String host = 'pair';

  /// Creates a [PairInvite].
  const PairInvite({required this.identity, required this.endpoint, required this.secret});

  /// Whose QR this is; [PairIdentity.scheme] is the payload's URI scheme.
  final PairIdentity identity;

  /// Where the outlet phone is listening.
  final PairEndpoint endpoint;

  /// The shared secret.
  final PairSecret secret;

  /// The QR payload.
  Uri toUri() => .new(
    scheme: identity.scheme,
    host: host,
    queryParameters: <String, String>{
      'h': endpoint.host,
      'p': endpoint.port.toString(),
      'k': secret.toBase64Url(),
    },
  );

  /// Parses a scanned payload, or returns null when it is not a pairing URI for [identity].
  ///
  /// Null rather than an exception: a camera reads whatever it is pointed at, and a code from
  /// another application is not an error.
  static PairInvite? tryParse(String raw, {required PairIdentity identity}) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || uri.scheme != identity.scheme || uri.host != host) return null;

    final host_ = uri.queryParameters['h'];
    final port = int.tryParse(uri.queryParameters['p'] ?? '');
    final key = uri.queryParameters['k'];
    if (host_ == null || host_.isEmpty) return null;
    if (port == null || port <= 0 || port > 65535) return null;
    if (key == null || key.isEmpty) return null;

    final PairSecret secret;
    try {
      // Rejects a wrong-length secret as well as bad base64: a short `k=` must not come back
      // labelled `PairStrength.scanned`.
      secret = PairSecret.fromBase64Url(key);
    } on FormatException {
      return null;
    }

    return PairInvite(
      identity: identity,
      endpoint: PairEndpoint(host: host_, port: port),
      secret: secret,
    );
  }
}
