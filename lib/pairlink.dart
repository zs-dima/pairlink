/// Local-network pairing between two devices: one listens, the other connects.
///
/// Pure Dart: no Flutter, no plugins, so frame validation, replay rejection and proof of
/// possession of the pairing secret behave identically on both devices and on CI.
library;

export 'src/discovery.dart';
export 'src/frames.dart';
export 'src/identity.dart';
export 'src/invite.dart';
export 'src/session.dart';
export 'src/session_key.dart';
export 'src/transport.dart';
