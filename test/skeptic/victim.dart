// Shared subject harness, imported by the skeptic tests; its members are public by design.
// ignore_for_file: avoid-top-level-members-in-tests

import 'dart:async';
import 'dart:io';

import 'package:pairlink/pairlink.dart';

import '../fixture.dart';

/// The outlet phone as an application runs it.
///
/// The accept loop mirrors a real service: each accepted socket is handed to the session and the
/// per-connection future is not awaited, so accepting resumes immediately. Serialising it here
/// would invent a defence the production code does not have.
final class OutletVictim {
  const OutletVictim._(this._server, this.session, this.events, this._accepts);

  final ServerSocket _server;

  final StreamSubscription<Socket> _accepts;

  /// The session under probe.
  final OutletSession session;

  /// Everything it reported.
  final List<OutletEvent> events;

  /// Where the uninvited peer connects.
  int get port => _server.port;

  /// Refusals so far, newest last.
  List<OutletRejectedPeer> get refusals => events.whereType<OutletRejectedPeer>().toList();

  /// Binds a port and starts accepting the way a real service does.
  static Future<OutletVictim> start(PairSecret secret, {String? device, AttemptLimiter? limiter}) async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final session = OutletSession(identity: kTestIdentity, secret: secret, device: device, limiter: limiter);
    final events = <OutletEvent>[];
    // ignore: avoid-unassigned-stream-subscriptions, dies with the session broadcast in stop().
    session.events.listen(events.add);
    // ignore: cancel_subscriptions, cancelled in stop(); it lives as long as the subject does.
    final accepts = server.listen((socket) {
      // Fire and forget, as the production accept loop does.
      unawaited(session.attach(SocketTransport(socket)));
    });
    return OutletVictim._(server, session, events, accepts);
  }

  Future<void> stop() async {
    await _accepts.cancel();
    await _server.close();
    await session.close();
  }
}

/// A hostile server: whatever the panel phone connected to, it is not the outlet phone.
///
/// Reachable in the field two ways. On the code path the four digits are advertised in the mDNS TXT
/// record, so anyone on the Wi-Fi can publish the same label and race the real outlet phone for the
/// panel's connection. On any path, a router the user does not control can answer instead.
final class HostileServer {
  const HostileServer._(this._server, this.sessions);

  final ServerSocket _server;

  /// Sockets as the subject connects them.
  final Stream<Socket> sessions;

  /// Where the subject connects.
  int get port => _server.port;

  /// Binds a port and accepts connections, exposing the raw socket of each.
  ///
  /// Broadcast rather than a controller of its own: each accepted socket is handed straight to the
  /// probe script, which owns it and destroys it.
  static Future<HostileServer> start() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    return HostileServer._(server, server.asBroadcastStream());
  }

  Future<void> stop() => _server.close();
}

/// The panel phone as an application runs it: it connects, and it owns the replay guard.
final class PanelVictim {
  const PanelVictim._(this.session, this.events);

  /// The session under probe.
  final PanelSession session;

  /// Everything it reported.
  final List<PanelEvent> events;

  /// Power events that reached the map.
  List<PanelPowerEvent> get delivered => events.whereType<PanelPowerEvent>().toList();

  /// Connects a fresh [PanelSession] to [port] and returns once the handshake settles.
  static Future<({PanelVictim victim, bool paired})> connect(int port, PairSecret secret, {String? device}) async {
    final session = PanelSession(identity: kTestIdentity, secret: secret, device: device);
    final events = <PanelEvent>[];
    // ignore: avoid-unassigned-stream-subscriptions, dies with the session broadcast in stop().
    session.events.listen(events.add);
    // The transport takes ownership of the socket and closes it; the analyzer cannot see that.
    // ignore: close_sinks
    final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
    final paired = await session.attach(SocketTransport(socket));
    return (victim: PanelVictim._(session, events), paired: paired);
  }

  Future<void> stop() => session.close();
}
