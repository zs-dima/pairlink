// ignore_for_file: avoid_print

import 'dart:io';

import 'package:pairlink/pairlink.dart';

/// Both phones in one process, over loopback: the outlet listens, the panel connects, one power
/// event travels signed and in order.
Future<void> main() async {
  const identity = PairIdentity(brand: 'example', serviceType: '_example._tcp', scheme: 'example');

  // Outlet phone: generate the secret and listen.
  final secret = PairSecret.generate();
  final outlet = OutletSession(identity: identity, secret: secret, device: 'outlet');
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final accepting = server.listen((socket) => outlet.attach(SocketTransport(socket)));

  // The QR the outlet phone would show.
  final invite = PairInvite(
    identity: identity,
    endpoint: PairEndpoint(host: server.address.address, port: server.port),
    secret: secret,
  );
  print('QR payload: ${invite.toUri()}');

  // Panel phone: scan, connect, listen.
  final scanned = PairInvite.tryParse(invite.toUri().toString(), identity: identity)!;
  final panel = PanelSession(identity: identity, secret: scanned.secret, device: 'panel');
  final events = panel.events.listen((event) => print('panel: ${event.runtimeType}'));
  final paired = await panel.attach(
    SocketTransport(await Socket.connect(scanned.endpoint.host, scanned.endpoint.port)),
  );
  print('paired: $paired (${scanned.secret.strength.name})');

  outlet.report(.lost);
  await Future<void>.delayed(const Duration(milliseconds: 100));

  await events.cancel();
  await panel.close();
  await outlet.close();
  await accepting.cancel();
  await server.close();
}
