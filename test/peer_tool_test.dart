@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:pairlink/pairlink.dart';
import 'package:test/test.dart';

/// `tool/peer.dart outlet --code`: the computer plays an outlet a panel pairs with by the digits it shows, so an
/// app's typed-code branch can be walked with one phone. A panel with the same code pairs; the tool reports it.
void main() {
  test('an outlet started with --code pairs with a panel holding the same code', () async {
    const identity = PairIdentity(brand: 'peertest', serviceType: '_peertest._tcp', scheme: 'peertest');
    final tool = await Process.start(Platform.resolvedExecutable, <String>[
      'run',
      'tool/peer.dart',
      'outlet',
      '--brand',
      'peertest',
      '--code',
      '4821',
      '--device',
      'window-origin',
      '--script',
      'wait;quit',
    ]);
    addTearDown(tool.kill);
    final lines = tool.stdout.transform(utf8.decoder).transform(const LineSplitter()).asBroadcastStream();
    final listening = await lines
        .firstWhere((line) => line.contains('listening on'))
        .timeout(const Duration(seconds: 60));
    final port = int.parse(listening.split(':').last.trim());

    final panel = PanelSession(identity: identity, secret: PairSecret.code('4821'), device: 'main');
    addTearDown(panel.close);
    final paired = panel.events.firstWhere((event) => event is PanelPaired);
    final attached = await panel.attach(SocketTransport(await Socket.connect(InternetAddress.loopbackIPv4, port)));
    expect(attached, isTrue);
    final event = await paired.timeout(const Duration(seconds: 10)) as PanelPaired;
    expect(event.device, 'window-origin');
    await lines.firstWhere((line) => line.contains('paired with')).timeout(const Duration(seconds: 10));
  }, timeout: const Timeout(Duration(minutes: 2)));
}
