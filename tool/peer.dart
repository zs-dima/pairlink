// A command-line tool: printing is its interface.
// ignore_for_file: avoid_print

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:pairlink/pairlink.dart';

/// The second phone, played by this computer — so a pairing app can be walked with ONE phone.
///
/// ```sh
/// # The phone is the PANEL: this computer listens, the phone dials it.
/// dart run tool/peer.dart outlet --brand breakersonar --adb --open
///
/// # The phone is the OUTLET: it shows a QR; this computer dials the invite in it.
/// python tool/phone_invite.py > invite.txt   # the QR on the phone's screen
/// dart run tool/peer.dart panel --brand breakersonar --adb --invite-file invite.txt
/// ```
///
/// `--adb` needs no shared network: `adb reverse` (outlet) or `adb forward` (panel) carries the
/// socket over USB, and the invite names 127.0.0.1. Without it the invite names this computer's
/// first LAN address, and both must be on one network.
///
/// Commands, from `--script "a; b; c"` or one per line on stdin: `wait` (until paired), `sleep <s>`,
/// `lost`, `restored` (outlet only), `share <key> <value>`, `signal <name>`, `quit`. A value is JSON
/// when it parses (`true`, `12`), a string otherwise. Every event is one line on stdout, so a script
/// can wait for it.
///
/// It speaks the protocol by being `pairlink` itself — the same frames, the same version, the same
/// handshake the app ships — which is why it lives in this repository and is written in Dart.
Future<void> main(List<String> args) async {
  final options = _Options.parse(args);
  if (options == null) {
    stderr.writeln(_usage);
    exitCode = 64;
    return;
  }
  final identity = PairIdentity(
    brand: options.brand,
    serviceType: '_${options.brand}._tcp',
    // The line's apps use their brand as the URI scheme too.
    // ignore: no-equal-arguments
    scheme: options.brand,
  );
  final peer = options.mode == 'outlet'
      ? await _Outlet.start(identity, options)
      : await _Panel.start(identity, options);
  if (peer == null) {
    exitCode = 1;
    return;
  }
  final commands = options.script == null
      ? stdin.transform(utf8.decoder).transform(const LineSplitter())
      : Stream<String>.fromIterable(options.script!.split(';'));
  await for (final line in commands) {
    final words = line.trim().split(RegExp(r'\s+')).where((word) => word.isNotEmpty).toList();
    if (words.isEmpty) continue;
    if (!await _run(peer, words)) break;
  }
  await peer.close();
  _log('closed');
}

/// Runs one command; false ends the session.
Future<bool> _run(_Peer peer, List<String> words) async {
  switch (words) {
    case ['quit']:
      return false;

    case ['wait']:
      await peer.paired.future;

    case ['sleep', final seconds]:
      await Future<void>.delayed(Duration(milliseconds: ((double.tryParse(seconds) ?? 1) * 1000).round()));

    case ['lost'] when peer is _Outlet:
      peer.session.report(.lost);
      _log('sent power lost');

    case ['restored'] when peer is _Outlet:
      peer.session.report(.restored);
      _log('sent power restored');

    case ['share', final key, ...final rest]:
      final value = _value(rest.join(' '));
      peer.share(key, value);
      _log('shared $key = ${jsonEncode(value)}');

    case ['signal', final name]:
      peer.signal(name);
      _log('signalled $name');

    default:
      _log('unknown command: ${words.join(' ')}');
  }
  return true;
}

Object? _value(String raw) {
  try {
    return jsonDecode(raw);
  } on FormatException {
    return raw;
  }
}

void _log(String line) => print('peer | ${DateTime.now().toIso8601String().substring(11, 23)} | $line');

sealed class _Peer {
  final Completer<void> paired = Completer<void>();

  void share(String key, Object? value);

  void signal(String name);

  Future<void> close();

  void _paired() {
    if (!paired.isCompleted) paired.complete();
  }
}

/// This computer in the wall socket: it listens, and the phone (the panel) dials it.
final class _Outlet extends _Peer {
  _Outlet._(this.session, this._server, this._accepting);

  final OutletSession session;
  final ServerSocket _server;
  final StreamSubscription<Socket> _accepting;
  late final StreamSubscription<OutletEvent> _events;

  static Future<_Outlet?> start(PairIdentity identity, _Options options) async {
    final server = await ServerSocket.bind(
      options.adb ? InternetAddress.loopbackIPv4 : InternetAddress.anyIPv4,
      options.port,
    );
    final host = options.adb ? '127.0.0.1' : await _lanAddress();
    if (host == null) {
      stderr.writeln('No LAN address; pass --adb.');
      await server.close();
      return null;
    }
    if (options.adb && !await _adb(<String>['reverse', 'tcp:${server.port}', 'tcp:${server.port}'])) {
      await server.close();
      return null;
    }
    final session = OutletSession(identity: identity, secret: PairSecret.generate(), device: options.device);
    // Cancelled in [close]; the analyzer does not follow it into the field.
    // ignore: cancel_subscriptions
    final accepting = server.listen((socket) => unawaited(session.attach(SocketTransport(socket))));
    final outlet = _Outlet._(session, server, accepting);
    outlet._events = session.events.listen((event) {
      switch (event) {
        case OutletPaired(:final device):
          outlet._paired();
          _log('paired with ${device ?? 'a panel'}');
        case OutletRejectedPeer(:final reason):
          _log('refused a peer: ${reason.name}');
        case OutletPeerLeft(:final graceful, :final queued):
          _log('panel left (${graceful ? 'bye' : 'lost'}), $queued queued');
        case OutletDelivered(:final seq):
          _log('delivered #$seq');
        case OutletPeerShared(:final key, :final value):
          _log('panel shares $key = ${jsonEncode(value)}');
        case OutletPeerSignal(:final name):
          _log('panel signals $name');
      }
    });
    final invite = PairInvite(
      identity: identity,
      endpoint: PairEndpoint(host: host, port: server.port),
      secret: session.secret,
    ).toUri().toString();
    _log('listening on $host:${server.port}');
    print('invite | $invite');
    if (options.open) {
      await _adb(<String>['shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', "'$invite'"]);
    }
    return outlet;
  }

  @override
  void share(String key, Object? value) => session.share(key: key, value: value);

  @override
  void signal(String name) => session.signal(name);

  @override
  Future<void> close() async {
    await session.close();
    await _events.cancel();
    await _accepting.cancel();
    await _server.close();
  }
}

/// This computer at the breaker panel: it dials the invite the phone (the outlet) shows.
final class _Panel extends _Peer {
  _Panel._(this.session);

  final PanelSession session;
  late final StreamSubscription<PanelEvent> _events;

  static Future<_Panel?> start(PairIdentity identity, _Options options) async {
    final invite = options.invite == null ? null : PairInvite.tryParse(options.invite!, identity: identity);
    if (invite == null) {
      stderr.writeln('--invite is missing or is not a ${identity.scheme} invite.');
      return null;
    }
    var host = invite.endpoint.host;
    var port = invite.endpoint.port;
    if (options.adb) {
      final local = await _adbOutput(<String>['forward', 'tcp:0', 'tcp:$port']);
      final forwarded = int.tryParse(local?.trim() ?? '');
      if (forwarded == null) return null;
      (host, port) = ('127.0.0.1', forwarded);
    }
    final session = PanelSession(identity: identity, secret: invite.secret, device: options.device);
    final panel = _Panel._(session);
    panel._events = session.events.listen((event) {
      switch (event) {
        case PanelPaired(:final device):
          panel._paired();
          _log('paired with ${device ?? 'an outlet'}');
        case PanelPowerEvent(:final state, :final seq):
          _log('power ${state.name} #$seq');
        case PanelRefused(:final reason):
          _log('refused: ${reason.name}');
        case PanelDisconnected(:final graceful):
          _log('outlet left (${graceful ? 'bye' : 'lost'})');
        case PanelGaveUp():
          _log('gave up');
        case PanelPeerShared(:final key, :final value):
          _log('outlet shares $key = ${jsonEncode(value)}');
        case PanelPeerSignal(:final name):
          _log('outlet signals $name');
      }
    });
    _log('dialling $host:$port');
    try {
      final attached = await session.attach(SocketTransport(await Socket.connect(host, port)));
      if (!attached) _log('handshake failed');
    } on SocketException catch (error) {
      _log('unreachable: ${error.message}');
    }
    return panel;
  }

  @override
  void share(String key, Object? value) => session.share(key: key, value: value);

  @override
  void signal(String name) => session.signal(name);

  @override
  Future<void> close() async {
    await session.close();
    await _events.cancel();
  }
}

Future<String?> _lanAddress() async {
  for (final interface in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
    for (final address in interface.addresses) {
      if (!address.isLoopback && !address.isLinkLocal) return address.address;
    }
  }
  return null;
}

Future<bool> _adb(List<String> args) async => await _adbOutput(args) != null;

/// Runs `adb`; null (and the reason on stderr) when it fails.
Future<String?> _adbOutput(List<String> args) async {
  final result = await Process.run('adb', args);
  if (result.exitCode == 0) return result.stdout as String;
  stderr.writeln('adb ${args.join(' ')}: ${result.stderr}');
  return null;
}

final class _Options {
  const _Options({
    required this.mode,
    required this.brand,
    required this.device,
    required this.port,
    required this.adb,
    required this.open,
    this.invite,
    this.script,
  });

  final String mode;
  final String brand;
  final String device;
  final int port;
  final bool adb;
  final bool open;
  final String? invite;
  final String? script;

  static _Options? parse(List<String> args) {
    if (args.isEmpty || !const <String>{'outlet', 'panel'}.contains(args.first)) return null;
    String? value(String name) {
      final at = args.indexOf(name);
      return at < 0 || at + 1 >= args.length ? null : args[at + 1];
    }

    return _Options(
      mode: args.first,
      brand: value('--brand') ?? 'breakersonar',
      device: value('--device') ?? 'pairlink peer (${Platform.localHostname})',
      port: int.tryParse(value('--port') ?? '') ?? 0,
      adb: args.contains('--adb'),
      open: args.contains('--open'),
      invite: value('--invite') ?? _read(value('--invite-file')),
      script: value('--script'),
    );
  }
}

/// The file's first line, trimmed. On Windows `dart` is a batch file, and cmd splits an invite's
/// `&` into commands, so a script hands the invite over in a file.
String? _read(String? path) => path == null ? null : File(path).readAsLinesSync().firstOrNull?.trim();

const String _usage = '''
usage: dart run tool/peer.dart outlet [--brand b] [--port n] [--adb] [--open] [--script "…"]
       dart run tool/peer.dart panel (--invite <uri> | --invite-file <path>) [--brand b] [--adb] [--script "…"]
commands: wait · sleep <s> · lost · restored · share <key> <value> · signal <name> · quit''';
