# pairlink

[![CI](https://github.com/zs-dima/pairlink/actions/workflows/ci.yml/badge.svg)](https://github.com/zs-dima/pairlink/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

Local-network pairing between two phones, in pure Dart. One phone listens in a wall socket, the
other connects and drives reconnection; a secret shared out of band proves possession over a
nonce-bound HMAC handshake, and nothing secret ever travels the wire.

`PROTOCOL.md` is the normative specification. Every `INVARIANT (tag)` in it is anchored to a
symbol in `lib/` or `test/`, and `test/contract_anchors_test.dart` fails when one loses its anchor.

## Roles

| Phone | Class | Does |
|---|---|---|
| Outlet, stationary in the socket | `OutletSession` | listens, sends power events, refuses strangers |
| Panel, carried around | `PanelSession` | connects, reconnects, drives the heartbeat |

## Two ways to share the secret

- **QR code** (primary): the outlet phone shows a `PairInvite`, 128 random bits plus its own
  address. No discovery, nothing guessable.
- **Four-digit code** (fallback): the panel phone shows a code, the user types it on the outlet
  phone, and the outlet phone advertises over mDNS. Weaker by design, and `PairStrength` says so
  all the way up to the UI. Guessing is capped by `AttemptLimiter`.

## Usage

```dart
const identity = PairIdentity(brand: 'myapp', serviceType: '_myapp._tcp', scheme: 'myapp');

// Outlet phone: generate the secret, show the invite, accept the peer.
final secret = PairSecret.generate();
final outlet = OutletSession(identity: identity, secret: secret);
final invite = PairInvite(identity: identity, endpoint: endpoint, secret: secret);
outlet.events.listen((event) { /* OutletPaired, OutletPeerLeft, ... */ });
await outlet.attach(SocketTransport(socket));

// Panel phone: scan, connect, listen for power events.
final scanned = PairInvite.tryParse(qrText, identity: identity)!;
final panel = PanelSession(identity: identity, secret: scanned.secret);
panel.events.listen((event) { /* PanelPowerEvent, PanelDisconnected, ... */ });
await panel.attach(SocketTransport(await Socket.connect(scanned.endpoint.host, scanned.endpoint.port)));
```

`PairIdentity.brand` is bound into every session key, so two applications on this protocol never
share a key space; `serviceType` is what the platform's mDNS responder advertises; `scheme` is the
QR payload's URI scheme. Discovery itself is the application's job: implement `PairAdvertiser` and
`PairDiscovery` over the platform responder (NsdManager, Bonjour).

## Testing

`dart test`. The suite includes `test/skeptic/`, an adversarial peer implemented independently of
the production code; extend `hostile.dart` when probing, never the code under test. The package runs
under plain `dart test` on Linux as well as macOS and Windows, which matters: a peer that vanishes
reports `done` on one and an error on another, and the attempt budget must not be spent by either.

## Install

```yaml
dependencies:
  pairlink:
    git:
      url: https://github.com/zs-dima/pairlink.git
      ref: v0.1.0
```

## Changelog

[CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE)
