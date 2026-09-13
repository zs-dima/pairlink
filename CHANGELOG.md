# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-13

### Added

- `Shared` and `Signal`: two application messages this package carries without reading — a named
  value one peer shares with the other, and a named one-shot request. Both directions, through
  `share(key:, value:)` and `signal(name)` on either session, arriving as `OutletPeerShared` /
  `OutletPeerSignal` and `PanelPeerShared` / `PanelPeerSignal`. A consumer can add a wire feature
  without a protocol bump or a release here.
  - `Shared` is state: re-asserted on every `attach` rather than queued. **A receiver that acts on
    one must ignore a repeat** — re-assertion means the link came back, not that anything changed,
    and one that restarts a timer per delivery lets a flapping link extend it without end.
  - `Signal` is never stored or queued and is dropped with the link: a command delivered late is
    executed at the wrong moment.
  - Values are scalars only (`bool`, `num`, `String`, null): `ArgumentError` on send,
    `FrameError(malformed)` on receipt. The MAC covers a canonicalization that sorts top-level keys
    only. A real check, not an assertion, which release builds strip.
  - Both are signed like every post-handshake frame and join no unsigned-acceptance set. An unknown
    `key` or `name` is ignored, never refused.

### Changed

- **Breaking:** `kPairlinkVersion` is 4. The session key binds the version, so 3 and 4 cannot pair;
  a mismatch is still a clean `Reject(versionMismatch)`.
- **Breaking:** the new sealed subclasses of `PairFrame`, `OutletEvent` and `PanelEvent` break every
  exhaustive switch over them until it handles them.

## [0.2.0] - 2026-09-05

### Added

- `PairEndpoint.id` and `PairSecret.pairId({required brand})`: a public name for a pairing, the
  first four bytes of HMAC-SHA256 over the secret, in hex. Null for a typed code by construction —
  thirty-two bits of a keyed hash over 128 random bits reveal nothing, while the same hash over
  four digits would be a ten-thousand-row lookup table. It lets two phones that remember each
  other recognise each other BEFORE they connect, so a search never spends a stranger's attempt
  budget on a handshake that could not verify.

### Fixed

- `PanelSession` reported one dropped socket TWICE. The transport's `onDone` emitted
  `PanelDisconnected` without detaching, so the idle timer stayed armed and fired again fifteen
  seconds later. A consumer that reacts to a drop with a bounded retry loop got the second report
  after it had finished, and started over with a fresh budget — the "stopped trying to reconnect,
  then connected on its own" shape seen on two phones on 2026-09-05.
- `PanelSession` reported a handshake that never completed as a drop. `attach` already says so by
  returning false; the extra event made a failed reconnect attempt look like a fresh outage.

## [0.1.0] - 2026-09-04

### Added

- First released version: the v3 wire protocol
  (`PROTOCOL.md`), `OutletSession`, `PanelSession`, `PairInvite`, `PairSecret`, the socket
  transport and the discovery contracts, with the skeptic test suite.
- `PairIdentity`: the application's `brand`, mDNS `serviceType` and QR `scheme` are one value the
  application declares and passes in. Two applications on this protocol never share a key space.

### Changed

- **Breaking.** `OutletSession`, `PanelSession` and `PairInvite` require an `identity`;
  `PairInvite.tryParse` takes one; `PairSecret.deriveKey` takes a `brand`. The constants
  `kWireBrand` and `kServiceType` are gone.
