# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
