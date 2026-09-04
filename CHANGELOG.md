# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
