# Changelog

## 0.1.3

- Retain and pair HTTP requests whose request target contains unescaped spaces or tabs, with an explicit nonconforming-target diagnostic.
- Report declared, captured and missing body bytes when Content-Length exceeds available data; a later TCP FIN does not override that mismatch.
- Add segmented-request regression tests and verify the reported 11-packet capture without adding its contents to the repository.

## 0.1.2

- Run as a workspace extension for Remote SSH; preserve host-local bounded reads and remote export locations.
- Show remote analysis status and explain the local Wireshark boundary.
- Add toolbar and command-palette Wireshark configuration, file selection/manual input, macOS app bundle resolution, executable validation and actionable launch errors.
- Add remote-host integration and configuration regression tests. Real SSH session validation remains pending.

## 0.1.1

Security hardening: bounded file reads and analysis budgets, per-capture gzip limits, bounded HTTP field metadata, filter nesting/token limits, DNS/VLAN limits, worker deduplication/cancellation/timeouts, absolute Wireshark executable resolution, and incremental UI rendering. Added security regression tests and documentation.

## 0.1.0

Initial local development build: HTTP-first capture editor, TypeScript capture and protocol analysis, TCP streams, DNS pairing, extensible display filters, statistics, bilingual UI and Wireshark integration.
