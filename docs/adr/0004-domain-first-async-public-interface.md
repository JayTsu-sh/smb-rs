---
status: accepted
---

# Expose a domain-first asynchronous interface

The public client interface follows `Client → Session → Share → typed resource`
and returns lazy configurable operations. It exposes positioned and cursor-based
I/O with explicit buffer ownership while hiding physical connections, message
IDs, credits, channels, workers, raw request pairing, and SMB CANCEL. This gives
common and expert callers one deep interface instead of two overlapping protocol
entry paths.

The redesign intentionally removes compatibility exports and renames the public
connected-share handle from `Tree` to `Share`; Tree remains a wire-protocol term.
The complete ownership, close, cancellation, reconnect, batching, error, and
prelude contract is recorded in `docs/architecture/async-public-interface.md`.
