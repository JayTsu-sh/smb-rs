---
status: accepted
---

# Own wire bytes as immutable frames and sealed segments

The wire codec will decode one immutable transport frame into owned typed
metadata plus validated ranges, and encode through a mutable metadata builder
that seals into immutable shared segments. This avoids self-referential borrows,
unsafe code, payload consolidation, and shared-buffer mutation while preserving
the operation-specific budgets in ADR-0001.

The connection runtime—not the codec or domain—owns the builder, protection
pipeline, send cursor, and request payload lifetime. Encryption and compression
consume a sealed message and replace it with one transform frame. The transport
consumes immutable segments and keeps partial-write position in a private
cursor. Detailed type states, range rules, transform ordering, and validation
requirements are recorded in `docs/architecture/wire-buffer-ownership.md`.

This rejects borrowed decoded messages, generic buffer abstractions, public
consolidation, mutable shared segments, and an unsafe self-referential codec.
Those alternatives either cannot cross async seams safely or move wire
complexity into every caller without improving the agreed payload-copy budget.
