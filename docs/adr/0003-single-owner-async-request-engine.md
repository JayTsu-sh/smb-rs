---
status: accepted
---

# Use one connection driver with a single state owner

Each physical SMB connection generation uses one asynchronous connection-driver
task. The driver is the only authority for lifecycle, admission, message IDs,
credits, pending requests, deadlines, tombstones, and caller completion. It
cooperatively polls independent framed-read and active-write futures, retaining
full-duplex I/O without routing every transport completion through additional
Tokio tasks and channels. Every state transition and first-terminal-wins race
therefore remains serializable and testable.

This replaces the handler/worker/backend split and its shared awaiting/pending
maps. It rejects a single task that interleaves blocking I/O with state commits,
multiple peer owners, detached preparation tasks, per-request timers, and an
engine that performs automatic replay. The complete state shape, queue rules,
credit accounting, cancellation semantics, and verification contract are in
`docs/architecture/async-request-engine.md`.
