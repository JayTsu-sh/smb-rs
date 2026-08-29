---
status: accepted
---

# Use one state owner with read and write pumps

Each physical SMB connection generation uses one asynchronous state-owner task
and two I/O pumps. The owner is the only authority for lifecycle, admission,
message IDs, credits, pending requests, deadlines, tombstones, and caller
completion; the pumps only advance framed reads and writes and report typed
events. This topology keeps full-duplex I/O while making every state transition
and first-terminal-wins race serializable and testable.

This replaces the handler/worker/backend split and its shared awaiting/pending
maps. It rejects a single task that interleaves blocking I/O with state commits,
multiple peer owners, detached preparation tasks, per-request timers, and an
engine that performs automatic replay. The complete state shape, queue rules,
credit accounting, cancellation semantics, and verification contract are in
`docs/architecture/async-request-engine.md`.
