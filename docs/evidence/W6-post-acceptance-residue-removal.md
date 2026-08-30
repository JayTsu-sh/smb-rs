# W6 post-acceptance residue removal

## Deletion result

The domain-first interface remains unchanged. The deletion test removed 3,725
lines of implementation that had no production caller or duplicated authority:

- the old high-level Client share/DFS/multichannel/lease convenience surface;
- four disconnected recovery and server-event shadow reducers;
- the obsolete file trait adapter and legacy Pipe RPC implementation;
- unused DFS and IPC Tree reference adapters;
- deprecated panic-based Resource conversion helpers.

The retained crate-private Connection, Session, Share, and Resource modules are
not compatibility surfaces. They are the active protocol implementation behind
`runtime::port`, including negotiation, authentication, request execution,
generation replacement, durable recovery, and LeaseBreak/OplockBreak handling.
Deleting those modules would move the same protocol complexity into domain
callers and would regress already accepted server-event behavior.

## Interface tightening

Every request must now carry an explicit sealed `Protection` policy before it
crosses the wire seam. Negotiate and SessionSetup explicitly select no
protection when appropriate; Session/Share submission selects signing or
encryption. The previous fallback from an absent policy to mutable header hints
was deleted.

Broad transition comments and allowances were removed. The remaining scoped
dead-code allowances state permanent reasons: conditional protocol paths and
deterministic fixture observations. They do not preserve a second public
interface or an alternative lifecycle authority.

## Verification

- complete workspace all-target tests: passed;
- strict SMB all-target Clippy with warnings denied: passed;
- `smb` library tests after deletion: passed;
- architecture, residue, evidence, and copy-budget gates: passed;
- fresh isolated appliance public-domain roundtrip: passed on plain and
  encryption-required Shares;
- manifest-authoritative appliance cleanup: passed with zero retained objects;
- secret and endpoint scan: passed.
