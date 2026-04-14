# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Build & Development Commands

```bash
# Standard build
cargo build
cargo build --all-features

# Tests
cargo test -p smb --lib                  # smb unit tests
cargo test -p smb-msg                    # message tests
cargo test -p smb-transport              # transport tests
cargo test --workspace                   # all (integration tests need server)

# Code quality
cargo fmt
cargo check --workspace
cargo clippy --workspace
```

## Workspace Architecture

| Crate | Role |
|-------|------|
| `smb` | Main SMB client library: connection, session, tree, file, pipe |
| `smb-msg` | SMB2/3 message structures and serialization (binrw) |
| `smb-msg-derive` | Procedural macros for SMB message definitions |
| `smb-dtyp` | Common MS-DTYP data types (GUID, SID, ACL, security descriptors) |
| `smb-dtyp-derive` | Derive macros for data types (mbitfield) |
| `smb-fscc` | MS-FSCC file system control codes |
| `smb-rpc` | MS-RPCE (DCE/RPC) over SMB |
| `smb-transport` | Transport layer: TCP, NetBios, QUIC, RDMA |
| `smb-tests` | Shared test utilities |
| `smb-cli` | Command-line interface |

## Code Style

### use statements

All `use` statements must be at the top of the file. No `use` inside function bodies or `impl` blocks (except in `#[cfg(test)]` blocks).

Paths in code should be at most two levels (`A::B`). Longer paths must be imported via `use` at file top.

### Error Handling (mandatory)

#### 1. No `.unwrap()` / `.expect()`

**Strictly forbidden in all production code.** These methods cause panic on `None`/`Err`, which is unacceptable in a library crate.

```rust
// WRONG
let val = some_option.unwrap();
let val = some_result.expect("should not fail");

// CORRECT - propagate with ?
let val = some_result?;

// CORRECT - pattern match
if let Some(val) = some_option { /* use val */ }

// CORRECT - convert Option to Result
let val = some_option.ok_or(Error::NotFound)?;

// CORRECT - provide default
let val = some_option.unwrap_or_default();
```

**Only exception:** `#[cfg(test)]` blocks and `tests/` directory.

#### 2. Error types: use `thiserror` enums

Each crate must define its own error enum with `thiserror`. Do not use `Box<dyn Error>` or bare `String` as error types across boundaries.

Do not use `.to_string()` to discard error type information. Use `#[from]` or `map_err` to preserve error chains.

### Refactoring Rules (mandatory)

**Refactoring changes structure only, never semantics. Observable behavior must remain identical before and after.**

If you discover a logic bug during refactoring, fix it in a **separate commit**.

## High-Performance IO / Async Patterns (mandatory)

- Large buffer transfers use `Bytes`/`BytesMut`, **never** `Vec<u8>` clone
- Shared counters use `AtomicU64`/`AtomicUsize`, **never** `Mutex<u64>`
- CPU-intensive tasks use `spawn_blocking`, **never** compute in async fn directly
- Prefer enum dispatch over `Box<dyn Trait>` where variant set is known
- Memory ordering: use `Relaxed`/`Acquire`/`Release` appropriately, avoid `SeqCst` unless required
- Transport: stack-allocate small headers, use vectored I/O for sends
- Signing/encryption: operate within lock scope or use cheap clone (enum/Arc), avoid `Box<dyn>` heap allocation per message

## Feature Flags

Threading models (mutually exclusive):
- `async` (default) — tokio-based async
- `multi_threaded` — std::thread sync
- `single_threaded` — single-thread sync

Crypto: `sign`, `encrypt`, `compress` (each with sub-features)
Transport: `netbios-transport`, `quic`, `rdma`
