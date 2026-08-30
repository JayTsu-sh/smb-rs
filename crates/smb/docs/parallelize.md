# Concurrency and transfers

SMB2/SMB3 can keep multiple requests in flight. The runtime owns message IDs,
credits, cancellation, and response correlation, so callers do not coordinate
those protocol details themselves.

`File`, `Directory`, `Share`, and `Client` are safe to share between async
tasks. Independent operations may be awaited concurrently. A single file can
also be accessed at explicit offsets without a shared cursor:

```rust,no_run
# use smb::{File, Result};
# async fn read_both(file: &File) -> Result<()> {
let (header, body) = tokio::try_join!(
    file.read_at(0, 4096),
    file.read_at(4096, 1024 * 1024),
)?;
# let _ = (header, body);
# Ok(())
# }
```

For a complete copy, prefer [`crate::Transfer`]. Its scheduler bounds
concurrency, keeps destination writes ordered, exposes progress, and cancels
in-flight chunks when the operation fails or its deadline expires. Payloads
are passed as `bytes::Bytes`, allowing slices and task handoffs to retain the
same backing allocation.

Keep one `Client` for related work. The public API intentionally does not
expose connection channels or SMB credits; these remain runtime policy rather
than application synchronization primitives.
