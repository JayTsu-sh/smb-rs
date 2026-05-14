//! Integration tests for `FileCreateArgs::lease_request` (Phase A of Handle Lease).
//!
//! These tests verify the end-to-end wire behavior against a real SMB server:
//!  1. Client sends an `RqLs` create context with the Create request.
//!  2. Server responds with an `RqLs` response context when it supports leasing.
//!  3. `ResourceHandle::lease_granted()` exposes the parsed grant to callers.
//!
//! Phase A is **infrastructure only** — opening with a lease still costs a full
//! `Create + Close` round-trip. Phases B-D introduce break handling and deferred
//! close that actually skip RTs.
//!
//! ## Running
//!
//! These tests connect to whatever server `SMB_RUST_TESTS_SERVER` points at
//! (defaults to `127.0.0.1`, expecting the docker-compose Samba setup from
//! `crates/smb/tests/README.md`). They are not gated to any particular IP; any
//! SMB 2.1+ server advertising `caps.leasing()` is sufficient.

mod common;
use common::{make_server_connection, smb_tests_share};
use serial_test::serial;
use smb::{FileCreateArgs, RequestLease, RequestLeaseV2};
use smb_fscc::FileDispositionInformation;
use smb_msg::{LeaseFlags, LeaseState};
use std::time::Duration;

/// Random-but-stable 128-bit lease key for the test. A real client would
/// generate a fresh UUID per open; a constant value is fine in a serial test
/// because the prior test's lease is released when the file is closed.
const TEST_LEASE_KEY: u128 = 0x4C45_4153_4520_5445_5354_204B_4559_2121_u128;

/// Build a v2 lease request asking for Read + Handle caching. Servers that
/// don't support leasing will silently omit the response context; we'll
/// observe that as `lease_granted() == None`.
fn make_lease_request() -> RequestLease {
    RequestLease::RqLsReqv2(RequestLeaseV2 {
        lease_key: TEST_LEASE_KEY,
        lease_state: LeaseState::new()
            .with_read_caching(true)
            .with_handle_caching(true),
        lease_flags: LeaseFlags::new(),
        parent_lease_key: 0,
        epoch: 0,
    })
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_lease_request_create_new() -> smb::Result<()> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;

    // Inspect the negotiated capabilities so we can interpret the result:
    // a server without `caps.leasing()` is expected to return None, and we
    // skip the positive assertion instead of treating it as a failure.
    let conn = client.get_connection(share_path.server()).await?;
    let info = conn.conn_info().expect("share_connect completed → negotiated");
    let server_supports_leasing = info.negotiation.caps.leasing();
    tracing::info!(
        "Negotiated: dialect={:?}, leasing={}, multi_channel={}",
        info.negotiation.dialect_rev,
        server_supports_leasing,
        info.negotiation.caps.multi_channel()
    );

    // OverwriteIf instead of Create — makes the test idempotent across reruns
    // (a prior failed run may have left the file behind without deleting it).
    let args = FileCreateArgs::make_overwrite(Default::default(), Default::default())
        .with_lease(make_lease_request());

    let file = client
        .create_file(&share_path.with_path("lease_phase_a.txt"), &args)
        .await?
        .into_file()
        .expect("created resource must be a file");

    let grant = file.handle().lease_granted();
    tracing::info!("server lease_granted={:?}", grant);

    if server_supports_leasing {
        let g = grant.expect("server supports leasing → grant must be Some");
        assert_eq!(g.key, TEST_LEASE_KEY, "server must echo our lease key");
        // Server may downgrade requested state (e.g., drop handle_caching).
        // Phase A only verifies the grant was parsed; the actual state is
        // whatever the server chose to issue.
        assert!(
            g.state.read_caching() || g.state.handle_caching() || g.state.write_caching(),
            "at least one caching bit must be set when grant is Some"
        );
    } else {
        // Servers without leasing capability must not produce a grant.
        assert!(
            grant.is_none(),
            "server lacks leasing capability but produced a grant: {:?}",
            grant
        );
    }

    file.set_info(FileDispositionInformation::default()).await?;
    file.close().await?;
    Ok(())
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_no_lease_request_has_no_grant() -> smb::Result<()> {
    // Control case: default FileCreateArgs (no lease_request) → server must
    // never produce a grant, regardless of server capability. This proves
    // Phase A's `lease_requested` gate correctly suppresses parsing when
    // the client didn't ask.
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;

    let args = FileCreateArgs::make_overwrite(Default::default(), Default::default());
    assert!(args.lease_request.is_none(), "control: args must have no lease");

    let file = client
        .create_file(&share_path.with_path("lease_phase_a_no_lease.txt"), &args)
        .await?
        .into_file()
        .expect("created resource must be a file");

    assert!(
        file.handle().lease_granted().is_none(),
        "no lease_request → grant must be None"
    );

    file.set_info(FileDispositionInformation::default()).await?;
    file.close().await?;
    Ok(())
}

/// Phase B (LeaseBreakNotify reception + auto-Ack):
///
/// Client A opens a file with a HandleCaching+ReadCaching lease, then a
/// separate Client B opens the same path. The server is required to break
/// the handle-caching component of A's lease and send a `LeaseBreakNotify`;
/// the smb-rs connection task receives it, auto-sends a `LeaseBreakAck`,
/// and fans out a `LeaseBreakEvent` to subscribers — which is what this
/// test waits for.
///
/// This is the end-to-end proof that Phase B's wire-level integration
/// works: subscription + decode + ack + fan-out. Unit-testable in isolation
/// is the decode/fan-out; only a real server can drive the break.
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_lease_break_notify_fanned_out() -> smb::Result<()> {
    let share = smb_tests_share();

    // Client A: holds the lease, subscribes to breaks.
    let (client_a, share_path_a) = make_server_connection(&share, None).await?;
    let conn = client_a.get_connection(share_path_a.server()).await?;
    let info = conn.conn_info().expect("connection negotiated");
    if !info.negotiation.caps.leasing() {
        tracing::warn!(
            "Server does not advertise caps.leasing(); Phase B break test \
             cannot run against this server. Skipping."
        );
        return Ok(());
    }

    let mut break_rx = client_a
        .subscribe_lease_breaks(share_path_a.server())
        .await?;

    let path = share_path_a.with_path("lease_phase_b_break.txt");
    let lease = RequestLease::RqLsReqv2(RequestLeaseV2 {
        lease_key: TEST_LEASE_KEY,
        lease_state: LeaseState::new()
            .with_read_caching(true)
            .with_handle_caching(true),
        lease_flags: LeaseFlags::new(),
        parent_lease_key: 0,
        epoch: 0,
    });
    let args_a = FileCreateArgs::make_overwrite(Default::default(), Default::default())
        .with_lease(lease);
    let file_a = client_a
        .create_file(&path, &args_a)
        .await?
        .into_file()
        .expect("Resource must be a file");

    let grant = file_a
        .handle()
        .lease_granted()
        .expect("server with caps.leasing() must issue a grant");
    tracing::info!("Client A holds lease: {grant:?}");
    assert!(
        grant.state.handle_caching(),
        "test relies on handle_caching to provoke a break on B's open",
    );

    // Client B: independent connection to same server, opens the same path
    // with OverwriteIf + GenericAll — strongly conflicts with A's
    // HandleCaching+ReadCaching lease. Per MS-SMB2 2.2.23.2 the server must
    // send a LeaseBreakNotify to A before completing B's Create.
    let (client_b, share_path_b) = make_server_connection(&share, None).await?;
    let path_b = share_path_b.with_path("lease_phase_b_break.txt");
    let file_b = client_b
        .create_file(
            &path_b,
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()
        .expect("Resource must be a file");

    // Bounded wait so a misbehaving server can't hang CI.
    let event = tokio::time::timeout(Duration::from_secs(10), break_rx.recv())
        .await
        .expect("LeaseBreakNotify must arrive within 10s of B's conflicting open")
        .expect("broadcast channel must remain open while client A is alive");

    tracing::info!("Client A received break event: {event:?}");
    assert_eq!(
        event.lease_key.as_u128(),
        grant.key,
        "break must target the lease we acquired (compared via u128 since \
         LeaseBreakNotify uses Guid while RequestLease uses u128)",
    );
    assert!(
        !event.new_state.handle_caching(),
        "server must drop handle_caching when another client opens the file",
    );

    // Cleanup: drop B first so A's set_info can mark the file for delete.
    drop(file_b);
    file_a
        .set_info(FileDispositionInformation::default())
        .await?;
    file_a.close().await?;
    Ok(())
}

/// Phase C.1 (cache table insert):
///
/// When `Client::create_file` succeeds with a granted lease, the
/// connection's `lease_table` must hold an entry keyed by the share-
/// relative path with a refcount of 1 and `tombstoned == false`. This
/// is the simplest building block of Phase C — cache hits (C.3),
/// break-driven tombstoning (C.2), and deferred close (C.4) all build
/// on this insertion path.
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_lease_slot_inserted_on_create() -> smb::Result<()> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let conn = client.get_connection(share_path.server()).await?;
    let info = conn.conn_info().expect("connection negotiated");
    if !info.negotiation.caps.leasing() {
        tracing::warn!("Server lacks caps.leasing(); skipping C.1 cache-insert test.");
        return Ok(());
    }

    // Baseline: cache must start empty for this fresh connection.
    let baseline = conn.lease_slot_count().await?;

    let path_rel = "lease_phase_c1_insert.txt";
    let args = FileCreateArgs::make_overwrite(Default::default(), Default::default())
        .with_lease(make_lease_request());
    let file = client
        .create_file(&share_path.with_path(path_rel), &args)
        .await?
        .into_file()
        .expect("Resource must be a file");

    let grant = file
        .handle()
        .lease_granted()
        .expect("server with caps.leasing() must issue a grant");

    // A slot should now exist for our path.
    assert_eq!(
        conn.lease_slot_count().await?,
        baseline + 1,
        "Create with lease must add one entry to the per-connection lease_table",
    );
    let slot = conn
        .peek_lease_slot(path_rel)
        .await?
        .expect("slot must be reachable by path");
    assert_eq!(slot.lease_key, grant.key, "slot's lease_key must echo the grant");
    assert_eq!(
        slot.refcount.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "initial refcount is the caller's handle",
    );
    assert!(
        !slot.tombstoned.load(std::sync::atomic::Ordering::Relaxed),
        "fresh slot must not be tombstoned",
    );

    file.set_info(FileDispositionInformation::default()).await?;
    file.close().await?;
    Ok(())
}

/// Phase C.2 (break-driven tombstone):
///
/// Client A opens with HandleCaching; client B opens the same path with
/// OverwriteIf. Server sends a `LeaseBreakNotify` to A. The per-connection
/// break-listener spawned during `_negotiate` consumes the event from
/// `lease_event_tx` and tombstones the matching slot in `lease_table`.
/// This test polls the slot until tombstoned (or times out) — no event
/// subscription needed, the test only inspects cache state.
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_lease_slot_tombstoned_on_break() -> smb::Result<()> {
    let share = smb_tests_share();

    let (client_a, share_path_a) = make_server_connection(&share, None).await?;
    let conn_a = client_a.get_connection(share_path_a.server()).await?;
    let info = conn_a.conn_info().expect("connection negotiated");
    if !info.negotiation.caps.leasing() {
        tracing::warn!("Server lacks caps.leasing(); skipping C.2 tombstone test.");
        return Ok(());
    }

    let path_rel = "lease_phase_c2_tombstone.txt";
    let args_a = FileCreateArgs::make_overwrite(Default::default(), Default::default())
        .with_lease(make_lease_request());
    let file_a = client_a
        .create_file(&share_path_a.with_path(path_rel), &args_a)
        .await?
        .into_file()
        .expect("Resource must be a file");

    let slot = conn_a
        .peek_lease_slot(path_rel)
        .await?
        .expect("slot must exist after Create with grant");
    assert!(
        !slot.tombstoned.load(std::sync::atomic::Ordering::Acquire),
        "slot must start un-tombstoned",
    );

    // Provoke a break from a second client.
    let (client_b, share_path_b) = make_server_connection(&share, None).await?;
    let file_b = client_b
        .create_file(
            &share_path_b.with_path(path_rel),
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()
        .expect("Resource must be a file");

    // Poll the slot's tombstoned flag with a bounded wait. The listener
    // task runs on the same tokio runtime; the event flows
    //   server -> worker -> notify channel -> handle_lease_break
    //   -> broadcast tx -> listener rx -> apply_lease_break
    //   -> slot.tombstoned.store(true).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !slot.tombstoned.load(std::sync::atomic::Ordering::Acquire) {
        if std::time::Instant::now() > deadline {
            panic!("slot was not tombstoned within 10s of B's conflicting open");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    tracing::info!(
        "Slot tombstoned: granted_state now {:?}",
        *slot.granted_state.read().expect("rwlock not poisoned"),
    );

    // Cleanup.
    drop(file_b);
    file_a
        .set_info(FileDispositionInformation::default())
        .await?;
    file_a.close().await?;
    Ok(())
}

/// Phase C.3+C.4 (cache hit + deferred close):
///
/// Open a file with a HandleCaching lease, close it, then reopen the same
/// path with the same lease request. The second open must hit the cache:
///   * No new FileId issued — the second handle reuses the first FileId.
///   * The connection's lease_table still has the entry (refcount goes
///     to 1 on the second open, never to 0 with tombstoned=false).
///   * The slot's `last_used` advances on hit.
///
/// This is the first phase that actually saves network RTs. Subsequent
/// opens against the same path are pure local table lookups.
#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "current_thread"))
))]
#[serial]
async fn test_lease_cache_hit_reuses_file_id() -> smb::Result<()> {
    use smb::FileAccessMask;
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let conn = client.get_connection(share_path.server()).await?;
    let info = conn.conn_info().expect("connection negotiated");
    if !info.negotiation.caps.leasing() {
        tracing::warn!("Server lacks caps.leasing(); skipping C.3 cache-hit test.");
        return Ok(());
    }

    // Use OverwriteIf for the initial set-up Create so we don't depend on
    // prior test state; cache-hit Open will use CreateDisposition::Open
    // which is the only disposition try_acquire_for_reuse accepts.
    let path_rel = "lease_phase_c3_hit.txt";
    let unc = share_path.with_path(path_rel);

    // Step 1: prime the cache. OverwriteIf + GenericAll, with lease.
    let args_prime = FileCreateArgs::make_overwrite(Default::default(), Default::default())
        .with_lease(make_lease_request());
    let file_first = client
        .create_file(&unc, &args_prime)
        .await?
        .into_file()
        .expect("Resource must be a file");
    let grant_first = file_first
        .handle()
        .lease_granted()
        .expect("server with caps.leasing() must issue a grant");
    let file_id_first = file_first.handle().raw_file_id();
    assert!(
        grant_first.state.handle_caching(),
        "cache-hit test relies on handle_caching being granted; got {:?}",
        grant_first.state,
    );

    // Step 2: close — but with a lease slot attached, this must be a
    // deferred close. The slot stays in the cache.
    file_first.close().await?;
    let slot_after_close = conn
        .peek_lease_slot(path_rel)
        .await?
        .expect("deferred close must leave the slot in the cache");
    assert!(
        !slot_after_close.tombstoned.load(std::sync::atomic::Ordering::Acquire),
        "no break happened, slot must still be alive (not tombstoned)",
    );
    assert_eq!(
        slot_after_close.refcount.load(std::sync::atomic::Ordering::Acquire),
        0,
        "refcount returns to 0 after close, but slot stays cached",
    );

    // Step 3: reopen with CreateDisposition::Open + matching access. The
    // returned Resource must reuse the cached FileId — no new Create RT
    // hit the wire. We assert FileId equality as the wire-observable
    // proof.
    let args_reopen = FileCreateArgs::make_open_existing(
        FileAccessMask::new().with_generic_all(true),
    )
    .with_lease(make_lease_request());
    let file_second = client
        .create_file(&unc, &args_reopen)
        .await?
        .into_file()
        .expect("Resource must be a file");
    let file_id_second = file_second.handle().raw_file_id();
    assert_eq!(
        file_id_second, file_id_first,
        "cache hit must reuse the original FileId (saving a Create RT)",
    );
    assert_eq!(
        slot_after_close.refcount.load(std::sync::atomic::Ordering::Acquire),
        1,
        "second open bumps refcount back to 1",
    );

    // Step 4: cleanup. set_info+close on the second handle marks the file
    // for delete. Because the slot was never tombstoned (no server-side
    // break), this close defers again — the file still gets deleted by
    // virtue of the dispose flag carrying into the eventual wire close.
    // We then provoke a tombstone via a flush_idle equivalent: a
    // separate client opening the file would force a break, but here we
    // just let drop() of the connection close everything at test end.
    file_second
        .set_info(FileDispositionInformation::default())
        .await?;
    file_second.close().await?;
    Ok(())
}
