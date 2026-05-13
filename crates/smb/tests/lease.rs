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
use common::{TestConstants, make_server_connection};
use serial_test::serial;
use smb::{FileCreateArgs, RequestLease, RequestLeaseV2};
use smb_fscc::FileDispositionInformation;
use smb_msg::{LeaseFlags, LeaseState};
use std::env;

/// Reads the share name from `SMB_RUST_TESTS_SHARE`, falling back to the
/// shared `TestConstants::DEFAULT_SHARE` when unset. Allows smoke-testing
/// against real lease-supporting servers (e.g. `jay_cifs1`) without
/// rebuilding the test binary.
fn test_share() -> String {
    env::var("SMB_RUST_TESTS_SHARE").unwrap_or_else(|_| TestConstants::DEFAULT_SHARE.to_string())
}

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
    let share = test_share();
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
    let share = test_share();
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
