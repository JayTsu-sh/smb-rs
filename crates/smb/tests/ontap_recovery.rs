//! Explicit real-server Connection-generation recovery gate.

mod common;

use common::{
    default_connection_config, make_server_connection, smb_test_identity, smb_tests_server,
    smb_tests_share,
};
use smb::{Connection, DurableOpenRequest, FileCreateArgs, UncPath, WriteAt};
use smb_dtyp::Guid;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires isolated ONTAP resources and exact-session disruption"]
async fn exact_session_disruption_is_typed_at_the_w4_2_boundary(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let server = share_path.server().to_owned();
    let path = share_path.with_path(&format!(
        "smb-rs-recovery-{}.bin",
        std::process::id()
    ));
    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;
    file.write_at(b"generation-one", 0).await?;

    let connection = client.get_connection(&server).await?;
    let initial = connection
        .observed_generation()
        .ok_or("connection has no active generation")?;
    println!("RECOVERY_DISRUPTION_READY");

    // The management-path session query can be slow on a busy appliance. This
    // outer orchestration window is deliberately longer than the client's
    // recovery-policy deadline; it does not relax any reconnect attempt bound.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(generation) = connection.observed_generation()
            && generation != initial
        {
            assert!(generation > initial);
            assert!(
                file.write_at(b"stale", 1).await.is_err(),
                "ordinary Resource from the lost generation must not migrate silently"
            );
            println!("RECOVERY_GENERATION_REPLACED");
            connection.close().await?;
            return Ok(());
        }
        if file.write_at(b"probe", 32).await.is_err() {
            // ONTAP's exact CIFS-session close may deliberately preserve the
            // underlying TCP connection. That is a Session-recovery input for
            // W4-3, not a transport-loss input for W4-2. The hard W4-2 boundary
            // is a typed stale-session result without blind Resource reopen.
            println!("RECOVERY_SESSION_TYPED_BOUNDARY");
            connection.close().await?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("disruption produced neither generation recovery nor typed boundary".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires isolated ONTAP resources and exact-session disruption"]
async fn exact_session_disruption_reauthenticates_and_revokes_children(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = smb_tests_server();
    let address: SocketAddr = format!("{server}:445").parse()?;
    let connection = Arc::new(Connection::build(
        &server,
        address,
        Guid::generate(),
        default_connection_config(),
    )?);
    connection.connect().await?;
    let session = connection.authenticate(smb_test_identity()?).await?;
    let share_name = smb_tests_share();
    let share_path = UncPath::new(&server)?.with_share(&share_name)?;
    let tree = session.tree_connect(&share_path).await?;
    let file = tree
        .create(
            &format!("smb-rs-session-recovery-{}.bin", std::process::id()),
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;
    file.write_at(b"session-one", 0).await?;
    let durable_file = tree
        .create(
            &format!("smb-rs-durable-recovery-{}.bin", std::process::id()),
            &FileCreateArgs::make_overwrite(Default::default(), Default::default())
                .with_durable(DurableOpenRequest::durable(30_000, Guid::generate())),
        )
        .await?
        .into_file()?;
    durable_file.write_at(b"durable-one", 0).await?;
    let initial_session_id = session.session_id();
    println!("SESSION_RECOVERY_DISRUPTION_READY");

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if session.session_id() != initial_session_id {
            println!("SESSION_ID_REPLACED");
            assert!(
                file.write_at(b"stale", 0).await.is_err(),
                "Resource from the replaced Session must remain stale"
            );
            println!("ORDINARY_RESOURCE_REVOKED");
            durable_file.write_at(b"durable-two", 0).await?;
            println!("DURABLE_WRITE_COMPLETED");
            let recovered_file = tree
                .create(
                    &format!("smb-rs-session-recovered-{}.bin", std::process::id()),
                    &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
                )
                .await?
                .into_file()?;
            println!("NEW_RESOURCE_CREATED");
            recovered_file.write_at(b"session-two", 0).await?;
            println!("SESSION_REAUTHENTICATED");
            println!("SHARE_RECONNECTED");
            println!("DURABLE_RESOURCE_RECONNECTED");
            connection.close().await?;
            return Ok(());
        }
        let _ = file.write_at(b"probe", 32).await;
        if Instant::now() >= deadline {
            return Err("Session was not reauthenticated before the deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn start_disrupting_proxy(
    upstream: SocketAddr,
) -> std::io::Result<(SocketAddr, CancellationToken, CancellationToken, tokio::task::JoinHandle<()>)>
{
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let disrupt_first = CancellationToken::new();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let disrupt_first = disrupt_first.clone();
        let shutdown = shutdown.clone();
        async move {
            let mut connections = JoinSet::new();
            let mut ordinal = 0_u64;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut downstream, _)) = accepted else { break };
                        ordinal += 1;
                        let disrupt = disrupt_first.clone();
                        connections.spawn(async move {
                            let Ok(mut upstream_stream) = TcpStream::connect(upstream).await else {
                                return;
                            };
                            if ordinal == 1 {
                                tokio::select! {
                                    _ = disrupt.cancelled() => {}
                                    _ = copy_bidirectional(&mut downstream, &mut upstream_stream) => {}
                                }
                            } else {
                                let _ = copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
    });
    Ok((address, disrupt_first, shutdown, task))
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable real-server share"]
async fn proxy_transport_loss_recovers_a_negotiated_connection_generation(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = smb_tests_server();
    let upstream: SocketAddr = format!("{server}:445").parse()?;
    let (proxy, disrupt, shutdown, proxy_task) = start_disrupting_proxy(upstream).await?;
    let connection = Arc::new(Connection::build(
        &server,
        proxy,
        Guid::generate(),
        default_connection_config(),
    )?);
    connection.connect().await?;
    let session = connection.authenticate(smb_test_identity()?).await?;
    let share_name = smb_tests_share();
    let share = UncPath::new(&server)?.with_share(&share_name)?;
    let tree = session.tree_connect(&share).await?;
    let file = tree
        .create(
            &format!("smb-rs-proxy-recovery-{}.bin", std::process::id()),
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;
    file.write_at(b"generation-one", 0).await?;
    let initial = connection
        .observed_generation()
        .ok_or("connection has no active generation")?;

    disrupt.cancel();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(generation) = connection.observed_generation()
            && generation != initial
        {
            assert!(generation > initial);
            break;
        }
        if Instant::now() >= deadline {
            return Err("proxy transport loss did not publish a replacement generation".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        file.write_at(b"stale", 1).await.is_err(),
        "ordinary Resource from the lost generation must fail before wire admission"
    );
    println!("RECOVERY_GENERATION_REPLACED");
    connection.close().await?;
    shutdown.cancel();
    proxy_task.await?;
    Ok(())
}
