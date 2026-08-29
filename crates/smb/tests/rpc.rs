#![cfg(feature = "test-ndr64")]

mod common;

use serial_test::serial;
use smb::{Client, ClientConfig, PipeName, RpcPipeConnection, ShareTarget};
use smb_rpc::interface::{ShareKind, SrvSvc};

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_shares_enum_through_domain_pipe() -> smb::Result<()> {
    let server = common::smb_tests_server();
    let client = Client::new(ClientConfig::default());
    let ipc = client
        .connect_share(
            &ShareTarget::new(&server, "IPC$")?,
            common::smb_test_credentials(),
        )
        .await?;
    let pipe = ipc.open_pipe(&PipeName::new("srvsvc")?).await?;
    let mut rpc = pipe.bind_rpc::<SrvSvc<RpcPipeConnection>>().await?;
    let shares = rpc.netr_share_enum(&server).await.map_err(|error| {
        smb::Error::InvalidMessage(format!("share enumeration RPC failed: {error}"))
    })?;
    assert!(shares.iter().any(|share| {
        share
            .netname
            .as_ref()
            .is_some_and(|name| name.to_string() == common::smb_tests_share())
            && share.share_type.kind() == ShareKind::Disk
    }));
    ipc.close().await?;
    client.close().await
}
