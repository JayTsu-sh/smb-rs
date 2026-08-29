#![cfg(feature = "test-ndr64")]

mod common;

use serial_test::serial;
use smb::{Client, ClientConfig, PipeName, RpcPipeConnection, ShareTarget};
use smb_rpc::{
    SmbRpcError,
    interface::{ShareKind, SrvSvc},
};

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
    let mut rpc = match pipe.bind_rpc::<SrvSvc<RpcPipeConnection>>().await {
        Ok(rpc) => rpc,
        Err(smb::Error::RpcError(SmbRpcError::RemoteFault { status })) => {
            assert_ne!(status, 0, "remote RPC fault must retain its status");
            ipc.close().await?;
            client.close().await?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
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
    rpc.into_connection().close().await?;
    ipc.close().await?;
    client.close().await
}
