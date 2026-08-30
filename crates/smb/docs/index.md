# SMB

The `smb` crate is an asynchronous, pure-Rust SMB2/SMB3 client. Its public
object hierarchy follows the lifetime of remote objects:

`Client` → `Session` → `Share` → `File` / `Directory` / `Pipe`

## Basic usage

```rust,no_run
use bytes::Bytes;
use smb::{
    Client, ClientConfig, Credentials, FileOpenOptions, SharePath, ShareTarget,
};

#[tokio::main]
async fn main() -> smb::Result<()> {
    let client = Client::new(ClientConfig::default());
    let target = ShareTarget::new("server", "share")?;
    let share = client
        .connect_share(&target, Credentials::ntlm("username", "password"))
        .await?;

    let path = SharePath::new("file.txt")?;
    let file = share
        .open_file(&path, FileOpenOptions::open_existing())
        .await?;

    let contents = file.read_at(0, 4096).await?;
    file.write_all_at(contents.len() as u64, Bytes::from_static(b"\n"))
        .await?;
    file.close().await?;
    share.close().await?;
    client.close().await
}
```

Operations are lazy futures. Deadlines, cancellation, and replay policy are
configured on the returned operation before it is awaited. File payloads use
`bytes::Bytes`, so slicing and handoff do not copy the underlying buffer.

Use explicit extensions for less common capabilities such as security
descriptors and typed RPC pipes; ordinary file and directory code remains on
the object hierarchy above.

## Feature flags

| Type | Algorithm | Feature |
| --- | --- | --- |
| Authentication | Kerberos | `kerberos` |
| Transport | QUIC | `quic` |
| Signing | all supported | `sign` |
| Signing | HMAC-SHA256 | `sign_hmac` |
| Signing | AES-GMAC | `sign_gmac` |
| Signing | AES-CMAC | `sign_cmac` |
| Encryption | all supported | `encrypt` |
| Encryption | AES-CCM | `encrypt_aesccm` |
| Encryption | AES-GCM | `encrypt_aesgcm` |
| Compression | all supported | `compress` |
| Compression | LZ4 | `compress_lz4` |
| Compression | Pattern V1 | `compress_pattern_v1` |
