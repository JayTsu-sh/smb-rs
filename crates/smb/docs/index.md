# SMB

The `smb` crate is an asynchronous, pure-Rust SMB2/SMB3 client. Its public
object hierarchy follows the lifetime of remote objects:

`Client` → `Session` → `Share` → `File` / `Directory` / `Pipe`

## Basic usage

```rust,no_run
use bytes::Bytes;
use smb::{
    Client, Credentials, FileOpenOptions, SharePath, ShareTarget,
};

#[tokio::main]
async fn main() -> smb::Result<()> {
    let client = Client::new();
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
    client.close().await.map(|_| ())
}
```

Operations are lazy futures. Deadlines, cancellation, and replay policy are
configured on the returned operation before it is awaited. File payloads use
`bytes::Bytes`, so slicing and handoff do not copy the underlying buffer.

Use explicit extensions for less common capabilities such as security
descriptors and typed RPC pipes; ordinary file and directory code remains on
the object hierarchy above.

## Negotiated signing policy

`Client::new()` retains the default `SigningPolicy::Required`: authenticated
traffic must be signed or encrypted. To omit ordinary message signing when
neither endpoint requires it:

```rust
use smb::{Client, SigningPolicy};

let client = Client::with_signing_policy(SigningPolicy::WhenRequired);
```

`WhenRequired` advertises signing support without requiring it. The client's
policy and the server's NEGOTIATE signing requirement determine the session
policy. Server-required signing always wins, including after reconnect.
Unsigned ordinary responses do not run signature verification; signed responses
are still verified and corrupted signatures are rejected. Authentication,
multichannel binding, SMB 3.1.1 TREE_CONNECT and encryption integrity protection
are not disabled. The policy belongs to the client, so its cached connections
and sessions cannot accidentally mix different policies.

Without SMB encryption, omitted signing means ordinary traffic has no SMB
message integrity protection. This option is not a general “ignore invalid
signatures” switch.

## Guest and anonymous sessions

Servers that map unknown or password-less users to a guest account (ONTAP
`guest-unix-user`, Samba `map to guest`) answer SessionSetup with
`SMB2_SESSION_FLAG_IS_GUEST`. Such sessions have no session key, so their
traffic can be neither signed nor encrypted (MS-SMB2 3.2.5.3.1); by default the
client rejects them at the final SessionSetup reply. Opt in explicitly:

```rust
use smb::{Client, GuestPolicy, SigningPolicy};

let client = Client::with_policies(SigningPolicy::WhenRequired, GuestPolicy::AllowUnsigned);
```

`GuestPolicy::AllowUnsigned` accepts guest and null sessions only when the
server does not require signing; server-required signing still wins. The NTLM
layer refuses an empty identity, so anonymous access is reached with a
placeholder username the server does not know. Guest traffic carries no SMB
message integrity protection.

## Renaming

`File::rename` / `Directory::rename` move an entry within the share and fail
with `STATUS_OBJECT_NAME_COLLISION` when the destination exists;
`File::rename_replace` / `Directory::rename_replace` ask the server to replace
it (NTFS-style servers only replace files and empty directories).

## Feature flags

| Type | Algorithm | Feature |
| --- | --- | --- |
| Authentication | Kerberos | `kerberos` |
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
