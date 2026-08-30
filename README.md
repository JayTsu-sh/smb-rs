# smb-rs: The SMB2 Client in Rust

[![Build](https://github.com/afiffon/smb-rs/actions/workflows/build.yml/badge.svg)](https://github.com/afiffon/smb-rs/actions/workflows/build.yml)
[![Crates.io](https://img.shields.io/crates/v/smb)](https://crates.io/crates/smb)
[![docs.rs](https://img.shields.io/docsrs/smb/latest?link=https%3A%2F%2Fdocs.rs%2Fsmb%2Flatest%2Fsmb%2Findex.html)](https://docs.rs/smb/latest/smb/index.html)

This project is the first rust implementation of
[SMB2 & 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) client --
the protocol that powers Windows file sharing and remote services.
The project is designed as a Rust library crate with an asynchronous domain interface.

While most current implementations are mostly bindings to C libraries (such as libsmb2, samba, or windows' own libraries), this project is a full implementation in Rust, with no _direct_ dependencies on C libraries.

## Getting started

Add the `smb` crate to an asynchronous Rust application and use the public
`Client -> Session -> Share -> File / Directory / Pipe` object hierarchy.

## Features

- ✅ All SMB 2.X & 3.X dialects support.
- ✅ Wire message parsing is fully safe, using the `binrw` crate.
- ✅ Async (`tokio`), Multi-threaded, or Single-threaded client.
- ✅ Compression & Encryption support.
- ✅ Transport using SMB over TCP (445) and NetBIOS (139).
- ✅ NTLM & Kerberos authentication (using the [`sspi`](https://crates.io/crates/sspi) crate).
- ✅ Cross-platform (Windows, Linux, MacOS).

You are welcome to see the project's roadmap in the [GitHub Project](https://github.com/users/afiffon/projects/2).

## Using the crate

Check out the `Client` struct, exported from the `smb` crate, to initiate a connection to an SMB server:

```rust,no_run
use smb::{Client, Credentials, FileOpenOptions, SharePath, ShareTarget};

#[tokio::main]
async fn main() -> smb::Result<()> {
    let client = Client::new();
    let target = ShareTarget::new("server", "share")?;
    let share = client
        .connect_share(&target, Credentials::ntlm("username", "password"))
        .await?;
    let file = share
        .open_file(&SharePath::new("file.txt")?, FileOpenOptions::open_existing())
        .await?;
    let data = file.read_at(0, 4096).await?;
    println!("read {} bytes", data.len());
    file.close().await?;
    share.close().await?;
    client.close().await
}
```

Check out the [docs.rs](https://docs.rs/smb/latest/smb/index.html) for more information regarding usage.

## Development

To set up a development environment, you may use any supported rust version.

- It is highly recommended to use rust nightly, and install pre-commit hooks (using `pip install pre-commit && pre-commit install`)
- Before committing your changes, run `cargo fmt` to format the code, and `cargo clippy` to check for linting issues.
- Run crate tests once you are ready to commit. Read tests' README.md before proceeding!
