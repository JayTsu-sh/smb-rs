//! Timestamp mutation without exposing wire types or requiring data access.
use std::time::SystemTime;

use super::{
    Directory, File, FileCloseAuthority, OpenInfo, OpenKind, Operation, ReplayPolicy, Resource,
    Share, SharePath,
};
use crate::{Error, runtime::port::RuntimeResource};

/// Optional timestamps. Unspecified fields remain unchanged; values are rounded down to 100 ns.
/// Change time is maintained by the server and is intentionally not copied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataUpdate {
    pub created: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub written: Option<SystemTime>,
}

/// Open an existing file or directory with attribute access only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataOpenOptions {
    write: bool,
}
impl MetadataOpenOptions {
    pub const fn write_attributes(mut self, write: bool) -> Self {
        self.write = write;
        self
    }
}

impl Share {
    pub fn open_metadata<'a>(
        &'a self,
        path: &SharePath,
        options: MetadataOpenOptions,
    ) -> Operation<'a, Resource> {
        let path = path.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "metadata open permits only ReplayPolicy::Never".into(),
                    ));
                }
                let resource = self
                    .inner
                    .runtime
                    .open_metadata_resource(path.as_str(), options.write)
                    .await?;
                self.record_resource_open();
                Ok(match resource {
                    RuntimeResource::File(inner) => Resource::File(Box::new(File {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::File, path.as_str()),
                    })),
                    RuntimeResource::Directory(inner) => Resource::Directory(Directory {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Directory, path.as_str()),
                    }),
                    RuntimeResource::Pipe(inner) => Resource::Pipe(super::Pipe {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Pipe, path.as_str()),
                    }),
                })
            })
        })
    }
}

impl Resource {
    pub fn set_metadata(&self, update: MetadataUpdate) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                match self {
                    Resource::File(file) => {
                        file.inner
                            .set_metadata(update.created, update.accessed, update.written)
                            .await
                    }
                    Resource::Directory(dir) => {
                        dir.inner
                            .set_metadata(update.created, update.accessed, update.written)
                            .await
                    }
                    Resource::Pipe(_) => Err(Error::UnsupportedOperation(
                        "pipe timestamps are unsupported".into(),
                    )),
                }
            })
        })
    }
}

impl File {
    pub fn set_metadata(&self, update: MetadataUpdate) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner
                    .set_metadata(update.created, update.accessed, update.written)
                    .await
            })
        })
    }
}
impl Directory {
    pub fn set_metadata(&self, update: MetadataUpdate) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner
                    .set_metadata(update.created, update.accessed, update.written)
                    .await
            })
        })
    }
}
