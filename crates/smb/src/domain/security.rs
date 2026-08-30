pub use smb_dtyp::SecurityDescriptor;

use super::{Operation, Resource};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecuritySelection {
    dacl: bool,
}

impl SecuritySelection {
    pub const fn dacl(mut self, include: bool) -> Self {
        self.dacl = include;
        self
    }

    pub const fn includes_dacl(self) -> bool {
        self.dacl
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecurityOpenOptions {
    write_dacl: bool,
}

impl SecurityOpenOptions {
    pub const fn write_dacl(mut self, write: bool) -> Self {
        self.write_dacl = write;
        self
    }

    pub(crate) const fn writes_dacl(self) -> bool {
        self.write_dacl
    }
}

impl Resource {
    pub fn query_security(
        &self,
        selection: SecuritySelection,
    ) -> Operation<'_, SecurityDescriptor> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                match self {
                    Resource::File(file) => file.inner.query_security(selection.dacl).await,
                    Resource::Directory(directory) => {
                        directory.inner.query_security(selection.dacl).await
                    }
                    Resource::Pipe(pipe) => pipe.inner.query_security(selection.dacl).await,
                }
            })
        })
    }

    pub fn set_security(
        &self,
        descriptor: SecurityDescriptor,
        selection: SecuritySelection,
    ) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                match self {
                    Resource::File(file) => {
                        file.inner.set_security(descriptor, selection.dacl).await
                    }
                    Resource::Directory(directory) => {
                        directory
                            .inner
                            .set_security(descriptor, selection.dacl)
                            .await
                    }
                    Resource::Pipe(pipe) => {
                        pipe.inner.set_security(descriptor, selection.dacl).await
                    }
                }
            })
        })
    }
}
