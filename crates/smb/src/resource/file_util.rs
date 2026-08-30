use tokio::sync::Mutex;

pub trait ReadAtChannel {
    fn read_at_channel(
        &self,
        buf: &mut [u8],
        offset: u64,
        channel: Option<u32>,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send;
}

pub trait ReadAt {
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send;
}

impl<T: ReadAtChannel + ?Sized> ReadAt for T {
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send {
        self.read_at_channel(buf, offset, None)
    }
}

pub trait WriteAtChannel {
    fn write_at_channel(
        &self,
        buf: &[u8],
        offset: u64,
        channel: Option<u32>,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send;
}

pub trait WriteAt {
    fn write_at(
        &self,
        buf: &[u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send;
}

impl<T: WriteAtChannel + ?Sized> WriteAt for T {
    fn write_at(
        &self,
        buf: &[u8],
        offset: u64,
    ) -> impl std::future::Future<Output = crate::Result<usize>> + Send {
        self.write_at_channel(buf, offset, None)
    }
}

#[allow(async_fn_in_trait)]
pub trait GetLen {
    async fn get_len(&self) -> crate::Result<u64>;
}

#[allow(async_fn_in_trait)]
pub trait SetLen {
    async fn set_len(&self, len: u64) -> crate::Result<()>;
}

#[cfg(feature = "std-fs-impls")]
mod impls {
    use super::*;

    use tokio::{
        fs::File,
        io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    };

    pub trait ReadSeek: AsyncRead + AsyncSeek + Unpin {}
    impl ReadSeek for File {}
    impl<F: ReadSeek + Send> ReadAtChannel for Mutex<F> {
        async fn read_at_channel(
            &self,
            buf: &mut [u8],
            offset: u64,
            _channel: Option<u32>,
        ) -> crate::Result<usize> {
            let mut reader = self.lock().await;
            reader.seek(std::io::SeekFrom::Start(offset)).await?;
            Ok(reader.read(buf).await?)
        }
    }

    pub trait WriteSeek: AsyncWrite + AsyncSeek + Unpin {}
    impl WriteSeek for File {}
    impl<F: WriteSeek + Send> WriteAtChannel for Mutex<F> {
        async fn write_at_channel(
            &self,
            buf: &[u8],
            offset: u64,
            _channel: Option<u32>,
        ) -> crate::Result<usize> {
            let mut writer = self.lock().await;
            writer.seek(std::io::SeekFrom::Start(offset)).await?;
            Ok(writer.write(buf).await?)
        }
    }

    impl GetLen for Mutex<File> {
        async fn get_len(&self) -> crate::Result<u64> {
            let file = self.lock().await;
            Ok(file.metadata().await?.len())
        }
    }

    impl SetLen for Mutex<File> {
        async fn set_len(&self, len: u64) -> crate::Result<()> {
            let file = self.lock().await;
            Ok(File::set_len(&file, len).await?)
        }
    }
}
