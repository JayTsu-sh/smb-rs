use thiserror::Error;

/// Transport-related errors.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Invalid transport message")]
    InvalidMessage,
    #[error("transport frame length {announced} exceeds hard maximum {maximum}")]
    FrameTooLarge { announced: usize, maximum: usize },
    #[error("outbound segment count {actual} exceeds transport maximum {maximum}")]
    SegmentLimitExceeded { actual: usize, maximum: usize },
    #[error("send cursor advance {requested} exceeds remaining {remaining}")]
    CursorAdvanceOutOfBounds { requested: usize, remaining: usize },
    #[error("transport vectored write returned zero before frame completion")]
    WriteZero,
    #[error("Failed to parse transport message {0}")]
    ParseError(#[from] binrw::Error),
    #[error("Not connected")]
    NotConnected,
    #[error("Connection already split")]
    AlreadySplit,
    #[error("Timed out after {}s", .0.as_secs())]
    Timeout(std::time::Duration),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TransportError>;
