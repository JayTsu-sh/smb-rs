//! Attribute-only timestamp writes. Zero is reserved for unspecified fields.
use std::time::{SystemTime, UNIX_EPOCH};

use smb_dtyp::binrw_util::prelude::FileTime;
use smb_fscc::{FileAttributes, FileBasicInformation};

use crate::{Error, Result, resource::ResourceHandle};

const UNIX_OFFSET_NS: i128 = 11_644_473_600_i128 * 1_000_000_000;

pub(super) async fn set_metadata(
    resource: &ResourceHandle,
    created: Option<SystemTime>,
    accessed: Option<SystemTime>,
    written: Option<SystemTime>,
) -> Result<()> {
    let basic = basic_information(created, accessed, written)?;
    if created.is_none() && accessed.is_none() && written.is_none() {
        return Ok(());
    }
    resource.set_info(basic).await
}

fn basic_information(
    created: Option<SystemTime>,
    accessed: Option<SystemTime>,
    written: Option<SystemTime>,
) -> Result<FileBasicInformation> {
    Ok(FileBasicInformation {
        creation_time: file_time(created)?,
        last_access_time: file_time(accessed)?,
        last_write_time: file_time(written)?,
        change_time: FileTime::ZERO,
        file_attributes: FileAttributes::default(),
    })
}

fn file_time(value: Option<SystemTime>) -> Result<FileTime> {
    let Some(value) = value else {
        return Ok(FileTime::ZERO);
    };
    let unix_ns = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()),
        Err(error) => i128::try_from(error.duration().as_nanos()).map(|nanos| -nanos),
    }
    .map_err(|_| invalid_timestamp())?;
    let ticks = unix_ns
        .checked_add(UNIX_OFFSET_NS)
        .ok_or_else(invalid_timestamp)?
        .div_euclid(100);
    // Negative LARGE_INTEGER values and zero have protocol sentinel semantics.
    if ticks <= 0 || ticks > i128::from(i64::MAX) {
        return Err(invalid_timestamp());
    }
    let ticks = u64::try_from(ticks).map_err(|_| invalid_timestamp())?;
    Ok(FileTime::from(ticks))
}

fn invalid_timestamp() -> Error {
    Error::InvalidArgument("timestamp is outside the positive SMB FILETIME range".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn omitted_fields_and_change_time_are_unchanged() {
        let value = basic_information(None, None, Some(UNIX_EPOCH)).unwrap();
        assert_eq!(*value.creation_time, 0);
        assert_eq!(*value.last_access_time, 0);
        assert_eq!(*value.change_time, 0);
        assert_eq!(*value.last_write_time, 116_444_736_000_000_000);
        assert_eq!(value.file_attributes, FileAttributes::default());
    }

    #[test]
    fn timestamps_round_down_to_hundred_nanoseconds() {
        assert_eq!(
            *file_time(Some(UNIX_EPOCH + Duration::from_nanos(199))).unwrap(),
            116_444_736_000_000_001
        );
        assert_eq!(
            *file_time(Some(UNIX_EPOCH - Duration::from_nanos(1))).unwrap(),
            116_444_735_999_999_999
        );
    }

    #[test]
    fn sentinel_and_out_of_range_timestamps_are_rejected() {
        let epoch = UNIX_EPOCH - Duration::from_secs(11_644_473_600);
        assert!(file_time(Some(epoch)).is_err());
        assert!(file_time(Some(epoch + Duration::from_nanos(99))).is_err());
        assert!(file_time(Some(epoch - Duration::from_nanos(1))).is_err());
        assert!(file_time(Some(epoch + Duration::from_nanos(100))).is_ok());
        if let Some(too_large) = UNIX_EPOCH.checked_add(Duration::from_secs(u64::MAX / 100)) {
            assert!(file_time(Some(too_large)).is_err());
        }
    }
}
