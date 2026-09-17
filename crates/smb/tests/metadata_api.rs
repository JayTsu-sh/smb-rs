//! Compile contracts for the attribute-only public facade.
use smb::{
    Directory, File, MetadataOpenOptions, MetadataUpdate, Operation, Resource, Share, SharePath,
};
use std::time::UNIX_EPOCH;

#[test]
fn timestamp_operations_are_lazy_and_use_only_public_types() {
    fn open<'a>(share: &'a Share, path: &SharePath) -> Operation<'a, Resource> {
        share.open_metadata(path, MetadataOpenOptions::default().write_attributes(true))
    }
    fn resource(resource: &Resource) -> Operation<'_, ()> {
        resource.set_metadata(MetadataUpdate {
            written: Some(UNIX_EPOCH),
            ..Default::default()
        })
    }
    fn file(file: &File) -> Operation<'_, ()> {
        file.set_metadata(MetadataUpdate::default())
    }
    fn directory(directory: &Directory) -> Operation<'_, ()> {
        directory.set_metadata(MetadataUpdate::default())
    }
    let _ = (open, resource, file, directory);
    let update = MetadataUpdate {
        written: Some(UNIX_EPOCH),
        ..Default::default()
    };
    assert_eq!(update.created, None);
    assert_eq!(update.accessed, None);
    assert_eq!(update.written, Some(UNIX_EPOCH));
}
