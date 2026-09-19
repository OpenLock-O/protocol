//! Firmware signatures use an independent root and domain from access grants.
use crate::{
    cose::{sign_object, verify_object},
    wire::Wire,
    SigningKey, VerifyingKey,
};
use alloc::vec::Vec;
use openlock_types::{Error, FirmwareManifest};
pub const FIRMWARE_DOMAIN: &[u8] = b"openlock:v4:firmware";
pub fn validate_manifest(m: &FirmwareManifest) -> Result<(), Error> {
    if m.model.is_empty()
        || m.model.len() > 64
        || m.hardware.is_empty()
        || m.hardware.len() > 64
        || m.version.is_empty()
        || m.version.len() > 64
        || m.size == 0
        || m.security_version == 0
    {
        return Err(Error::FirmwareInvalid);
    }
    Ok(())
}
pub fn sign_manifest(key: &SigningKey, manifest: &FirmwareManifest) -> Result<Vec<u8>, Error> {
    validate_manifest(manifest)?;
    sign_object(key, FIRMWARE_DOMAIN, &manifest.value())
}
pub fn read_manifest(key: &VerifyingKey, bytes: &[u8]) -> Result<FirmwareManifest, Error> {
    let m = FirmwareManifest::parse(&verify_object(key, FIRMWARE_DOMAIN, bytes)?)?;
    validate_manifest(&m)?;
    Ok(m)
}
