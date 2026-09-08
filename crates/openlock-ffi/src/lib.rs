//! Small C ABI surface for embedding the transport-independent core.

use openlock_core::{credential_id, CredentialId};

#[repr(C)]
pub struct OpenLockCredentialId {
    pub bytes: [u8; 16],
}

#[no_mangle]
/// # Safety
/// `data` must point to `len` readable bytes and `out` must point to writable
/// storage for one `OpenLockCredentialId` for the duration of this call.
pub unsafe extern "C" fn openlock_credential_id(
    data: *const u8,
    len: usize,
    out: *mut OpenLockCredentialId,
) -> i32 {
    if data.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: callers provide a valid immutable byte slice and writable output
    // pointer for the duration of this call, as required by the C header.
    let bytes = std::slice::from_raw_parts(data, len);
    let CredentialId(id) = credential_id(bytes);
    (*out).bytes = id;
    0
}
