//! Small C ABI surface for embedding the transport-independent core.

use openlock_core::{credential_id, CredentialId};
use openlock_protocol::{Session, SessionEvent};
use openlock_types::{AccessRequest, Command, Error};

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

#[repr(C)]
pub struct OpenLockSession {
    inner: Session,
}

unsafe fn copy_out(bytes: &[u8], out: *mut u8, capacity: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() || (!bytes.is_empty() && out.is_null()) {
        return -1;
    }
    *out_len = bytes.len();
    if bytes.len() > capacity {
        return -2;
    }
    if !bytes.is_empty() {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    *out_len = bytes.len();
    0
}

#[no_mangle]
/// # Safety
/// `private_key` and `lock_public` point to 32 readable bytes and `out` is writable.
pub unsafe extern "C" fn openlock_session_initiator(
    private_key: *const u8,
    lock_public: *const u8,
    capabilities: u64,
    out: *mut *mut OpenLockSession,
) -> i32 {
    if private_key.is_null() || lock_public.is_null() || out.is_null() {
        return -1;
    }
    *out = std::ptr::null_mut();
    let private = &*(private_key as *const [u8; 32]);
    let public = &*(lock_public as *const [u8; 32]);
    match Session::initiator(private, public, capabilities) {
        Ok(inner) => {
            *out = Box::into_raw(Box::new(OpenLockSession { inner }));
            0
        }
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `private_key` points to 32 readable bytes and `out` is writable.
pub unsafe extern "C" fn openlock_session_responder(
    private_key: *const u8,
    capabilities: u64,
    out: *mut *mut OpenLockSession,
) -> i32 {
    if private_key.is_null() || out.is_null() {
        return -1;
    }
    *out = std::ptr::null_mut();
    let private = &*(private_key as *const [u8; 32]);
    match Session::responder(private, capabilities) {
        Ok(inner) => {
            *out = Box::into_raw(Box::new(OpenLockSession { inner }));
            0
        }
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `session` is a live handle; `out` and `out_len` are writable buffers.
pub unsafe extern "C" fn openlock_session_start(
    session: *mut OpenLockSession,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() {
        return -1;
    }
    match (*session).inner.start() {
        Ok(bytes) => copy_out(&bytes, out, capacity, out_len),
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `session` is live, `input` contains `input_len` readable bytes, and output pointers are valid.
pub unsafe extern "C" fn openlock_session_receive(
    session: *mut OpenLockSession,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
    event: *mut u32,
) -> i32 {
    if session.is_null() || (input_len > 0 && input.is_null()) || event.is_null() {
        return -1;
    }
    let input = if input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };
    match (*session).inner.receive(input) {
        Ok((events, reply)) => {
            *event = match events.first() {
                Some(SessionEvent::HandshakeComplete { .. }) => 1,
                Some(SessionEvent::Request { .. }) => 2,
                Some(SessionEvent::Response { .. }) => 3,
                None => 0,
            };
            copy_out(reply.as_deref().unwrap_or(&[]), out, capacity, out_len)
        }
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `session` is live, `credential` contains `credential_len` readable bytes, and output pointers are valid.
pub unsafe extern "C" fn openlock_session_send_unlock(
    session: *mut OpenLockSession,
    credential: *const u8,
    credential_len: usize,
    requested_use: i64,
    request_id: *mut u32,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() || (credential_len > 0 && credential.is_null()) || request_id.is_null() {
        return -1;
    }
    let requested_use = if requested_use < -1 || requested_use > u32::MAX as i64 {
        return -1;
    } else if requested_use == -1 {
        None
    } else {
        Some(requested_use as u32)
    };
    let credential = if credential_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(credential, credential_len)
    };
    let command = Command::Unlock(AccessRequest {
        credential: credential.to_vec(),
        requested_use,
    });
    match (*session).inner.send(command) {
        Ok((id, bytes)) => {
            *request_id = id;
            copy_out(&bytes, out, capacity, out_len)
        }
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `session` is either null or a handle returned by a constructor and not freed before this call.
pub unsafe extern "C" fn openlock_session_free(session: *mut OpenLockSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

#[allow(dead_code)]
fn _error_code(error: Error) -> i32 {
    error.code() as i32
}
