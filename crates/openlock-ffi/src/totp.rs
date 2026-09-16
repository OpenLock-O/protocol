//! Stateless host-side C ABI. Lock authorization uses openlock-totp::core, including
//! its mandatory durable replay/throttle state; decoding is not authorization.

use openlock_totp::crypto::{totp, unlock_request, TotpSecret};
use openlock_totp::protocol::{decode_response, decode_unlock, encode_response, encode_unlock};
use openlock_totp::types::{CredentialId, Error, UnlockRequest, UnlockResponse};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenLockRequest {
    pub credential_id: u32,
    pub time_step: u64,
    pub code: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenLockResponse {
    pub credential_id: u32,
    pub time_step: u64,
    pub error_code: u32,
}

unsafe fn secret_from_ptr(secret: *const u8) -> TotpSecret {
    TotpSecret::new(std::slice::from_raw_parts(secret, 32).try_into().unwrap())
}
unsafe fn copy_out(bytes: &[u8], out: *mut u8, capacity: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() || (capacity > 0 && out.is_null()) {
        return -1;
    }
    *out_len = bytes.len();
    if capacity < bytes.len() {
        return -2;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    0
}

#[no_mangle]
/// # Safety
/// `secret` points to 32 readable bytes; `out_code` is aligned and writable.
/// This generates an OTP only; it does not authorize or consume anything.
pub unsafe extern "C" fn openlock_totp(
    secret: *const u8,
    unix_seconds: u64,
    out_code: *mut u32,
) -> i32 {
    if secret.is_null() || out_code.is_null() {
        return -1;
    }
    out_code.write(totp(&secret_from_ptr(secret), unix_seconds));
    0
}

#[no_mangle]
/// # Safety
/// `secret` points to 32 readable bytes; `out` has `capacity` writable bytes;
/// `out_len` is aligned, writable and does not overlap `out`.
/// For a size query, pass NULL/0 for out/capacity; -2 reports required length.
pub unsafe extern "C" fn openlock_make_unlock(
    secret: *const u8,
    credential_id: u32,
    unix_seconds: u64,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if secret.is_null() {
        return -1;
    }
    match unlock_request(
        &secret_from_ptr(secret),
        CredentialId(credential_id),
        unix_seconds,
    )
    .and_then(|request| encode_unlock(&request))
    {
        Ok(bytes) => copy_out(&bytes, out, capacity, out_len),
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `out` has `capacity` writable bytes; `out_len` is aligned, writable and does
/// not overlap `out`. NULL/0 is a size query. This encodes a supplied OTP.
pub unsafe extern "C" fn openlock_encode_unlock(
    credential_id: u32,
    time_step: u64,
    code: u32,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    match encode_unlock(&UnlockRequest {
        credential_id: CredentialId(credential_id),
        time_step,
        code,
    }) {
        Ok(bytes) => copy_out(&bytes, out, capacity, out_len),
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `input` has `input_len` readable bytes; `out` is aligned and writable.
/// Decoding is not OTP verification or access authorization.
pub unsafe extern "C" fn openlock_decode_unlock(
    input: *const u8,
    input_len: usize,
    out: *mut OpenLockRequest,
) -> i32 {
    if input.is_null() || out.is_null() {
        return -1;
    }
    match decode_unlock(std::slice::from_raw_parts(input, input_len)) {
        Ok(request) => {
            out.write(OpenLockRequest {
                credential_id: request.credential_id.0,
                time_step: request.time_step,
                code: request.code,
            });
            0
        }
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `out` has `capacity` writable bytes; `out_len` is aligned, writable and does
/// not overlap `out`. NULL/0 is a size query. `error_code=0` means success.
pub unsafe extern "C" fn openlock_encode_response(
    credential_id: u32,
    time_step: u64,
    error_code: u32,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    let result = if error_code == 0 {
        Ok(())
    } else {
        match Error::from_code(error_code) {
            Some(error) => Err(error),
            None => return Error::InvalidPayload.code() as i32,
        }
    };
    match encode_response(&UnlockResponse {
        credential_id: CredentialId(credential_id),
        time_step,
        result,
    }) {
        Ok(bytes) => copy_out(&bytes, out, capacity, out_len),
        Err(error) => error.code() as i32,
    }
}

#[no_mangle]
/// # Safety
/// `input` has `input_len` readable bytes; `out` is aligned and writable.
/// The decoded response is unauthenticated and cannot prove physical opening.
pub unsafe extern "C" fn openlock_decode_response(
    input: *const u8,
    input_len: usize,
    out: *mut OpenLockResponse,
) -> i32 {
    if input.is_null() || out.is_null() {
        return -1;
    }
    match decode_response(std::slice::from_raw_parts(input, input_len)) {
        Ok(response) => {
            out.write(OpenLockResponse {
                credential_id: response.credential_id.0,
                time_step: response.time_step,
                error_code: response.result.err().map_or(0, Error::code),
            });
            0
        }
        Err(error) => error.code() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    #[test]
    fn ffi_vector_buffer_queries_and_nulls() {
        let key = b"12345678901234567890123456789012";
        let mut length = 0;
        let mut bytes = [0xa5; 18];
        let mut request = OpenLockRequest::default();
        // SAFETY: all test inputs/output buffers have the sizes required by ABI.
        unsafe {
            assert_eq!(
                openlock_make_unlock(key.as_ptr(), 7, 59, ptr::null_mut(), 0, &mut length),
                -2
            );
            assert_eq!(length, 18);
            assert_eq!(
                openlock_make_unlock(key.as_ptr(), 7, 59, bytes.as_mut_ptr(), 17, &mut length),
                -2
            );
            assert_eq!(bytes, [0xa5; 18]);
            assert_eq!(
                openlock_make_unlock(key.as_ptr(), 7, 59, bytes.as_mut_ptr(), 18, &mut length),
                0
            );
            assert_eq!(openlock_decode_unlock(bytes.as_ptr(), 18, &mut request), 0);
            assert_eq!(
                (request.credential_id, request.time_step, request.code),
                (7, 1, 46_119_246)
            );
            assert_eq!(openlock_totp(ptr::null(), 59, &mut request.code), -1);
            assert_eq!(openlock_decode_unlock(ptr::null(), 0, &mut request), -1);
            assert_eq!(
                openlock_make_unlock(key.as_ptr(), 0, 59, bytes.as_mut_ptr(), 18, &mut length),
                3
            );
            assert_eq!(
                openlock_make_unlock(key.as_ptr(), 7, 59, ptr::null_mut(), 18, &mut length),
                -1
            );
            assert_eq!(
                openlock_encode_unlock(7, 1, 100_000_000, bytes.as_mut_ptr(), 18, &mut length),
                3
            );
        }
    }
    #[test]
    fn response_reports_operation_errors_separately_from_abi_errors() {
        let mut bytes = [0; 15];
        let mut length = 0;
        let mut response = OpenLockResponse::default();
        unsafe {
            assert_eq!(
                openlock_encode_response(7, 1, 24, bytes.as_mut_ptr(), 15, &mut length),
                0
            );
            assert_eq!(
                openlock_decode_response(bytes.as_ptr(), 15, &mut response),
                0
            );
            assert_eq!(response.error_code, 24);
            assert_eq!(
                openlock_decode_response(bytes.as_ptr(), 14, &mut response),
                3
            );
            assert_eq!(
                openlock_encode_response(7, 1, 255, bytes.as_mut_ptr(), 15, &mut length),
                3
            );
        }
    }
}
