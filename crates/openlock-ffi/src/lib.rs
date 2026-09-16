//! OpenLock v3 C ABI: secure v2 sessions and optional plaintext TOTP helpers.
//! Both schemes are enabled by default; choose features explicitly for a smaller
//! library. Enabling TOTP does not alter or downgrade secure-session behavior.

#[cfg(feature = "secure")]
mod secure;
#[cfg(feature = "secure")]
pub use secure::*;
#[cfg(feature = "totp")]
mod totp;
#[cfg(feature = "totp")]
pub use totp::*;

#[cfg(all(test, feature = "secure", feature = "totp"))]
mod tests {
    use super::*;

    #[test]
    fn both_abis_coexist_and_secure_sessions_do_not_fall_back_to_totp() {
        let private = [3; 32];
        let public = [9; 32];
        let mut session = std::ptr::null_mut();
        let mut buffer = [0; 4096];
        let mut length = 0;
        // SAFETY: keys and all buffers have the lengths required by the ABI;
        // the session is constructed once and freed once below.
        unsafe {
            assert_eq!(
                openlock_session_initiator(private.as_ptr(), public.as_ptr(), 1, &mut session),
                0
            );
            assert_eq!(
                openlock_session_start(session, buffer.as_mut_ptr(), buffer.len(), &mut length),
                0
            );
            let packet = openlock_protocol::decode_packet(&buffer[..length]).unwrap();
            assert_eq!(packet.kind, openlock_protocol::KIND_HANDSHAKE);
            assert_eq!(openlock_types::PROTOCOL_VERSION, 2);
            let mut request = OpenLockRequest::default();
            assert_eq!(
                openlock_decode_unlock(buffer.as_ptr(), length, &mut request),
                3
            );

            let key = b"12345678901234567890123456789012";
            let mut totp = [0; 18];
            assert_eq!(
                openlock_make_unlock(
                    key.as_ptr(),
                    7,
                    59,
                    totp.as_mut_ptr(),
                    totp.len(),
                    &mut length
                ),
                0
            );
            assert_eq!(
                openlock_decode_unlock(totp.as_ptr(), length, &mut request),
                0
            );
            assert_eq!(request.code, 46_119_246);
            let mut event = 0;
            assert_ne!(
                openlock_session_receive(
                    session,
                    totp.as_ptr(),
                    length,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut length,
                    &mut event
                ),
                0
            );
            assert_eq!(event, 0);
            openlock_session_free(session);
        }
    }
}
