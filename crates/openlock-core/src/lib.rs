//! Heap-free TOTP authorization with durable replay protection and throttling.
#![cfg_attr(not(feature = "std"), no_std)]

pub use openlock_crypto::TotpSecret;
use openlock_crypto::{time_step, verify_totp_at_step};
pub use openlock_types::{CredentialId, Error, LockId, UnlockRequest, UnlockResponse, Validity};
use openlock_types::{ALLOWED_CLOCK_SKEW_STEPS, MAX_ATTEMPTS_PER_STEP};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageState {
    /// A high-water mark: this step and every earlier step are unusable.
    pub last_accepted_step: Option<u64>,
    pub uses: u32,
}

/// Local configuration, never a wire payload. Each credential has its own key.
#[derive(Clone, Debug)]
pub struct Credential {
    pub lock_id: LockId,
    pub id: CredentialId,
    pub secret: TotpSecret,
    pub enabled: bool,
    pub validity: Option<Validity>,
    pub max_uses: Option<u32>,
    pub usage: UsageState,
}
impl Credential {
    pub fn validate(&self) -> Result<(), Error> {
        if self.id.0 == 0 || self.max_uses == Some(0) {
            return Err(Error::InvalidPayload);
        }
        if let Some(validity) = self.validity {
            validity.validate()?;
        }
        if self.usage.last_accepted_step.is_none() != (self.usage.uses == 0) {
            return Err(Error::StorageUnavailable);
        }
        Ok(())
    }
}

/// Lock-wide persisted budget; includes successful and failed attempts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AttemptState {
    pub last_attempt_at: Option<u64>,
    pub attempts: u8,
}

/// Firmware supplies storage. All operations for a lock (across BLE, NFC and
/// reconnects) MUST be serialized through one owner. Commits MUST be atomic and
/// durable before returning success; a reboot must load the latest state.
///
/// Never treat a read error/corruption as empty state. Factory defaults are only
/// valid for a newly provisioned key. Resetting usage requires a fresh key.
/// Do not serialize these Rust structs by memory layout; use explicit fields.
pub trait PersistentState {
    fn load_attempts(&self) -> Result<AttemptState, Error>;
    fn commit_attempts(&mut self, state: &AttemptState) -> Result<(), Error>;
    fn load_credential(&self, id: CredentialId) -> Result<Option<Credential>, Error>;
    fn commit_usage(&mut self, id: CredentialId, state: &UsageState) -> Result<(), Error>;
}

pub struct LockState<S> {
    lock_id: LockId,
    storage: S,
}
impl<S: PersistentState> LockState<S> {
    pub fn new(lock_id: LockId, storage: S) -> Self {
        Self { lock_id, storage }
    }
    pub fn storage(&self) -> &S {
        &self.storage
    }
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// The only access operation. `now` is trusted local Unix time; pass None
    /// after RTC loss or when time is uncertain. Never use the request as a clock.
    /// A successful verification is consumed BEFORE invoking the actuator.
    /// Callback errors, lost replies and restarts do not restore an OTP.
    pub fn unlock(
        &mut self,
        request: &UnlockRequest,
        now: Option<u64>,
        actuator: impl FnOnce() -> Result<(), ActuationError>,
    ) -> Result<(), Error> {
        request.validate()?;
        let now = now.ok_or(Error::ClockUntrusted)?;
        let step = time_step(now);
        if request.time_step.abs_diff(step) > ALLOWED_CLOCK_SKEW_STEPS {
            return Err(Error::InvalidTotp);
        }
        self.reserve_attempt(now)?;
        let credential = self
            .storage
            .load_credential(request.credential_id)
            .map_err(|_| Error::StorageUnavailable)?
            .ok_or(Error::UnknownCredential)?;
        credential.validate()?;
        if credential.id != request.credential_id {
            return Err(Error::StorageUnavailable);
        }
        if credential.lock_id != self.lock_id {
            return Err(Error::WrongLock);
        }
        if !credential.enabled {
            return Err(Error::Revoked);
        }
        if let Some(validity) = credential.validity {
            if now < validity.not_before || now >= validity.not_after {
                return Err(Error::Expired);
            }
        }
        if credential
            .usage
            .last_accepted_step
            .is_some_and(|last| request.time_step <= last)
        {
            return Err(Error::Replayed);
        }
        if credential
            .max_uses
            .is_some_and(|max| credential.usage.uses >= max)
        {
            return Err(Error::UsageExhausted);
        }
        if !verify_totp_at_step(&credential.secret, request.time_step, request.code) {
            return Err(Error::InvalidTotp);
        }
        let usage = UsageState {
            last_accepted_step: Some(request.time_step),
            uses: credential
                .usage
                .uses
                .checked_add(1)
                .ok_or(Error::UsageExhausted)?,
        };
        self.storage
            .commit_usage(credential.id, &usage)
            .map_err(|_| Error::StorageUnavailable)?;
        actuator().map_err(|_| Error::ActuatorFailed)
    }

    fn reserve_attempt(&mut self, now: u64) -> Result<(), Error> {
        let previous = self
            .storage
            .load_attempts()
            .map_err(|_| Error::StorageUnavailable)?;
        if previous.attempts > MAX_ATTEMPTS_PER_STEP
            || previous.last_attempt_at.is_none() != (previous.attempts == 0)
        {
            return Err(Error::StorageUnavailable);
        }
        let attempts = match previous.last_attempt_at {
            Some(last) if now < last => return Err(Error::ClockUntrusted),
            Some(last) if time_step(last) == time_step(now) => previous.attempts,
            _ => 0,
        };
        if attempts >= MAX_ATTEMPTS_PER_STEP {
            return Err(Error::RateLimited);
        }
        // Reserve even invalid codes and unknown IDs before examining a key.
        // The budget therefore survives an attacker cutting power mid-check.
        self.storage
            .commit_attempts(&AttemptState {
                last_attempt_at: Some(now),
                attempts: attempts + 1,
            })
            .map_err(|_| Error::StorageUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuationError {
    Failed,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use openlock_crypto::unlock_request;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct Store {
        credential: Credential,
        attempts: AttemptState,
        fail_attempts: bool,
        fail_usage: bool,
        fail_after_usage_write: bool,
        fail_read: bool,
        committed: Rc<Cell<bool>>,
    }
    impl PersistentState for Store {
        fn load_attempts(&self) -> Result<AttemptState, Error> {
            if self.fail_read {
                Err(Error::StorageUnavailable)
            } else {
                Ok(self.attempts)
            }
        }
        fn commit_attempts(&mut self, state: &AttemptState) -> Result<(), Error> {
            if self.fail_attempts {
                return Err(Error::StorageUnavailable);
            }
            self.attempts = *state;
            Ok(())
        }
        fn load_credential(&self, id: CredentialId) -> Result<Option<Credential>, Error> {
            Ok((id == self.credential.id).then(|| self.credential.clone()))
        }
        fn commit_usage(&mut self, id: CredentialId, state: &UsageState) -> Result<(), Error> {
            assert_eq!(id, self.credential.id);
            if self.fail_usage {
                return Err(Error::StorageUnavailable);
            }
            self.credential.usage = *state;
            self.committed.set(true);
            if self.fail_after_usage_write {
                return Err(Error::StorageUnavailable);
            }
            Ok(())
        }
    }
    fn fixture() -> (LockState<Store>, UnlockRequest) {
        let credential = Credential {
            lock_id: LockId([1; 16]),
            id: CredentialId(7),
            secret: TotpSecret::new([9; 32]),
            enabled: true,
            validity: None,
            max_uses: None,
            usage: UsageState::default(),
        };
        let request = unlock_request(&credential.secret, credential.id, 300).unwrap();
        let store = Store {
            credential,
            attempts: AttemptState::default(),
            fail_attempts: false,
            fail_usage: false,
            fail_after_usage_write: false,
            fail_read: false,
            committed: Rc::new(Cell::new(false)),
        };
        (LockState::new(LockId([1; 16]), store), request)
    }
    fn must_not_actuate() -> Result<(), ActuationError> {
        panic!("unexpected actuation")
    }

    #[test]
    fn consumes_before_actuation_and_rejects_replay_after_reboot() {
        let (mut lock, request) = fixture();
        let committed = lock.storage().committed.clone();
        lock.unlock(&request, Some(300), || {
            assert!(committed.get());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            lock.unlock(&request, Some(301), must_not_actuate),
            Err(Error::Replayed)
        );
        let mut rebooted = LockState::new(LockId([1; 16]), lock.into_storage());
        assert_eq!(
            rebooted.unlock(&request, Some(330), must_not_actuate),
            Err(Error::Replayed)
        );
        assert_eq!(rebooted.storage().credential.usage.uses, 1);
    }

    #[test]
    fn an_ambiguous_actuator_failure_still_consumes_the_otp() {
        let (mut lock, request) = fixture();
        assert_eq!(
            lock.unlock(&request, Some(300), || Err(ActuationError::Failed)),
            Err(Error::ActuatorFailed)
        );
        assert_eq!(
            lock.unlock(&request, Some(300), must_not_actuate),
            Err(Error::Replayed)
        );
        assert_eq!(lock.storage().credential.usage.uses, 1);
    }

    #[test]
    fn every_storage_failure_fails_closed() {
        for mode in 0..3 {
            let (mut lock, request) = fixture();
            lock.storage.fail_attempts = mode == 0;
            lock.storage.fail_usage = mode == 1;
            lock.storage.fail_read = mode == 2;
            assert_eq!(
                lock.unlock(&request, Some(300), must_not_actuate),
                Err(Error::StorageUnavailable)
            );
            assert_eq!(lock.storage().credential.usage, UsageState::default());
        }
    }

    #[test]
    fn a_commit_that_writes_then_errors_never_restores_the_otp() {
        let (mut lock, request) = fixture();
        lock.storage.fail_after_usage_write = true;
        assert_eq!(
            lock.unlock(&request, Some(300), must_not_actuate),
            Err(Error::StorageUnavailable)
        );
        let mut recovered = LockState::new(LockId([1; 16]), lock.into_storage());
        recovered.storage.fail_after_usage_write = false;
        assert_eq!(
            recovered.unlock(&request, Some(301), must_not_actuate),
            Err(Error::Replayed)
        );
        assert_eq!(recovered.storage().credential.usage.uses, 1);
    }

    #[test]
    fn window_checks_boundaries_and_rejects_untrusted_time() {
        for (at, valid) in [
            (269, false),
            (270, true),
            (299, true),
            (300, true),
            (329, true),
            (330, true),
            (359, true),
            (360, false),
        ] {
            let (mut lock, request) = fixture();
            let result = lock.unlock(&request, Some(at), || {
                assert!(valid);
                Ok(())
            });
            assert_eq!(
                result,
                if valid {
                    Ok(())
                } else {
                    Err(Error::InvalidTotp)
                }
            );
        }
        let (mut lock, request) = fixture();
        assert_eq!(
            lock.unlock(&request, None, must_not_actuate),
            Err(Error::ClockUntrusted)
        );
        lock.unlock(&request, Some(310), || Ok(())).unwrap();
        assert_eq!(
            lock.unlock(&request, Some(309), must_not_actuate),
            Err(Error::ClockUntrusted)
        );
    }

    #[test]
    fn future_step_consumption_also_blocks_older_unconsumed_codes() {
        let (mut lock, current) = fixture();
        let next = unlock_request(
            &lock.storage().credential.secret,
            current.credential_id,
            330,
        )
        .unwrap();
        lock.unlock(&next, Some(300), || Ok(())).unwrap();
        assert_eq!(
            lock.unlock(&current, Some(300), must_not_actuate),
            Err(Error::Replayed)
        );
        let later = unlock_request(
            &lock.storage().credential.secret,
            current.credential_id,
            360,
        )
        .unwrap();
        lock.unlock(&later, Some(360), || Ok(())).unwrap();
    }

    #[test]
    fn bad_codes_do_not_consume_but_throttle_survives_restarts_and_id_changes() {
        let (mut lock, mut bad) = fixture();
        bad.code ^= 1;
        for _ in 0..MAX_ATTEMPTS_PER_STEP {
            assert_eq!(
                lock.unlock(&bad, Some(300), must_not_actuate),
                Err(Error::InvalidTotp)
            );
            lock = LockState::new(LockId([1; 16]), lock.into_storage());
        }
        assert_eq!(lock.storage().credential.usage, UsageState::default());
        bad.credential_id = CredentialId(99);
        assert_eq!(
            lock.unlock(&bad, Some(301), must_not_actuate),
            Err(Error::RateLimited)
        );
        assert_eq!(
            lock.unlock(&bad, Some(330), must_not_actuate),
            Err(Error::UnknownCredential)
        );
    }

    #[test]
    fn unknown_ids_spend_the_same_global_budget() {
        let (mut lock, mut request) = fixture();
        for id in 20..25 {
            request.credential_id = CredentialId(id);
            assert_eq!(
                lock.unlock(&request, Some(300), must_not_actuate),
                Err(Error::UnknownCredential)
            );
        }
        request.credential_id = CredentialId(7);
        assert_eq!(
            lock.unlock(&request, Some(300), must_not_actuate),
            Err(Error::RateLimited)
        );
    }

    #[test]
    fn local_policy_and_credential_binding_are_enforced() {
        for error in [
            Error::Revoked,
            Error::WrongLock,
            Error::Expired,
            Error::UsageExhausted,
        ] {
            let (mut lock, request) = fixture();
            match error {
                Error::Revoked => lock.storage.credential.enabled = false,
                Error::WrongLock => lock.storage.credential.lock_id = LockId([2; 16]),
                Error::Expired => {
                    lock.storage.credential.validity = Some(Validity {
                        not_before: 100,
                        not_after: 300,
                    })
                }
                Error::UsageExhausted => {
                    lock.storage.credential.max_uses = Some(1);
                    lock.storage.credential.usage = UsageState {
                        last_accepted_step: Some(9),
                        uses: 1,
                    };
                }
                _ => unreachable!(),
            }
            assert_eq!(
                lock.unlock(&request, Some(300), must_not_actuate),
                Err(error)
            );
        }
    }

    #[test]
    fn extreme_timestamps_and_corrupt_storage_cannot_bypass_checks() {
        let (mut lock, mut request) = fixture();
        request.time_step = u64::MAX;
        assert_eq!(
            lock.unlock(&request, Some(0), must_not_actuate),
            Err(Error::InvalidTotp)
        );
        request = unlock_request(&lock.storage.credential.secret, CredentialId(7), 0).unwrap();
        lock.unlock(&request, Some(0), || Ok(())).unwrap();
        assert_eq!(
            lock.unlock(&request, Some(0), must_not_actuate),
            Err(Error::Replayed)
        );
        lock.storage.attempts = AttemptState {
            last_attempt_at: None,
            attempts: 1,
        };
        assert_eq!(
            lock.unlock(&request, Some(0), must_not_actuate),
            Err(Error::StorageUnavailable)
        );
    }
}
