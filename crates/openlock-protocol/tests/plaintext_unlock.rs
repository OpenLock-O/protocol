//! Full client/transport/lock path, with one shared durable state across links.
use openlock_core::{AttemptState, Credential, LockState, PersistentState, UsageState};
use openlock_crypto::{unlock_request, TotpSecret};
use openlock_protocol::{decode_response, decode_unlock, encode_response, encode_unlock};
use openlock_transport::FrameCodec;
use openlock_transport_ble::BleCodec;
use openlock_transport_nfc::IsoDepCodec;
use openlock_types::{CredentialId, Error, LockId, UnlockResponse};

struct Store {
    attempts: AttemptState,
    credentials: [Credential; 2],
}
impl PersistentState for Store {
    fn load_attempts(&self) -> Result<AttemptState, Error> {
        Ok(self.attempts)
    }
    fn commit_attempts(&mut self, state: &AttemptState) -> Result<(), Error> {
        self.attempts = *state;
        Ok(())
    }
    fn load_credential(&self, id: CredentialId) -> Result<Option<Credential>, Error> {
        Ok(self.credentials.iter().find(|c| c.id == id).cloned())
    }
    fn commit_usage(&mut self, id: CredentialId, state: &UsageState) -> Result<(), Error> {
        self.credentials
            .iter_mut()
            .find(|c| c.id == id)
            .unwrap()
            .usage = *state;
        Ok(())
    }
}
fn credential(id: u32, key: u8) -> Credential {
    Credential {
        lock_id: LockId([1; 16]),
        id: CredentialId(id),
        secret: TotpSecret::new([key; 32]),
        enabled: true,
        validity: None,
        max_uses: None,
        usage: UsageState::default(),
    }
}
fn lock() -> LockState<Store> {
    LockState::new(
        LockId([1; 16]),
        Store {
            attempts: AttemptState::default(),
            credentials: [credential(1, 7), credential(2, 8)],
        },
    )
}

#[test]
fn ble_unlock_nfc_replay_after_restart_and_independent_credential() {
    let ble = BleCodec::default();
    let nfc = IsoDepCodec;
    let mut lock = lock();
    let original = unlock_request(&TotpSecret::new([7; 32]), CredentialId(1), 1_800).unwrap();
    let packet = encode_unlock(&original).unwrap();
    assert_eq!(packet.len(), 18);
    let received = decode_unlock(ble.decode(ble.encode(&packet).unwrap()).unwrap()).unwrap();
    let mut actuations = 0;
    let outcome = lock.unlock(&received, Some(1_800), || {
        actuations += 1;
        Ok(())
    });
    let response = encode_response(&UnlockResponse::for_request(&received, outcome)).unwrap();
    let response = decode_response(ble.decode(&response).unwrap()).unwrap();
    assert_eq!(
        (response.credential_id, response.time_step, response.result),
        (original.credential_id, original.time_step, Ok(()))
    );

    // Reconnecting over a different medium and restarting the runtime preserve
    // exactly-once verification, even after moving into the next time window.
    let mut restarted = LockState::new(LockId([1; 16]), lock.into_storage());
    let replay = decode_unlock(nfc.decode(nfc.encode(&packet).unwrap()).unwrap()).unwrap();
    assert_eq!(
        restarted.unlock(&replay, Some(1_830), || {
            actuations += 1;
            Ok(())
        }),
        Err(Error::Replayed)
    );
    assert_eq!(actuations, 1);

    let other = unlock_request(&TotpSecret::new([8; 32]), CredentialId(2), 1_830).unwrap();
    restarted
        .unlock(&other, Some(1_830), || {
            actuations += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(actuations, 2);
}

#[test]
fn changing_id_step_or_code_cannot_authorize_another_request() {
    let original = unlock_request(&TotpSecret::new([7; 32]), CredentialId(1), 1_800).unwrap();
    for offset in [5, 13, 17] {
        let mut packet = encode_unlock(&original).unwrap();
        packet[offset] ^= 3; // another ID, out-of-window step, or another code
        let request = decode_unlock(&packet).unwrap();
        assert!(lock()
            .unlock(&request, Some(1_800), || panic!("tampering actuated"))
            .is_err());
    }
    // Distinct provisioned secrets bind credentials even with identical IDs.
    let wrong_key = unlock_request(&TotpSecret::new([8; 32]), CredentialId(1), 1_800).unwrap();
    assert_eq!(
        lock().unlock(&wrong_key, Some(1_800), || panic!("wrong key actuated")),
        Err(Error::InvalidTotp)
    );
}
