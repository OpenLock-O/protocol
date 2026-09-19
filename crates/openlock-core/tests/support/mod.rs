#![allow(dead_code)]
use openlock_core::device::*;
use openlock_crypto::{sha256, sign_grant, static_public, SigningKey};
use openlock_types::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
#[derive(Clone, Default)]
pub struct MemoryStore {
    pub trace: Rc<RefCell<Vec<&'static str>>>,
    pub state: Rc<RefCell<Option<DeviceSnapshot>>>,
    pub commits: Rc<Cell<usize>>,
    pub fail_at: Rc<Cell<Option<usize>>>,
    pub after_write: Rc<Cell<bool>>,
    pub fail_load: Rc<Cell<bool>>,
    pub commit_hook: Rc<RefCell<Option<CommitHook>>>,
}
pub type CommitHook = Box<dyn FnOnce()>;
impl DeviceStorage for MemoryStore {
    fn load(&self) -> Result<Option<DeviceSnapshot>, Error> {
        self.trace.borrow_mut().push("load");
        if self.fail_load.get() {
            return Err(Error::StorageUnavailable);
        }
        Ok(self.state.borrow().clone())
    }
    fn commit(&mut self, s: &DeviceSnapshot) -> Result<(), Error> {
        self.trace.borrow_mut().push("commit");
        let count = self.commits.get() + 1;
        self.commits.set(count);
        if self.fail_at.get() == Some(count) {
            if self.after_write.get() {
                *self.state.borrow_mut() = Some(s.clone());
            }
            return Err(Error::StorageUnavailable);
        }
        *self.state.borrow_mut() = Some(s.clone());
        if let Some(hook) = self.commit_hook.borrow_mut().take() {
            hook();
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Hardware {
    pub trace: Rc<RefCell<Vec<&'static str>>>,
    pub ms: u64,
    pub unix: Option<u64>,
    pub sample: HardwareSample,
    pub sample_override: Rc<Cell<Option<HardwareSample>>>,
    pub monotonic_override: Rc<Cell<Option<u64>>>,
    pub wall_override: Rc<Cell<Option<u64>>>,
    pub wall_reads: Cell<usize>,
    pub wall_tick_on_read: Cell<Option<(usize, u64)>>,
    pub wall_samples: RefCell<VecDeque<Option<ClockSample>>>,
    pub actions: Vec<ActionTarget>,
    pub action_id: Option<ActuationId>,
    pub fail_start: bool,
    pub fail_stop: bool,
    pub stop_count: usize,
    pub reboot: bool,
    pub image: Vec<u8>,
    pub boot: BootOutcome,
    pub boot_candidate: Option<FirmwareManifest>,
    pub activation_count: usize,
    pub fail_write: bool,
    pub power_ok: bool,
}
impl Default for Hardware {
    fn default() -> Self {
        Self {
            trace: Default::default(),
            ms: 100,
            unix: Some(1000),
            sample: HardwareSample {
                bolt: Reading::Known(BoltState::Locked),
                door: Reading::Known(DoorState::Closed),
                privacy: Reading::Known(false),
                battery_percent: Reading::Known(80),
            },
            sample_override: Default::default(),
            monotonic_override: Default::default(),
            wall_override: Default::default(),
            wall_reads: Cell::new(0),
            wall_tick_on_read: Cell::new(None),
            wall_samples: Default::default(),
            actions: Vec::new(),
            action_id: None,
            fail_start: false,
            fail_stop: false,
            stop_count: 0,
            reboot: false,
            image: Vec::new(),
            boot: BootOutcome::Pending,
            boot_candidate: None,
            activation_count: 0,
            fail_write: false,
            power_ok: true,
        }
    }
}
impl DevicePlatform for Hardware {
    fn monotonic_ms(&self) -> u64 {
        self.monotonic_override.get().unwrap_or(self.ms)
    }
    fn wall_clock(&self) -> Option<ClockSample> {
        if let Some(sample) = self.wall_samples.borrow_mut().pop_front() {
            return sample;
        }
        let read = self.wall_reads.get() + 1;
        self.wall_reads.set(read);
        if let Some((tick, time)) = self.wall_tick_on_read.get() {
            if read == tick {
                self.wall_override.set(Some(time));
            }
        }
        self.wall_override
            .get()
            .or(self.unix)
            .map(|t| ClockSample { lower: t, upper: t })
    }
    fn sensors(&self) -> HardwareSample {
        self.sample_override.get().unwrap_or(self.sample)
    }
    fn start_action(
        &mut self,
        id: ActuationId,
        target: ActionTarget,
        _duration: u32,
        _hold: bool,
    ) -> Result<(), Error> {
        self.action_id = Some(id);
        self.actions.push(target);
        if self.fail_start {
            Err(Error::ActuatorFailed)
        } else {
            if self.sample.bolt != Reading::Unsupported {
                self.sample.bolt = Reading::Unknown;
            }
            Ok(())
        }
    }
    fn stop_action(&mut self) -> Result<(), Error> {
        self.trace.borrow_mut().push("stop");
        self.stop_count += 1;
        if self.fail_stop {
            return Err(Error::ActuatorFailed);
        }
        Ok(())
    }
    fn set_wall_clock(&mut self, t: u64) -> Result<(), Error> {
        self.unix = Some(t);
        self.wall_override.set(None);
        Ok(())
    }
    fn request_reboot(&mut self) -> Result<(), Error> {
        self.reboot = true;
        Ok(())
    }
    fn bootloader(&mut self) -> Option<&mut dyn Bootloader> {
        Some(self)
    }
    fn has_device_private_key(&self, key: &[u8; 32]) -> bool {
        *key == static_public(&[4; 32]) || *key == static_public(&[12; 32])
    }
}
impl Bootloader for Hardware {
    fn begin(&mut self, m: &FirmwareManifest, _signed: &[u8]) -> Result<(), Error> {
        self.image = vec![0; m.size as usize];
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        if self.fail_write {
            return Err(Error::StorageUnavailable);
        }
        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(Error::FirmwareConflict)?;
        self.image
            .get_mut(start..end)
            .ok_or(Error::FirmwareConflict)?
            .copy_from_slice(data);
        Ok(())
    }
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        let start = offset as usize;
        let end = start
            .checked_add(out.len())
            .ok_or(Error::FirmwareConflict)?;
        out.copy_from_slice(self.image.get(start..end).ok_or(Error::FirmwareConflict)?);
        Ok(())
    }
    fn image_hash(&mut self, size: u64) -> Result<[u8; 32], Error> {
        Ok(sha256(
            self.image
                .get(..size as usize)
                .ok_or(Error::FirmwareInvalid)?,
        ))
    }
    fn ready_to_activate(&mut self) -> Result<(), Error> {
        if self.power_ok {
            Ok(())
        } else {
            Err(Error::PowerInsufficient)
        }
    }
    fn activate(&mut self, m: &FirmwareManifest, signed: &[u8]) -> Result<(), Error> {
        let root = SigningKey::from_bytes(&[8; 32]).verifying_key();
        if openlock_crypto::firmware::read_manifest(&root, signed)? != *m
            || sha256(&self.image) != m.sha256
        {
            return Err(Error::FirmwareInvalid);
        }
        self.activation_count += 1;
        self.boot_candidate = Some(m.clone());
        self.boot = BootOutcome::Pending;
        Ok(())
    }
    fn outcome(&mut self, candidate: &FirmwareManifest) -> Result<BootOutcome, Error> {
        Ok(if self.boot_candidate.as_ref() == Some(candidate) {
            self.boot
        } else {
            BootOutcome::RolledBack
        })
    }
    fn abort(&mut self) -> Result<(), Error> {
        self.image.clear();
        Ok(())
    }
}
pub fn factory() -> FactoryIdentity {
    FactoryIdentity {
        info: DeviceInfo {
            lock_id: LockId([1; 16]),
            model: "reference-lock".into(),
            hardware: "rev-a".into(),
            firmware: "1.0".into(),
            capabilities: KNOWN_CAPABILITIES,
            actuator: ActuatorKind::Motor,
            bolt_sensor: true,
            door_sensor: true,
            privacy_sensor: true,
            battery_sensor: true,
            safe_lock_without_door: false,
            hold_open: true,
            max_release_ms: 2000,
            max_action_ms: 30_000,
            max_delay_ms: 300_000,
            log_capacity: 64,
            operation_capacity: 16,
            credential_capacity: 32,
            max_image_size: 65536,
            max_chunk_size: 1024,
        },
        setup_key_hash: sha256(&[7; 32]),
        firmware_root: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        device_key: DeviceKey {
            device_id: LockId([1; 16]),
            key_id: 1,
            key_version: 1,
            x25519_public_key: static_public(&[4; 32]),
            rotation_public_key: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            capabilities: KNOWN_CAPABILITIES,
        },
    }
}
pub type Device = DeviceController<MemoryStore, Hardware>;
pub fn grant(id: u8, rights: u32, max: Option<u32>, epoch: u64) -> Vec<u8> {
    sign_grant(
        &SigningKey::from_bytes(&[9; 32]),
        &Grant {
            credential_id: CredentialId([id; 16]),
            lock_id: LockId([1; 16]),
            subject_key: SubjectKey(static_public(&[3; 32])),
            rights,
            epoch,
            validity: None,
            max_uses: max,
        },
    )
    .unwrap()
}
pub fn peer() -> SubjectKey {
    SubjectKey(static_public(&[3; 32]))
}
pub fn request(credential: Vec<u8>, sequence: u64, action: Action) -> Command {
    Command {
        credential,
        sequence: if action.mutates() {
            Some(sequence)
        } else {
            None
        },
        action,
    }
}
pub fn fresh() -> Device {
    DeviceController::provision(factory(), MemoryStore::default(), Hardware::default()).unwrap()
}
pub fn claim(d: &mut Device) {
    d.open_pairing_window().unwrap();
    let epoch = d.snapshot().epoch;
    let c = request(
        vec![],
        1,
        Action::Claim {
            setup_key: [7; 32],
            issuer: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            admin_credential: grant(2, KNOWN_RIGHTS, None, epoch),
        },
    );
    let r = d.handle(d.context(peer()), &c);
    assert!(matches!(r.result, Ok(Reply::Claimed { .. })), "{r:?}");
}
pub fn ready() -> Device {
    let mut d = fresh();
    claim(&mut d);
    // Operation tests count stops after the startup safety stop.
    d.platform_mut().stop_count = 0;
    d
}
pub fn send(d: &mut Device, seq: u64, action: Action) -> Response {
    let c = request(
        grant(2, KNOWN_RIGHTS, None, d.snapshot().epoch),
        seq,
        action,
    );
    d.handle(d.context(peer()), &c)
}
pub fn complete(d: &mut Device, bolt: BoltState) {
    d.platform_mut().sample.bolt = Reading::Known(bolt);
    d.actuator_finished(d.platform().action_id.unwrap(), ActuatorResult::Completed)
        .unwrap();
}
pub fn success(r: Response) -> OperationStatus {
    match r.result {
        Ok(Reply::Operation(s)) if s.error == 0 => s,
        _ => panic!("unexpected response {r:?}"),
    }
}
pub fn signed_image(bytes: &[u8], security: u64) -> Vec<u8> {
    openlock_crypto::firmware::sign_manifest(
        &SigningKey::from_bytes(&[8; 32]),
        &FirmwareManifest {
            model: "reference-lock".into(),
            hardware: "rev-a".into(),
            version: "2.0".into(),
            size: bytes.len() as u64,
            sha256: sha256(bytes),
            security_version: security,
        },
    )
    .unwrap()
}
