//! One serialized owner for a physical lock and its durable authorization state.
//! Storage commits are atomic and durable; an uncertain commit poisons this instance.
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use openlock_crypto::{
    firmware::read_manifest,
    read_grant, read_policy, sha256,
    wire::{encode_wire, Wire},
    VerifyingKey,
};
use openlock_types::*;

#[derive(Clone)]
pub struct FactoryIdentity {
    pub info: DeviceInfo,
    /// SHA-256 of the independent 32-byte QR setup key. Never advertise this key.
    pub setup_key_hash: [u8; 32],
    pub firmware_root: [u8; 32],
    pub device_key: DeviceKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Owner {
    pub issuer: [u8; 32],
    pub first_admin: SubjectKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    pub digest: [u8; 32],
    pub status: OperationStatus,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSnapshot {
    pub format: u32,
    pub lock_id: LockId,
    pub owner: Option<Owner>,
    pub epoch: u64,
    pub generation: u64,
    pub policy_version: u64,
    pub revoked: BTreeSet<CredentialId>,
    pub uses: BTreeMap<CredentialId, u32>,
    pub watermarks: BTreeMap<CredentialId, u64>,
    pub bindings: BTreeMap<CredentialId, [u8; 32]>,
    pub operations: Vec<OperationRecord>,
    pub config: DeviceConfig,
    pub events: Vec<AuditEvent>,
    pub next_cursor: u64,
    pub clock_floor: Option<u64>,
    pub clock_valid: bool,
    pub pending_relock: bool,
    pub automatic_inflight: bool,
    pub firmware: FirmwareStatus,
    pub signed_manifest: Vec<u8>,
    pub device_key: DeviceKey,
}
/// A store must distinguish an absent factory record from corruption or I/O failure.
/// Encode explicit fields, with integrity checks; Rust layout is not a disk format.
/// Persist the entire snapshot atomically. A failed commit may have taken effect.
pub trait DeviceStorage {
    fn load(&self) -> Result<Option<DeviceSnapshot>, Error>;
    fn commit(&mut self, next: &DeviceSnapshot) -> Result<(), Error>;
}
pub type HardwareSample = HardwareState;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuatorResult {
    Completed,
    Jammed,
    SensorConflict,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootOutcome {
    Pending,
    Confirmed,
    RolledBack,
}
/// Implement only with a bootloader that independently verifies the signed image,
/// durably stages a candidate and can restore the last confirmed boot image.
pub trait Bootloader {
    fn begin(&mut self, manifest: &FirmwareManifest, signed: &[u8]) -> Result<(), Error>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error>;
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error>;
    fn image_hash(&mut self, size: u64) -> Result<[u8; 32], Error>;
    fn ready_to_activate(&mut self) -> Result<(), Error>;
    fn activate(&mut self, manifest: &FirmwareManifest, signed: &[u8]) -> Result<(), Error>;
    fn outcome(&mut self) -> Result<BootOutcome, Error>;
    fn abort(&mut self) -> Result<(), Error>;
}
/// Platform callbacks never derive trust or physical presence from network input.
pub trait DevicePlatform {
    fn monotonic_ms(&self) -> u64;
    fn wall_clock(&self) -> Option<ClockSample>;
    fn sensors(&self) -> HardwareSample;
    /// Starts once. For pulse hardware enforce release_ms in hardware even if the
    /// host stops polling or loses power. hold_open requires a suitable mechanism.
    fn start_action(
        &mut self,
        target: ActionTarget,
        release_ms: u32,
        hold_open: bool,
    ) -> Result<(), Error>;
    fn stop_action(&mut self) -> Result<(), Error>;
    fn set_wall_clock(&mut self, unix_seconds: u64) -> Result<(), Error>;
    /// Schedule reboot after the response has been transmitted, or its deadline.
    fn request_reboot(&mut self) -> Result<(), Error>;
    fn bootloader(&mut self) -> Option<&mut dyn Bootloader> {
        None
    }
    /// Private material for this public key must already be securely provisioned.
    fn has_device_private_key(&self, _public: &[u8; 32]) -> bool {
        false
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionContext {
    pub peer: SubjectKey,
    pub generation: u64,
}
struct Active {
    credential_id: CredentialId,
    sequence: u64,
    target: ActionTarget,
    deadline: u64,
    automatic: bool,
}
struct Confirmation {
    peer: SubjectKey,
    digest: [u8; 32],
    expires: u64,
}
pub struct DeviceController<S, P> {
    factory: FactoryIdentity,
    storage: S,
    platform: P,
    state: DeviceSnapshot,
    poisoned: bool,
    sample: HardwareSample,
    fault: Fault,
    active: Option<Active>,
    last_mono: u64,
    relock_deadline: Option<u64>,
    door_open_since: Option<u64>,
    pairing_until: Option<u64>,
    pairing_failures: u8,
    confirmation: Option<Confirmation>,
}
impl DeviceSnapshot {
    fn factory(f: &FactoryIdentity) -> Self {
        Self {
            format: 1,
            lock_id: f.info.lock_id,
            owner: None,
            epoch: 0,
            generation: 0,
            policy_version: 0,
            revoked: BTreeSet::new(),
            uses: BTreeMap::new(),
            watermarks: BTreeMap::new(),
            bindings: BTreeMap::new(),
            operations: Vec::new(),
            config: DeviceConfig::factory(&f.info),
            events: Vec::new(),
            next_cursor: 1,
            clock_floor: None,
            clock_valid: true,
            pending_relock: false,
            automatic_inflight: false,
            firmware: FirmwareStatus {
                phase: FirmwarePhase::Empty,
                received: 0,
                manifest: None,
                security_version: 0,
            },
            signed_manifest: Vec::new(),
            device_key: f.device_key.clone(),
        }
    }
    fn validate(&self, f: &FactoryIdentity) -> Result<(), Error> {
        if self.format != 1
            || self.lock_id != f.info.lock_id
            || self.device_key.device_id != self.lock_id
            || self.next_cursor == 0
            || self.operations.len() > f.info.operation_capacity as usize
            || self.events.len() > f.info.log_capacity as usize
            || self.watermarks.len() > f.info.credential_capacity as usize
            || self.bindings.len() > f.info.credential_capacity as usize
            || self.uses.len() > f.info.credential_capacity as usize
            || self.revoked.len() > f.info.credential_capacity as usize
        {
            return Err(Error::StorageUnavailable);
        }
        self.config
            .validate(&f.info)
            .map_err(|_| Error::StorageUnavailable)?;
        openlock_crypto::validate_device_key(&self.device_key)
            .map_err(|_| Error::StorageUnavailable)?;
        if let Some(owner) = &self.owner {
            VerifyingKey::from_bytes(&owner.issuer).map_err(|_| Error::StorageUnavailable)?;
        }
        for op in &self.operations {
            if op.status.sequence == 0
                || self
                    .watermarks
                    .get(&op.status.credential_id)
                    .copied()
                    .unwrap_or(0)
                    < op.status.sequence
                || op.status.opcode > 22
            {
                return Err(Error::StorageUnavailable);
            }
        }
        let mut last = 0;
        for e in &self.events {
            if e.cursor <= last || e.cursor >= self.next_cursor {
                return Err(Error::StorageUnavailable);
            }
            last = e.cursor;
        }
        if self.firmware.phase == FirmwarePhase::Empty {
            if self.firmware.manifest.is_some() || !self.signed_manifest.is_empty() {
                return Err(Error::StorageUnavailable);
            }
        } else {
            let root = VerifyingKey::from_bytes(&f.firmware_root)
                .map_err(|_| Error::StorageUnavailable)?;
            let manifest = read_manifest(&root, &self.signed_manifest)
                .map_err(|_| Error::StorageUnavailable)?;
            if self.firmware.manifest.as_ref() != Some(&manifest)
                || manifest.model != f.info.model
                || manifest.hardware != f.info.hardware
                || manifest.size > f.info.max_image_size
                || matches!(
                    self.firmware.phase,
                    FirmwarePhase::Verified | FirmwarePhase::Trial | FirmwarePhase::Confirmed
                ) && self.firmware.received != manifest.size
                || self.firmware.phase == FirmwarePhase::Confirmed
                    && self.firmware.security_version != manifest.security_version
                || self.firmware.phase != FirmwarePhase::Confirmed
                    && manifest.security_version <= self.firmware.security_version
            {
                return Err(Error::StorageUnavailable);
            }
        }
        if self.firmware.received > self.firmware.manifest.as_ref().map_or(0, |m| m.size) {
            return Err(Error::StorageUnavailable);
        }
        Ok(())
    }
}
impl<S: DeviceStorage, P: DevicePlatform> DeviceController<S, P> {
    /// Only for a genuinely absent store. Never use this as recovery from load failure.
    pub fn provision(factory: FactoryIdentity, mut storage: S, platform: P) -> Result<Self, Error> {
        factory.info.validate()?;
        if storage.load()?.is_some() {
            return Err(Error::AlreadyProvisioned);
        }
        let state = DeviceSnapshot::factory(&factory);
        state.validate(&factory)?;
        storage.commit(&state)?;
        Self::open(factory, storage, platform)
    }
    /// Explicit migration into a NEW v4 store. Retain the old store until this
    /// transaction succeeds. Identity/root inputs come from trusted provisioning.
    pub fn migrate_legacy(
        factory: FactoryIdentity,
        mut storage: S,
        platform: P,
        legacy: &crate::LockSnapshot,
        issuer: VerifyingKey,
        first_admin: SubjectKey,
    ) -> Result<Self, Error> {
        if storage.load()?.is_some() {
            return Err(Error::AlreadyProvisioned);
        }
        let mut state = DeviceSnapshot::factory(&factory);
        state.owner = Some(Owner {
            issuer: issuer.to_bytes(),
            first_admin,
        });
        state.epoch = legacy.epoch;
        state.policy_version = legacy.policy_version;
        state.revoked = legacy.revoked.clone();
        state.uses = legacy.usage.clone();
        state.generation = 1;
        state.validate(&factory)?;
        storage.commit(&state)?;
        Self::open(factory, storage, platform)
    }
    pub fn open(factory: FactoryIdentity, storage: S, mut platform: P) -> Result<Self, Error> {
        factory.info.validate()?;
        let mut state = storage.load()?.ok_or(Error::NotProvisioned)?;
        state.validate(&factory)?;
        if factory.info.capabilities & (0x3f << 13) != 0 && platform.bootloader().is_none() {
            return Err(Error::InvalidConfig);
        }
        if state.automatic_inflight
            || state.operations.iter().any(|r| {
                matches!(r.status.opcode, 0 | 3)
                    && matches!(
                        r.status.phase,
                        OperationPhase::Accepted
                            | OperationPhase::Running
                            | OperationPhase::Unknown
                    )
            })
        {
            platform.stop_action()?;
        }
        let interrupted_automatic = state.automatic_inflight;
        state.automatic_inflight = false;
        let sample = platform.sensors();
        let last_mono = platform.monotonic_ms();
        for op in &mut state.operations {
            if matches!(
                op.status.phase,
                OperationPhase::Accepted | OperationPhase::Running
            ) {
                op.status.phase = OperationPhase::Unknown;
                op.status.error = Error::ActuatorFailed.code();
            }
        }
        let pending = state.pending_relock;
        let mut out = Self {
            factory,
            storage,
            platform,
            state,
            poisoned: false,
            sample,
            fault: Fault::None,
            active: None,
            last_mono,
            relock_deadline: if pending { Some(last_mono) } else { None },
            door_open_since: if sample.door == Reading::Known(DoorState::Open) {
                Some(last_mono)
            } else {
                None
            },
            pairing_until: None,
            pairing_failures: 0,
            confirmation: None,
        };
        out.validate_sample(sample)?;
        let mut recovered = out.state.clone();
        if interrupted_automatic {
            out.fault = Fault::Driver;
            out.audit_automatic(
                &mut recovered,
                OperationPhase::Unknown,
                CompletionEvidence::None,
                Error::ActuatorFailed.code(),
            )?;
        }
        out.commit(recovered)?;
        if out.state.firmware.phase == FirmwarePhase::Confirmed {
            out.factory.info.firmware = out
                .state
                .firmware
                .manifest
                .as_ref()
                .ok_or(Error::StorageUnavailable)?
                .version
                .clone();
        }
        out.reconcile_boot()?;
        Ok(out)
    }
    pub fn snapshot(&self) -> &DeviceSnapshot {
        &self.state
    }
    pub fn info(&self) -> &DeviceInfo {
        &self.factory.info
    }
    pub fn platform(&self) -> &P {
        &self.platform
    }
    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }
    pub fn into_parts(self) -> (S, P) {
        (self.storage, self.platform)
    }
    pub fn context(&self, peer: SubjectKey) -> SessionContext {
        SessionContext {
            peer,
            generation: self.state.generation,
        }
    }
    fn commit(&mut self, next: DeviceSnapshot) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::StorageUnavailable);
        }
        next.validate(&self.factory)?;
        if self.storage.commit(&next).is_err() {
            self.poisoned = true;
            return Err(Error::StorageUnavailable);
        }
        self.state = next;
        Ok(())
    }
    fn now(&mut self) -> Result<u64, Error> {
        if self.poisoned {
            return Err(Error::StorageUnavailable);
        }
        let now = self.platform.monotonic_ms();
        if now < self.last_mono {
            self.poisoned = true;
            return Err(Error::ClockUntrusted);
        }
        self.last_mono = now;
        Ok(now)
    }
    fn refresh_clock(&mut self) -> Result<(), Error> {
        if let Some(sample) = self.platform.wall_clock() {
            if sample.lower > sample.upper
                || self
                    .state
                    .clock_floor
                    .is_some_and(|floor| sample.lower < floor)
            {
                if self.state.clock_valid {
                    let mut next = self.state.clone();
                    next.clock_valid = false;
                    self.commit(next)?;
                }
            } else if self.state.clock_valid && self.state.clock_floor != Some(sample.lower) {
                let mut next = self.state.clone();
                next.clock_floor = Some(sample.lower);
                self.commit(next)?;
            }
        } else if self.state.clock_valid {
            let mut next = self.state.clone();
            next.clock_valid = false;
            self.commit(next)?;
        }
        Ok(())
    }
    fn wall(&self) -> Option<ClockSample> {
        if !self.state.clock_valid {
            return None;
        }
        self.platform.wall_clock().filter(|c| {
            c.lower <= c.upper
                && self
                    .state
                    .clock_floor
                    .map_or(true, |floor| c.lower >= floor)
        })
    }
    fn audit(
        &self,
        s: &mut DeviceSnapshot,
        kind: AuditKind,
        id: Option<CredentialId>,
        sequence: Option<u64>,
        code: u32,
    ) -> Result<(), Error> {
        let cursor = s.next_cursor;
        s.next_cursor = cursor.checked_add(1).ok_or(Error::ResourceExhausted)?;
        s.events.push(AuditEvent {
            cursor,
            unix_seconds: self.wall().map(|x| x.lower),
            kind,
            credential_id: id,
            sequence,
            code,
            hardware: None,
            operation: if kind == AuditKind::Operation {
                s.operations
                    .iter()
                    .find(|r| {
                        Some(r.status.credential_id) == id && Some(r.status.sequence) == sequence
                    })
                    .map(|r| r.status.clone())
            } else {
                None
            },
        });
        if s.events.len() > self.factory.info.log_capacity as usize {
            s.events.remove(0);
        }
        Ok(())
    }
    fn record_wall(&self, s: &mut DeviceSnapshot) {
        if let Some(now) = self.wall() {
            s.clock_floor = Some(s.clock_floor.map_or(now.lower, |old| old.max(now.lower)));
        }
    }
    fn audit_automatic(
        &self,
        next: &mut DeviceSnapshot,
        phase: OperationPhase,
        evidence: CompletionEvidence,
        error: u32,
    ) -> Result<(), Error> {
        self.audit(next, AuditKind::Operation, None, None, error)?;
        if let Some(event) = next.events.last_mut() {
            event.operation = Some(OperationStatus {
                credential_id: CredentialId([0; 16]),
                sequence: 0,
                opcode: 3,
                phase,
                evidence,
                error,
            });
        }
        Ok(())
    }
    fn validate_sample(&self, s: HardwareSample) -> Result<(), Error> {
        fn valid<T>(r: &Reading<T>, present: bool) -> bool {
            matches!(r, Reading::Unsupported) != present
        }
        let i = &self.factory.info;
        if !valid(&s.bolt, i.bolt_sensor)
            || !valid(&s.door, i.door_sensor)
            || !valid(&s.privacy, i.privacy_sensor)
            || !valid(&s.battery_percent, i.battery_sensor)
            || matches!(s.battery_percent,Reading::Known(n) if n>100)
        {
            return Err(Error::SensorConflict);
        }
        Ok(())
    }
    /// A local button/gesture opens the commissioning window. Not a wire command.
    pub fn open_pairing_window(&mut self) -> Result<(), Error> {
        let now = self.now()?;
        if self.state.owner.is_some() {
            return Err(Error::AlreadyProvisioned);
        }
        self.pairing_until = Some(now.checked_add(120_000).ok_or(Error::InvalidState)?);
        self.pairing_failures = 0;
        Ok(())
    }
    /// Called only after a physical gesture confirming this exact displayed request.
    pub fn confirm_physical(
        &mut self,
        context: SessionContext,
        command: &Command,
    ) -> Result<(), Error> {
        self.authorize(context, command)?;
        if !matches!(
            command.action,
            Action::FactoryReset | Action::ReplaceIssuer(_)
        ) {
            return Err(Error::InvalidPayload);
        }
        let now = self.now()?;
        self.confirmation = Some(Confirmation {
            peer: context.peer,
            digest: sha256(&encode_wire(command)?),
            expires: now.checked_add(60_000).ok_or(Error::InvalidState)?,
        });
        Ok(())
    }
    fn authorize(&self, context: SessionContext, c: &Command) -> Result<Grant, Error> {
        if context.generation != self.state.generation {
            return Err(Error::InvalidState);
        }
        let owner = self.state.owner.as_ref().ok_or(Error::NotProvisioned)?;
        let key = VerifyingKey::from_bytes(&owner.issuer).map_err(|_| Error::UntrustedKey)?;
        let grant = read_grant(&key, &c.credential)?;
        if grant.lock_id != self.state.lock_id {
            return Err(Error::WrongLock);
        }
        if grant.subject_key != context.peer {
            return Err(Error::BadSignature);
        }
        if grant.epoch != self.state.epoch {
            return Err(Error::StaleEpoch);
        }
        if grant.rights & c.action.right() != c.action.right() {
            return Err(Error::MissingRight);
        }
        if self.state.revoked.contains(&grant.credential_id) {
            return Err(Error::Revoked);
        }
        if let Some(v) = grant.validity {
            let now = self.wall().ok_or(Error::ClockUntrusted)?;
            if now.lower < v.not_before || now.upper >= v.not_after {
                return Err(Error::Expired);
            }
        }
        if let Some(binding) = self.state.bindings.get(&grant.credential_id) {
            if *binding != sha256(&c.credential) {
                return Err(Error::Conflict);
            }
        }
        Ok(grant)
    }
    pub fn handle(&mut self, context: SessionContext, c: &Command) -> Response {
        let mut result = self.dispatch(context, c).map_err(|e| e.code());
        if let Err(code) = result {
            if !self.poisoned && self.state.owner.is_some() {
                let mut next = self.state.clone();
                if self
                    .audit(&mut next, AuditKind::Rejected, None, None, code)
                    .and_then(|_| self.commit(next))
                    .is_err()
                {
                    result = Err(Error::StorageUnavailable.code());
                }
            }
        }
        Response {
            opcode: c.action.opcode(),
            result,
        }
    }
    /// Trusted local management still supplies a valid administrator credential;
    /// use context from a locally verified key and the same physical-confirmation API.
    pub fn handle_local(&mut self, peer: SubjectKey, c: &Command) -> Response {
        self.handle(self.context(peer), c)
    }
    fn dispatch(&mut self, context: SessionContext, c: &Command) -> Result<Reply, Error> {
        let now = self.now()?;
        c.validate()?;
        Action::parse(&c.action.value())?;
        if c.capability() & self.factory.info.capabilities == 0 {
            return Err(Error::UnsupportedCapability);
        }
        if context.generation != self.state.generation {
            return Err(Error::InvalidState);
        }
        if matches!(c.action, Action::PairingStatus) {
            if self.state.owner.is_some() {
                return Err(Error::AlreadyProvisioned);
            }
            return Ok(Reply::Pairing {
                epoch: self.state.epoch,
                generation: self.state.generation,
                window_open: self.pairing_until.is_some_and(|until| now < until),
            });
        }
        if let Action::Claim {
            setup_key,
            issuer,
            admin_credential,
        } = &c.action
        {
            return self.claim(context, setup_key, issuer, admin_credential, now);
        }
        self.refresh_clock()?;
        let grant = self.authorize(context, c)?;
        if !c.action.mutates() {
            return self.query(&grant, &c.action);
        }
        let seq = c.sequence.ok_or(Error::InvalidPayload)?;
        let digest = sha256(&encode_wire(c)?);
        if seq
            <= self
                .state
                .watermarks
                .get(&grant.credential_id)
                .copied()
                .unwrap_or(0)
        {
            let previous = self
                .state
                .operations
                .iter()
                .find(|r| r.status.credential_id == grant.credential_id && r.status.sequence == seq)
                .ok_or(Error::ResultUnavailable)?;
            if previous.digest != digest {
                return Err(Error::Conflict);
            }
            return Ok(Reply::Operation(previous.status.clone()));
        }
        self.preflight(&grant, c, now, digest, context.peer)?;
        let mut next = self.state.clone();
        if (!next.watermarks.contains_key(&grant.credential_id)
            && next.watermarks.len() >= self.factory.info.credential_capacity as usize)
            || (!next.bindings.contains_key(&grant.credential_id)
                && next.bindings.len() >= self.factory.info.credential_capacity as usize)
        {
            return Err(Error::ResourceExhausted);
        }
        next.watermarks.insert(grant.credential_id, seq);
        next.bindings
            .insert(grant.credential_id, sha256(&c.credential));
        let no_change = match c.action {
            Action::Unlock => self.sample.bolt == Reading::Known(BoltState::Unlocked),
            Action::Lock => self.sample.bolt == Reading::Known(BoltState::Locked),
            _ => false,
        };
        if matches!(c.action, Action::Unlock) && !no_change {
            let uses = next.uses.get(&grant.credential_id).copied().unwrap_or(0);
            if grant.max_uses.is_some_and(|max| uses >= max) {
                return Err(Error::UsageExhausted);
            }
            next.uses.insert(
                grant.credential_id,
                uses.checked_add(1).ok_or(Error::UsageExhausted)?,
            );
        }
        let status = OperationStatus {
            credential_id: grant.credential_id,
            sequence: seq,
            opcode: c.action.opcode(),
            phase: OperationPhase::Accepted,
            evidence: CompletionEvidence::None,
            error: 0,
        };
        if next.operations.len() >= self.factory.info.operation_capacity as usize {
            let idx = next
                .operations
                .iter()
                .position(|r| {
                    self.active.as_ref().map_or(true, |a| {
                        a.credential_id != r.status.credential_id || a.sequence != r.status.sequence
                    }) && !matches!(
                        r.status.phase,
                        OperationPhase::Accepted | OperationPhase::Running
                    )
                })
                .ok_or(Error::ResourceExhausted)?;
            next.operations.remove(idx);
        }
        next.operations.push(OperationRecord {
            digest,
            status: status.clone(),
        });
        self.record_wall(&mut next);
        self.audit(
            &mut next,
            AuditKind::Operation,
            Some(grant.credential_id),
            Some(seq),
            0,
        )?;
        self.commit(next)?;
        if no_change {
            return self.finish(
                &status,
                OperationPhase::Completed,
                CompletionEvidence::NoChange,
                0,
            );
        }
        let execution = self.execute(context, c, &status, now);
        match execution {
            Ok(Some(reply)) => Ok(reply),
            Ok(None) => self.finish(
                &status,
                OperationPhase::Completed,
                CompletionEvidence::None,
                0,
            ),
            Err(e) => {
                if self.poisoned {
                    return Err(e);
                }
                self.finish(
                    &status,
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    e.code(),
                )
            }
        }
    }
    fn claim(
        &mut self,
        context: SessionContext,
        key: &[u8; 32],
        issuer: &[u8; 32],
        admin: &[u8],
        now: u64,
    ) -> Result<Reply, Error> {
        if self.state.owner.is_some() {
            return Err(Error::AlreadyProvisioned);
        }
        if self.pairing_until.map_or(true, |until| now >= until) || self.pairing_failures >= 5 {
            return Err(Error::PairingClosed);
        }
        if !openlock_crypto::constant_time_eq(&sha256(key), &self.factory.setup_key_hash) {
            self.pairing_failures += 1;
            if self.pairing_failures >= 5 {
                self.pairing_until = None;
            }
            return Err(Error::InvalidSetupKey);
        }
        let verifying = VerifyingKey::from_bytes(issuer).map_err(|_| Error::UntrustedKey)?;
        let grant = read_grant(&verifying, admin)?;
        if grant.lock_id != self.state.lock_id
            || grant.subject_key != context.peer
            || grant.epoch != self.state.epoch
            || grant.rights != KNOWN_RIGHTS
            || grant.max_uses.is_some()
            || grant.validity.is_some()
        {
            return Err(Error::InvalidPayload);
        }
        let mut next = self.state.clone();
        next.owner = Some(Owner {
            issuer: *issuer,
            first_admin: context.peer,
        });
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        next.bindings.insert(grant.credential_id, sha256(admin));
        self.record_wall(&mut next);
        self.audit(
            &mut next,
            AuditKind::Ownership,
            Some(grant.credential_id),
            None,
            0,
        )?;
        self.commit(next)?;
        self.pairing_until = None;
        self.confirmation = None;
        Ok(Reply::Claimed {
            epoch: self.state.epoch,
            generation: self.state.generation,
        })
    }
    fn query(&self, g: &Grant, action: &Action) -> Result<Reply, Error> {
        Ok(match action {
            Action::Info => Reply::Info(self.factory.info.clone()),
            Action::Status => Reply::Status(self.status()),
            Action::GetConfig => Reply::Config(self.state.config.clone()),
            Action::Operation(seq) => Reply::Operation(
                self.state
                    .operations
                    .iter()
                    .find(|r| {
                        r.status.credential_id == g.credential_id && r.status.sequence == *seq
                    })
                    .ok_or(Error::ResultUnavailable)?
                    .status
                    .clone(),
            ),
            Action::ReadLog { after, limit } => {
                let first = self
                    .state
                    .events
                    .first()
                    .map_or(self.state.next_cursor, |e| e.cursor);
                let events: Vec<_> = self
                    .state
                    .events
                    .iter()
                    .filter(|e| e.cursor > *after)
                    .take(*limit as usize)
                    .cloned()
                    .collect();
                let next_cursor = events.last().map_or(*after, |e| e.cursor);
                Reply::Audit(AuditPage {
                    events,
                    next_cursor,
                    gap: after.saturating_add(1) < first,
                })
            }
            Action::FirmwareStatus => Reply::Firmware(self.state.firmware.clone()),
            Action::CredentialStatus => Reply::Credential {
                uses: self.state.uses.get(&g.credential_id).copied().unwrap_or(0),
                max_uses: g.max_uses,
                next_sequence: self
                    .state
                    .watermarks
                    .get(&g.credential_id)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(Error::ResourceExhausted)?,
            },
            _ => return Err(Error::InvalidPayload),
        })
    }
    pub fn status(&self) -> LockStatus {
        let active = self.active.as_ref().and_then(|a| {
            if a.automatic {
                return Some(OperationStatus {
                    credential_id: CredentialId([0; 16]),
                    sequence: 0,
                    opcode: 3,
                    phase: OperationPhase::Running,
                    evidence: CompletionEvidence::None,
                    error: 0,
                });
            }
            self.state
                .operations
                .iter()
                .find(|r| {
                    r.status.credential_id == a.credential_id && r.status.sequence == a.sequence
                })
                .map(|r| r.status.clone())
        });
        LockStatus {
            bolt: self.sample.bolt,
            door: self.sample.door,
            privacy: self.sample.privacy,
            battery_percent: self.sample.battery_percent,
            fault: self.fault,
            active,
            epoch: self.state.epoch,
            policy_version: self.state.policy_version,
            config_version: self.state.config.version,
            generation: self.state.generation,
            clock_trusted: self.wall().is_some(),
        }
    }
    fn can_lock(&self) -> Result<(), Error> {
        if self.factory.info.actuator != ActuatorKind::Motor {
            return Err(Error::UnsupportedCapability);
        }
        match self.sample.door {
            Reading::Known(DoorState::Closed) => Ok(()),
            Reading::Known(DoorState::Open) => Err(Error::DoorOpen),
            Reading::Unsupported if self.factory.info.safe_lock_without_door => Ok(()),
            _ => Err(Error::SensorConflict),
        }
    }
    fn preflight(
        &mut self,
        _g: &Grant,
        c: &Command,
        now: u64,
        digest: [u8; 32],
        peer: SubjectKey,
    ) -> Result<(), Error> {
        self.hardware_changed()?;
        match &c.action {
            Action::Unlock | Action::Lock => {
                if self.active.is_some() {
                    return Err(Error::Busy);
                }
                if self.state.firmware.phase == FirmwarePhase::Trial {
                    return Err(Error::Busy);
                }
                if matches!(c.action, Action::Unlock) {
                    match self.sample.privacy {
                        Reading::Known(true) => return Err(Error::PrivacyActive),
                        Reading::Unknown => return Err(Error::SensorConflict),
                        _ => (),
                    }
                } else if self.sample.bolt != Reading::Known(BoltState::Locked) {
                    self.can_lock()?;
                }
            }
            Action::SetConfig(config) => {
                if self.active.is_some() {
                    return Err(Error::Busy);
                }
                config.validate(&self.factory.info)?;
                if config.version
                    != self
                        .state
                        .config
                        .version
                        .checked_add(1)
                        .ok_or(Error::ResourceExhausted)?
                {
                    return Err(Error::Conflict);
                }
            }
            Action::SetClock(t) => {
                if self.state.clock_floor.is_some_and(|floor| *t < floor) {
                    return Err(Error::ClockRollback);
                }
                if self.wall().is_some_and(|now| *t < now.lower) {
                    return Err(Error::ClockRollback);
                }
            }
            Action::Reboot
            | Action::FactoryReset
            | Action::ReplaceIssuer(_)
            | Action::FirmwareActivate
            | Action::RotateDeviceKey(_) => {
                if self.active.is_some() {
                    return Err(Error::Busy);
                }
                if matches!(c.action, Action::FactoryReset | Action::ReplaceIssuer(_)) {
                    let confirmation = self
                        .confirmation
                        .take()
                        .ok_or(Error::PhysicalConfirmationRequired)?;
                    if confirmation.peer != peer
                        || confirmation.digest != digest
                        || now >= confirmation.expires
                    {
                        return Err(Error::PhysicalConfirmationRequired);
                    }
                    if self.state.firmware.phase == FirmwarePhase::Trial {
                        return Err(Error::Busy);
                    }
                }
                if let Action::ReplaceIssuer(key) = &c.action {
                    VerifyingKey::from_bytes(key).map_err(|_| Error::UntrustedKey)?;
                }
                if matches!(c.action, Action::FirmwareActivate) {
                    if self.state.firmware.phase != FirmwarePhase::Verified {
                        return Err(Error::FirmwareIncomplete);
                    }
                    self.boot()?.ready_to_activate()?;
                }
            }
            Action::FirmwareBegin(bytes) => {
                if matches!(
                    self.state.firmware.phase,
                    FirmwarePhase::Receiving | FirmwarePhase::Verified | FirmwarePhase::Trial
                ) {
                    return Err(Error::Busy);
                }
                let manifest = self.manifest(bytes)?;
                if manifest.size > self.factory.info.max_image_size {
                    return Err(Error::ObjectTooLarge);
                }
            }
            Action::FirmwareChunk { offset, data } => {
                if self.state.firmware.phase != FirmwarePhase::Receiving {
                    return Err(Error::InvalidState);
                }
                let m = self
                    .state
                    .firmware
                    .manifest
                    .as_ref()
                    .ok_or(Error::FirmwareInvalid)?;
                if data.len() > self.factory.info.max_chunk_size as usize
                    || offset
                        .checked_add(data.len() as u64)
                        .map_or(true, |end| end > m.size)
                    || *offset > self.state.firmware.received
                {
                    return Err(Error::FirmwareConflict);
                }
                if *offset < self.state.firmware.received {
                    if offset + data.len() as u64 > self.state.firmware.received {
                        return Err(Error::FirmwareConflict);
                    }
                    let mut old = alloc::vec![0;data.len()];
                    self.boot()?.read(*offset, &mut old)?;
                    if old != *data {
                        return Err(Error::FirmwareConflict);
                    }
                }
            }
            Action::FirmwareFinish => {
                if self.state.firmware.phase != FirmwarePhase::Receiving
                    || self
                        .state
                        .firmware
                        .manifest
                        .as_ref()
                        .map_or(true, |m| m.size != self.state.firmware.received)
                {
                    return Err(Error::FirmwareIncomplete);
                }
            }
            Action::FirmwareAbort => {
                if self.state.firmware.phase == FirmwarePhase::Trial {
                    return Err(Error::Busy);
                }
            }
            Action::ApplyPolicy(bytes) => {
                let key = VerifyingKey::from_bytes(
                    &self
                        .state
                        .owner
                        .as_ref()
                        .ok_or(Error::NotProvisioned)?
                        .issuer,
                )
                .map_err(|_| Error::UntrustedKey)?;
                let p = read_policy(&key, bytes)?;
                if p.lock_id != self.state.lock_id {
                    return Err(Error::WrongLock);
                }
                if self.active.is_some() && p.epoch > self.state.epoch {
                    return Err(Error::Busy);
                }
                if p.epoch < self.state.epoch
                    || p.epoch == self.state.epoch && p.version <= self.state.policy_version
                {
                    return Err(Error::StalePolicy);
                }
                if p.revoked.len() > self.factory.info.credential_capacity as usize
                    || (p.epoch == self.state.epoch
                        && self.state.revoked.union(&p.revoked).count()
                            > self.factory.info.credential_capacity as usize)
                {
                    return Err(Error::ResourceExhausted);
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn finish(
        &mut self,
        status: &OperationStatus,
        phase: OperationPhase,
        evidence: CompletionEvidence,
        error: u32,
    ) -> Result<Reply, Error> {
        let mut next = self.state.clone();
        let record = next
            .operations
            .iter_mut()
            .find(|r| {
                r.status.credential_id == status.credential_id
                    && r.status.sequence == status.sequence
            })
            .ok_or(Error::ResultUnavailable)?;
        record.status.phase = phase;
        record.status.evidence = evidence;
        record.status.error = error;
        let result = record.status.clone();
        self.audit(
            &mut next,
            AuditKind::Operation,
            Some(status.credential_id),
            Some(status.sequence),
            error,
        )?;
        self.commit(next)?;
        Ok(Reply::Operation(result))
    }
    fn execute(
        &mut self,
        context: SessionContext,
        c: &Command,
        status: &OperationStatus,
        now: u64,
    ) -> Result<Option<Reply>, Error> {
        let mut next = self.state.clone();
        match &c.action {
            Action::Unlock | Action::Lock => {
                let target = if matches!(c.action, Action::Unlock) {
                    ActionTarget::Unlock
                } else {
                    ActionTarget::Lock
                };
                let deadline = now
                    .checked_add(self.state.config.action_timeout_ms as u64)
                    .ok_or(Error::InvalidState)?;
                // Invalidate an old reading before a movement starts.
                if self.factory.info.bolt_sensor {
                    self.sample.bolt = Reading::Unknown;
                }
                self.active = Some(Active {
                    credential_id: status.credential_id,
                    sequence: status.sequence,
                    target,
                    deadline,
                    automatic: false,
                });
                if self
                    .platform
                    .start_action(
                        target,
                        self.state.config.release_ms,
                        self.state.config.hold_open,
                    )
                    .is_err()
                {
                    self.fault = Fault::Driver;
                    return self
                        .finish(
                            status,
                            OperationPhase::Unknown,
                            CompletionEvidence::None,
                            Error::ActuatorFailed.code(),
                        )
                        .map(Some);
                }
                return self
                    .finish(status, OperationPhase::Running, CompletionEvidence::None, 0)
                    .map(Some);
            }
            Action::SetConfig(config) => {
                next.config = config.clone();
                next.pending_relock = false;
                self.relock_deadline = None;
                if self.sample.bolt == Reading::Known(BoltState::Unlocked) {
                    self.schedule_relock(&mut next, now);
                }
                self.audit(
                    &mut next,
                    AuditKind::Configuration,
                    Some(status.credential_id),
                    Some(status.sequence),
                    0,
                )?;
            }
            Action::ApplyPolicy(bytes) => {
                let key = VerifyingKey::from_bytes(
                    &next.owner.as_ref().ok_or(Error::NotProvisioned)?.issuer,
                )
                .map_err(|_| Error::UntrustedKey)?;
                let p = read_policy(&key, bytes)?;
                if p.epoch > next.epoch {
                    next.epoch = p.epoch;
                    next.revoked.clear();
                    next.uses.clear();
                    next.bindings.clear();
                    next.watermarks.clear();
                    next.operations.retain(|r| r.status == *status);
                    next.watermarks
                        .insert(status.credential_id, status.sequence);
                    next.generation = next
                        .generation
                        .checked_add(1)
                        .ok_or(Error::ResourceExhausted)?;
                }
                next.policy_version = p.version;
                next.revoked.extend(p.revoked);
                self.audit(
                    &mut next,
                    AuditKind::Policy,
                    Some(status.credential_id),
                    Some(status.sequence),
                    0,
                )?;
            }
            Action::SetClock(time) => {
                next.clock_floor = Some(*time);
                next.clock_valid = false;
                self.commit(next)?;
                self.platform.set_wall_clock(*time)?;
                next = self.state.clone();
                next.clock_valid = true;
                self.audit(
                    &mut next,
                    AuditKind::Clock,
                    Some(status.credential_id),
                    Some(status.sequence),
                    0,
                )?;
            }
            Action::Reboot => {
                self.platform.request_reboot()?;
                self.audit(
                    &mut next,
                    AuditKind::Reboot,
                    Some(status.credential_id),
                    Some(status.sequence),
                    0,
                )?;
            }
            Action::FactoryReset => {
                let epoch = next.epoch.checked_add(1).ok_or(Error::ResourceExhausted)?;
                let generation = next
                    .generation
                    .checked_add(1)
                    .ok_or(Error::ResourceExhausted)?;
                let security = next.firmware.security_version;
                let floor = next.clock_floor;
                let valid = next.clock_valid;
                next = DeviceSnapshot::factory(&self.factory);
                next.epoch = epoch;
                next.generation = generation;
                next.firmware.security_version = security;
                next.clock_floor = floor;
                next.clock_valid = valid;
                self.commit(next)?;
                self.pairing_until = None;
                self.confirmation = None;
                self.relock_deadline = None;
                let mut result = status.clone();
                result.phase = OperationPhase::Completed;
                return Ok(Some(Reply::Operation(result)));
            }
            Action::ReplaceIssuer(issuer) => {
                next.owner = Some(Owner {
                    issuer: *issuer,
                    first_admin: context.peer,
                });
                next.epoch = next.epoch.checked_add(1).ok_or(Error::ResourceExhausted)?;
                next.generation = next
                    .generation
                    .checked_add(1)
                    .ok_or(Error::ResourceExhausted)?;
                next.revoked.clear();
                next.uses.clear();
                next.bindings.clear();
                next.watermarks.clear();
                next.operations.clear();
                next.policy_version = 0;
                self.audit(
                    &mut next,
                    AuditKind::Ownership,
                    Some(status.credential_id),
                    Some(status.sequence),
                    0,
                )?;
                self.commit(next)?;
                self.confirmation = None;
                let mut result = status.clone();
                result.phase = OperationPhase::Completed;
                return Ok(Some(Reply::Operation(result)));
            }
            Action::FirmwareBegin(bytes) => {
                let manifest = self.manifest(bytes)?;
                self.boot()?.begin(&manifest, bytes)?;
                next.firmware = FirmwareStatus {
                    phase: FirmwarePhase::Receiving,
                    received: 0,
                    manifest: Some(manifest),
                    security_version: next.firmware.security_version,
                };
                next.signed_manifest = bytes.clone();
            }
            Action::FirmwareChunk { offset, data } => {
                if *offset == next.firmware.received {
                    self.boot()?.write(*offset, data)?;
                    next.firmware.received = offset + data.len() as u64;
                }
            }
            Action::FirmwareFinish => {
                let m = next
                    .firmware
                    .manifest
                    .as_ref()
                    .ok_or(Error::FirmwareInvalid)?;
                if self.boot()?.image_hash(m.size)? != m.sha256 {
                    return Err(Error::FirmwareInvalid);
                }
                next.firmware.phase = FirmwarePhase::Verified;
            }
            Action::FirmwareActivate => {
                let m = next
                    .firmware
                    .manifest
                    .clone()
                    .ok_or(Error::FirmwareInvalid)?;
                next.firmware.phase = FirmwarePhase::Trial;
                self.commit(next)?;
                let signed = self.state.signed_manifest.clone();
                self.boot()?.activate(&m, &signed)?;
                next = self.state.clone();
            }
            Action::FirmwareAbort => {
                self.boot()?.abort()?;
                next.firmware = FirmwareStatus {
                    phase: FirmwarePhase::Empty,
                    received: 0,
                    manifest: None,
                    security_version: next.firmware.security_version,
                };
                next.signed_manifest.clear();
            }
            Action::RotateDeviceKey(bytes) => {
                let owner = next.owner.as_ref().ok_or(Error::NotProvisioned)?;
                let issuer =
                    VerifyingKey::from_bytes(&owner.issuer).map_err(|_| Error::UntrustedKey)?;
                let update = openlock_crypto::read_key_update(
                    &issuer,
                    &next.device_key,
                    bytes,
                    self.wall().ok_or(Error::ClockUntrusted)?,
                )?;
                if !self
                    .platform
                    .has_device_private_key(&update.new_record.key.x25519_public_key)
                {
                    return Err(Error::UntrustedKey);
                }
                next.device_key = update.new_record.key;
                next.generation = next
                    .generation
                    .checked_add(1)
                    .ok_or(Error::ResourceExhausted)?;
            }
            _ => return Err(Error::InvalidPayload),
        }
        if matches!(
            c.action,
            Action::FirmwareBegin(_)
                | Action::FirmwareChunk { .. }
                | Action::FirmwareFinish
                | Action::FirmwareActivate
                | Action::FirmwareAbort
        ) {
            self.audit(
                &mut next,
                AuditKind::Firmware,
                Some(status.credential_id),
                Some(status.sequence),
                0,
            )?;
        }
        self.commit(next)?;
        Ok(None)
    }
    fn manifest(&self, bytes: &[u8]) -> Result<FirmwareManifest, Error> {
        let key = VerifyingKey::from_bytes(&self.factory.firmware_root)
            .map_err(|_| Error::UntrustedKey)?;
        let m = read_manifest(&key, bytes)?;
        if m.model != self.factory.info.model || m.hardware != self.factory.info.hardware {
            return Err(Error::FirmwareTargetMismatch);
        }
        if m.security_version <= self.state.firmware.security_version {
            return Err(Error::FirmwareRollback);
        }
        Ok(m)
    }
    fn boot(&mut self) -> Result<&mut dyn Bootloader, Error> {
        self.platform
            .bootloader()
            .ok_or(Error::UnsupportedCapability)
    }
    fn reconcile_boot(&mut self) -> Result<(), Error> {
        if self.state.firmware.phase != FirmwarePhase::Trial {
            return Ok(());
        }
        let outcome = self.boot()?.outcome()?;
        let mut next = self.state.clone();
        match outcome {
            BootOutcome::Pending => return Ok(()),
            BootOutcome::Confirmed => {
                let m = next
                    .firmware
                    .manifest
                    .as_ref()
                    .ok_or(Error::FirmwareInvalid)?;
                next.firmware.security_version = m.security_version;
                next.firmware.phase = FirmwarePhase::Confirmed;
                self.factory.info.firmware = m.version.clone();
            }
            BootOutcome::RolledBack => next.firmware.phase = FirmwarePhase::Failed,
        }
        self.audit(
            &mut next,
            AuditKind::Firmware,
            None,
            None,
            if outcome == BootOutcome::RolledBack {
                Error::BootFailed.code()
            } else {
                0
            },
        )?;
        self.commit(next)
    }
    pub fn hardware_changed(&mut self) -> Result<(), Error> {
        let now = self.now()?;
        let sample = self.platform.sensors();
        if self.validate_sample(sample).is_err() {
            self.fault = Fault::SensorConflict;
            let i = &self.factory.info;
            self.sample = HardwareSample {
                bolt: if i.bolt_sensor {
                    Reading::Unknown
                } else {
                    Reading::Unsupported
                },
                door: if i.door_sensor {
                    Reading::Unknown
                } else {
                    Reading::Unsupported
                },
                privacy: if i.privacy_sensor {
                    Reading::Unknown
                } else {
                    Reading::Unsupported
                },
                battery_percent: if i.battery_sensor {
                    Reading::Unknown
                } else {
                    Reading::Unsupported
                },
            };
            let mut next = self.state.clone();
            if let Some(active) = self.active.take() {
                if self.platform.stop_action().is_err() {
                    self.poisoned = true;
                    return Err(Error::ActuatorFailed);
                }
                next.automatic_inflight = false;
                next.pending_relock = false;
                self.relock_deadline = None;
                if !active.automatic {
                    let record = next
                        .operations
                        .iter_mut()
                        .find(|r| {
                            r.status.credential_id == active.credential_id
                                && r.status.sequence == active.sequence
                        })
                        .ok_or(Error::ResultUnavailable)?;
                    record.status.phase = OperationPhase::Failed;
                    record.status.error = Error::SensorConflict.code();
                    record.status.evidence = CompletionEvidence::None;
                    self.audit(
                        &mut next,
                        AuditKind::Operation,
                        Some(active.credential_id),
                        Some(active.sequence),
                        Error::SensorConflict.code(),
                    )?;
                } else {
                    self.audit_automatic(
                        &mut next,
                        OperationPhase::Failed,
                        CompletionEvidence::None,
                        Error::SensorConflict.code(),
                    )?;
                }
            }
            if !next.events.last().is_some_and(|e| {
                e.kind == AuditKind::Hardware && e.code == Error::SensorConflict.code()
            }) {
                self.audit(
                    &mut next,
                    AuditKind::Hardware,
                    None,
                    None,
                    Error::SensorConflict.code(),
                )?;
            }
            if next != self.state {
                self.commit(next)?;
            }
            return Err(Error::SensorConflict);
        }
        let old = self.sample;
        self.sample = sample;
        if sample == old {
            return self.stop_unsafe_lock();
        }
        let mut next = self.state.clone();
        self.audit(&mut next, AuditKind::Hardware, None, None, 0)?;
        if let Some(event) = next.events.last_mut() {
            event.hardware = Some(sample);
        }
        if sample.bolt == Reading::Known(BoltState::Locked) {
            next.pending_relock = false;
            self.relock_deadline = None;
        }
        if old.door != sample.door {
            self.door_open_since = if sample.door == Reading::Known(DoorState::Open) {
                Some(now)
            } else {
                None
            };
            if next.pending_relock {
                if let AutoRelock::AfterClose(ms) = next.config.auto_relock {
                    self.relock_deadline = if sample.door == Reading::Known(DoorState::Closed) {
                        Some(now.saturating_add(ms as u64))
                    } else {
                        None
                    };
                }
            }
        }
        if self.active.is_none()
            && old.bolt != sample.bolt
            && sample.bolt == Reading::Known(BoltState::Unlocked)
        {
            self.schedule_relock(&mut next, now);
        }
        self.commit(next)?;
        self.stop_unsafe_lock()
    }
    fn stop_unsafe_lock(&mut self) -> Result<(), Error> {
        if !self
            .active
            .as_ref()
            .is_some_and(|a| a.target == ActionTarget::Lock)
        {
            return Ok(());
        }
        let error = match self.can_lock() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if self.platform.stop_action().is_err() {
            self.poisoned = true;
            return Err(Error::ActuatorFailed);
        }
        let active = self.active.take().ok_or(Error::InvalidState)?;
        self.fault = if error == Error::DoorOpen {
            Fault::DoorAjar
        } else {
            Fault::SensorConflict
        };
        let mut next = self.state.clone();
        next.automatic_inflight = false;
        next.pending_relock = false;
        self.relock_deadline = None;
        if !active.automatic {
            let record = next
                .operations
                .iter_mut()
                .find(|r| {
                    r.status.credential_id == active.credential_id
                        && r.status.sequence == active.sequence
                })
                .ok_or(Error::ResultUnavailable)?;
            record.status.phase = OperationPhase::Failed;
            record.status.evidence = CompletionEvidence::None;
            record.status.error = error.code();
        }
        if active.automatic {
            self.audit_automatic(
                &mut next,
                OperationPhase::Failed,
                CompletionEvidence::None,
                error.code(),
            )?;
        } else {
            self.audit(
                &mut next,
                AuditKind::Operation,
                Some(active.credential_id),
                Some(active.sequence),
                error.code(),
            )?;
        }
        self.commit(next)
    }
    fn schedule_relock(&mut self, next: &mut DeviceSnapshot, now: u64) {
        if next.config.hold_open {
            return;
        }
        match next.config.auto_relock {
            AutoRelock::Disabled => (),
            AutoRelock::Delay(ms) => {
                next.pending_relock = true;
                self.relock_deadline = Some(now.saturating_add(ms as u64));
            }
            AutoRelock::AfterClose(ms) => {
                next.pending_relock = true;
                self.relock_deadline = if self.sample.door == Reading::Known(DoorState::Closed) {
                    Some(now.saturating_add(ms as u64))
                } else {
                    None
                };
            }
        }
    }
    pub fn actuator_finished(&mut self, result: ActuatorResult) -> Result<(), Error> {
        let now = self.now()?;
        self.hardware_changed()?;
        let active = self.active.take().ok_or(Error::InvalidState)?;
        let expected = if active.target == ActionTarget::Unlock {
            BoltState::Unlocked
        } else {
            BoltState::Locked
        };
        let (phase, evidence, error) = match result {
            ActuatorResult::Completed if matches!(self.sample.bolt,Reading::Known(b) if b!=expected) =>
            {
                self.fault = Fault::SensorConflict;
                (
                    OperationPhase::Failed,
                    CompletionEvidence::Sensor,
                    Error::SensorConflict.code(),
                )
            }
            ActuatorResult::Completed => {
                self.fault = Fault::None;
                (
                    OperationPhase::Completed,
                    if self.sample.bolt == Reading::Known(expected) {
                        CompletionEvidence::Sensor
                    } else {
                        CompletionEvidence::Driver
                    },
                    0,
                )
            }
            ActuatorResult::Jammed => {
                self.fault = Fault::Jammed;
                (
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    Error::Jammed.code(),
                )
            }
            ActuatorResult::SensorConflict => {
                self.fault = Fault::SensorConflict;
                (
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    Error::SensorConflict.code(),
                )
            }
            ActuatorResult::Failed => {
                self.fault = Fault::Driver;
                (
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    Error::ActuatorFailed.code(),
                )
            }
        };
        let mut next = self.state.clone();
        if phase == OperationPhase::Completed && active.target == ActionTarget::Unlock {
            self.schedule_relock(&mut next, now);
        }
        if active.target == ActionTarget::Lock {
            next.automatic_inflight = false;
            next.pending_relock = false;
            self.relock_deadline = None;
        }
        self.commit(next)?;
        if active.automatic {
            let mut next = self.state.clone();
            self.audit_automatic(&mut next, phase, evidence, error)?;
            self.commit(next)?;
        } else {
            let status = self
                .state
                .operations
                .iter()
                .find(|r| {
                    r.status.credential_id == active.credential_id
                        && r.status.sequence == active.sequence
                })
                .ok_or(Error::ResultUnavailable)?
                .status
                .clone();
            self.finish(&status, phase, evidence, error)?;
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<(), Error> {
        let now = self.now()?;
        self.hardware_changed()?;
        self.reconcile_boot()?;
        if self.active.as_ref().is_some_and(|a| now >= a.deadline) {
            let operation = self
                .active
                .as_ref()
                .filter(|a| !a.automatic)
                .map(|a| (a.credential_id, a.sequence));
            if self.platform.stop_action().is_err() {
                self.poisoned = true;
                return Err(Error::ActuatorFailed);
            }
            self.actuator_finished(ActuatorResult::Failed)?;
            self.fault = Fault::Timeout;
            // Distinct timeout result; never retry the action.
            if let Some(record) = self
                .state
                .operations
                .iter()
                .find(|r| Some((r.status.credential_id, r.status.sequence)) == operation)
                .cloned()
            {
                self.finish(
                    &record.status,
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    Error::ActionTimeout.code(),
                )?;
            } else if operation.is_none() {
                let mut next = self.state.clone();
                self.audit_automatic(
                    &mut next,
                    OperationPhase::Failed,
                    CompletionEvidence::None,
                    Error::ActionTimeout.code(),
                )?;
                self.commit(next)?;
            }
        }
        if self.state.config.door_ajar_ms > 0
            && self
                .door_open_since
                .is_some_and(|t| now.saturating_sub(t) >= self.state.config.door_ajar_ms as u64)
            && self.fault != Fault::DoorAjar
        {
            self.fault = Fault::DoorAjar;
            let mut next = self.state.clone();
            self.audit(
                &mut next,
                AuditKind::Hardware,
                None,
                None,
                Error::DoorOpen.code(),
            )?;
            self.commit(next)?;
        }
        if self.active.is_none()
            && self.state.firmware.phase != FirmwarePhase::Trial
            && self.state.pending_relock
            && self.relock_deadline.is_some_and(|t| now >= t)
            && self.can_lock().is_ok()
        {
            // Clearing this intent before driving prevents a reboot from replaying an ambiguous motor action.
            let mut next = self.state.clone();
            next.pending_relock = false;
            next.automatic_inflight = true;
            self.audit_automatic(
                &mut next,
                OperationPhase::Accepted,
                CompletionEvidence::None,
                0,
            )?;
            self.commit(next)?;
            self.relock_deadline = None;
            self.active = Some(Active {
                credential_id: CredentialId([0; 16]),
                sequence: 0,
                target: ActionTarget::Lock,
                deadline: now.saturating_add(self.state.config.action_timeout_ms as u64),
                automatic: true,
            });
            if let Err(e) =
                self.platform
                    .start_action(ActionTarget::Lock, self.state.config.release_ms, false)
            {
                self.fault = Fault::Driver;
                return Err(e);
            }
        }
        Ok(())
    }
}
