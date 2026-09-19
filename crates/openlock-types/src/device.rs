//! Physical and management contract. Integer representations are specified on wire.
use crate::*;
use alloc::string::String;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reading<T> {
    Unsupported,
    Unknown,
    Known(T),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoltState {
    Locked,
    Unlocked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoorState {
    Closed,
    Open,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuatorKind {
    Motor,
    Pulse,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionTarget {
    Unlock,
    Lock,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    None,
    Jammed,
    Timeout,
    SensorConflict,
    Driver,
    DoorAjar,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionEvidence {
    None,
    Driver,
    Sensor,
    NoChange,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    Accepted,
    Running,
    Completed,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationStatus {
    pub credential_id: CredentialId,
    pub sequence: u64,
    pub opcode: u8,
    pub phase: OperationPhase,
    pub evidence: CompletionEvidence,
    pub error: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockStatus {
    pub bolt: Reading<BoltState>,
    pub door: Reading<DoorState>,
    pub privacy: Reading<bool>,
    pub battery_percent: Reading<u8>,
    pub fault: Fault,
    pub active: Option<OperationStatus>,
    pub epoch: u64,
    pub policy_version: u64,
    pub config_version: u64,
    pub generation: u64,
    pub clock_trusted: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub lock_id: LockId,
    pub model: String,
    pub hardware: String,
    pub firmware: String,
    pub capabilities: u64,
    pub actuator: ActuatorKind,
    pub bolt_sensor: bool,
    pub door_sensor: bool,
    pub privacy_sensor: bool,
    pub battery_sensor: bool,
    pub safe_lock_without_door: bool,
    pub hold_open: bool,
    pub max_release_ms: u32,
    pub max_action_ms: u32,
    pub max_delay_ms: u32,
    pub log_capacity: u32,
    pub operation_capacity: u32,
    pub credential_capacity: u32,
    pub max_image_size: u64,
    pub max_chunk_size: u32,
}
impl DeviceInfo {
    pub fn validate(&self) -> Result<(), Error> {
        if self.capabilities == 0
            || self.capabilities & !KNOWN_CAPABILITIES != 0
            || self.model.is_empty()
            || self.hardware.is_empty()
            || self.firmware.is_empty()
            || self.model.len() > 64
            || self.hardware.len() > 64
            || self.firmware.len() > 64
            || self.max_release_ms == 0
            || self.max_action_ms == 0
            || self.max_delay_ms == 0
            || self.log_capacity == 0
            || self.operation_capacity == 0
            || self.credential_capacity == 0
            || self.max_chunk_size > 1024
            || (self.actuator == ActuatorKind::Pulse && self.capabilities & (1 << 3) != 0)
            || (self.capabilities & (0x3f << 13) != 0
                && (self.max_image_size == 0 || self.max_chunk_size == 0))
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoRelock {
    Disabled,
    Delay(u32),
    AfterClose(u32),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceConfig {
    pub version: u64,
    pub auto_relock: AutoRelock,
    pub release_ms: u32,
    pub action_timeout_ms: u32,
    pub hold_open: bool,
    pub door_ajar_ms: u32,
}
impl DeviceConfig {
    pub fn factory(info: &DeviceInfo) -> Self {
        Self {
            version: 0,
            auto_relock: AutoRelock::Disabled,
            release_ms: info.max_release_ms.min(500),
            action_timeout_ms: info.max_action_ms.min(10_000),
            hold_open: false,
            door_ajar_ms: 0,
        }
    }
    pub fn validate(&self, info: &DeviceInfo) -> Result<(), Error> {
        if self.release_ms == 0
            || self.release_ms > info.max_release_ms
            || self.action_timeout_ms == 0
            || self.action_timeout_ms > info.max_action_ms
            || self.hold_open && !info.hold_open
            || self.door_ajar_ms > info.max_delay_ms
            || self.door_ajar_ms != 0 && !info.door_sensor
        {
            return Err(Error::InvalidConfig);
        }
        match self.auto_relock {
            AutoRelock::Disabled => (),
            AutoRelock::Delay(ms) | AutoRelock::AfterClose(ms) => {
                if ms == 0
                    || ms > info.max_delay_ms
                    || info.capabilities & (1 << 3) == 0
                    || self.hold_open
                    || (!info.door_sensor && !info.safe_lock_without_door)
                    || matches!(self.auto_relock, AutoRelock::AfterClose(_)) && !info.door_sensor
                {
                    return Err(Error::InvalidConfig);
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditKind {
    Operation,
    Hardware,
    Configuration,
    Ownership,
    Clock,
    Policy,
    Firmware,
    Reboot,
    Rejected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareState {
    pub bolt: Reading<BoltState>,
    pub door: Reading<DoorState>,
    pub privacy: Reading<bool>,
    pub battery_percent: Reading<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub cursor: u64,
    pub unix_seconds: Option<u64>,
    pub kind: AuditKind,
    pub credential_id: Option<CredentialId>,
    pub sequence: Option<u64>,
    pub code: u32,
    pub hardware: Option<HardwareState>,
    pub operation: Option<OperationStatus>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_cursor: u64,
    pub gap: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirmwareManifest {
    pub model: String,
    pub hardware: String,
    pub version: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub security_version: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwarePhase {
    Empty,
    Receiving,
    Verified,
    Trial,
    Confirmed,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirmwareStatus {
    pub phase: FirmwarePhase,
    pub received: u64,
    pub manifest: Option<FirmwareManifest>,
    pub security_version: u64,
}
#[derive(Clone, Eq, PartialEq)]
pub enum Action {
    Unlock,
    Status,
    ApplyPolicy(Vec<u8>),
    Lock,
    Info,
    Operation(u64),
    GetConfig,
    SetConfig(DeviceConfig),
    ReadLog {
        after: u64,
        limit: u32,
    },
    SetClock(u64),
    Reboot,
    FactoryReset,
    ReplaceIssuer([u8; 32]),
    FirmwareBegin(Vec<u8>),
    FirmwareChunk {
        offset: u64,
        data: Vec<u8>,
    },
    FirmwareFinish,
    FirmwareActivate,
    FirmwareAbort,
    FirmwareStatus,
    Claim {
        setup_key: [u8; 32],
        issuer: [u8; 32],
        admin_credential: Vec<u8>,
    },
    CredentialStatus,
    RotateDeviceKey(Vec<u8>),
    PairingStatus,
}
impl Action {
    pub fn opcode(&self) -> u8 {
        match self {
            Self::Unlock => 0,
            Self::Status => 1,
            Self::ApplyPolicy(_) => 2,
            Self::Lock => 3,
            Self::Info => 4,
            Self::Operation(_) => 5,
            Self::GetConfig => 6,
            Self::SetConfig(_) => 7,
            Self::ReadLog { .. } => 8,
            Self::SetClock(_) => 9,
            Self::Reboot => 10,
            Self::FactoryReset => 11,
            Self::ReplaceIssuer(_) => 12,
            Self::FirmwareBegin(_) => 13,
            Self::FirmwareChunk { .. } => 14,
            Self::FirmwareFinish => 15,
            Self::FirmwareActivate => 16,
            Self::FirmwareAbort => 17,
            Self::FirmwareStatus => 18,
            Self::Claim { .. } => 19,
            Self::CredentialStatus => 20,
            Self::RotateDeviceKey(_) => 21,
            Self::PairingStatus => 22,
        }
    }
    pub fn right(&self) -> u32 {
        match self {
            Self::Unlock => RIGHTS_UNLOCK,
            Self::Lock => RIGHTS_LOCK,
            Self::Status
            | Self::Info
            | Self::Operation(_)
            | Self::GetConfig
            | Self::CredentialStatus => RIGHTS_STATUS,
            Self::ApplyPolicy(_) => RIGHTS_CREDENTIALS,
            Self::SetConfig(_) => RIGHTS_CONFIG,
            Self::ReadLog { .. } => RIGHTS_LOG,
            Self::SetClock(_) => RIGHTS_CLOCK,
            Self::Reboot => RIGHTS_REBOOT,
            Self::FactoryReset => RIGHTS_RESET,
            Self::ReplaceIssuer(_) | Self::RotateDeviceKey(_) => RIGHTS_TRUST,
            Self::FirmwareBegin(_)
            | Self::FirmwareChunk { .. }
            | Self::FirmwareFinish
            | Self::FirmwareActivate
            | Self::FirmwareAbort
            | Self::FirmwareStatus => RIGHTS_FIRMWARE,
            Self::Claim { .. } | Self::PairingStatus => 0,
        }
    }
    pub fn mutates(&self) -> bool {
        !matches!(
            self,
            Self::Status
                | Self::Info
                | Self::Operation(_)
                | Self::GetConfig
                | Self::ReadLog { .. }
                | Self::FirmwareStatus
                | Self::CredentialStatus
                | Self::PairingStatus
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub credential: Vec<u8>,
    pub sequence: Option<u64>,
    pub action: Action,
}
impl Command {
    pub fn capability(&self) -> u64 {
        1 << self.action.opcode()
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.credential.len() > MAX_OBJECT_SIZE
            || self.credential.is_empty()
                != matches!(self.action, Action::Claim { .. } | Action::PairingStatus)
            || self.action.mutates() != self.sequence.is_some()
            || self.sequence == Some(0)
        {
            return Err(Error::InvalidPayload);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    Operation(OperationStatus),
    Status(LockStatus),
    Info(DeviceInfo),
    Config(DeviceConfig),
    Audit(AuditPage),
    Firmware(FirmwareStatus),
    Pairing {
        epoch: u64,
        generation: u64,
        window_open: bool,
    },
    Claimed {
        epoch: u64,
        generation: u64,
    },
    Credential {
        uses: u32,
        max_uses: Option<u32>,
        next_sequence: u64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub opcode: u8,
    pub result: Result<Reply, u32>,
}
impl Response {
    pub fn rejected(action: &Action, error: Error) -> Self {
        Self {
            opcode: action.opcode(),
            result: Err(error.code()),
        }
    }
}

impl core::fmt::Debug for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Action")
            .field("opcode", &self.opcode())
            .finish_non_exhaustive()
    }
}

impl Drop for Action {
    fn drop(&mut self) {
        if let Self::Claim { setup_key, .. } = self {
            use zeroize::Zeroize;
            setup_key.zeroize();
        }
    }
}
