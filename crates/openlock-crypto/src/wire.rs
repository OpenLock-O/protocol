//! Canonical v4 application values, shared by wire, issuer and controller.
use crate::cbor::*;
use alloc::{string::String, vec, vec::Vec};
use openlock_types::*;

pub trait Wire: Sized {
    fn value(&self) -> Value;
    fn parse(value: &Value) -> Result<Self, Error>;
}
pub fn encode_wire<T: Wire>(value: &T) -> Result<Vec<u8>, Error> {
    encode(&value.value())
}
pub fn decode_wire<T: Wire>(input: &[u8]) -> Result<T, Error> {
    T::parse(&decode(input)?)
}
macro_rules! integer {
    ($($t:ty),*) => {$(impl Wire for $t {
        fn value(&self)->Value { uint(*self as u64) }
        fn parse(v:&Value)->Result<Self,Error> { number(v)?.try_into().map_err(|_|Error::InvalidPayload) }
    })*};
}
integer!(u8, u32, u64);
impl Wire for bool {
    fn value(&self) -> Value {
        uint(u64::from(*self))
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        match number(v)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidPayload),
        }
    }
}
impl Wire for String {
    fn value(&self) -> Value {
        Value::Text(self.clone())
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        match v {
            Value::Text(s) if s.len() <= 64 => Ok(s.clone()),
            _ => Err(Error::InvalidPayload),
        }
    }
}
impl<const N: usize> Wire for [u8; N] {
    fn value(&self) -> Value {
        bytes(self)
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        fixed(v)
    }
}
impl Wire for Vec<u8> {
    fn value(&self) -> Value {
        bytes(self)
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        Ok(data(v)?.to_vec())
    }
}
impl<T: Wire> Wire for Option<T> {
    fn value(&self) -> Value {
        self.as_ref().map_or(Value::Null, Wire::value)
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        if *v == Value::Null {
            Ok(None)
        } else {
            Ok(Some(T::parse(v)?))
        }
    }
}
macro_rules! enumeration {
    ($t:ty; $($v:ident),+) => {impl Wire for $t {
        fn value(&self)->Value { uint(*self as u64) }
        fn parse(v:&Value)->Result<Self,Error> { let n=number(v)?; $(if n==Self::$v as u64 {return Ok(Self::$v);})+ Err(Error::InvalidPayload) }
    }};
}
enumeration!(BoltState; Locked,Unlocked);
enumeration!(DoorState; Closed,Open);
enumeration!(ActuatorKind; Motor,Pulse);
enumeration!(Fault; None,Jammed,Timeout,SensorConflict,Driver,DoorAjar);
enumeration!(CompletionEvidence; None,Driver,Sensor,NoChange);
enumeration!(OperationPhase; Accepted,Running,Completed,Failed,Unknown);
enumeration!(AuditKind; Operation,Hardware,Configuration,Ownership,Clock,Policy,Firmware,Reboot,Rejected);
enumeration!(FirmwarePhase; Empty,Receiving,Verified,Trial,Confirmed,Failed);
impl<T: Wire> Wire for Reading<T> {
    fn value(&self) -> Value {
        match self {
            Self::Unsupported => array(vec![uint(0)]),
            Self::Unknown => array(vec![uint(1)]),
            Self::Known(x) => array(vec![uint(2), x.value()]),
        }
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let Value::Array(f) = v else {
            return Err(Error::InvalidPayload);
        };
        match (f.first().map(number).transpose()?, f.len()) {
            (Some(0), 1) => Ok(Self::Unsupported),
            (Some(1), 1) => Ok(Self::Unknown),
            (Some(2), 2) => Ok(Self::Known(T::parse(&f[1])?)),
            _ => Err(Error::InvalidPayload),
        }
    }
}
macro_rules! id {
    ($t:ty) => {
        impl Wire for $t {
            fn value(&self) -> Value {
                self.0.value()
            }
            fn parse(v: &Value) -> Result<Self, Error> {
                Ok(Self(fixed(v)?))
            }
        }
    };
}
id!(LockId);
id!(CredentialId);
id!(SubjectKey);
macro_rules! record {
    ($t:ty; $($field:ident),+) => {impl Wire for $t {
        fn value(&self)->Value {array(vec![$(self.$field.value()),+])}
        fn parse(v:&Value)->Result<Self,Error> {
            let count=[$(stringify!($field)),+].len(); let mut iter=fields(v,count)?.iter();
            Ok(Self{$($field:Wire::parse(iter.next().ok_or(Error::InvalidPayload)?)?),+})
        }
    }};
}
record!(OperationStatus; credential_id,sequence,opcode,phase,evidence,error);
record!(LockStatus; bolt,door,privacy,battery_percent,fault,active,epoch,policy_version,config_version,generation,clock_trusted);
record!(DeviceInfo; lock_id,model,hardware,firmware,capabilities,actuator,bolt_sensor,door_sensor,privacy_sensor,battery_sensor,safe_lock_without_door,hold_open,max_release_ms,max_action_ms,max_delay_ms,log_capacity,operation_capacity,credential_capacity,max_image_size,max_chunk_size);
record!(DeviceConfig; version,auto_relock,release_ms,action_timeout_ms,hold_open,door_ajar_ms);
record!(AuditEvent; cursor,unix_seconds,kind,credential_id,sequence,code,hardware,operation);
record!(FirmwareManifest; model,hardware,version,size,sha256,security_version);
record!(FirmwareStatus; phase,received,manifest,security_version);
impl Wire for AutoRelock {
    fn value(&self) -> Value {
        match self {
            Self::Disabled => array(vec![uint(0)]),
            Self::Delay(ms) => array(vec![uint(1), ms.value()]),
            Self::AfterClose(ms) => array(vec![uint(2), ms.value()]),
        }
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let Value::Array(f) = v else {
            return Err(Error::InvalidPayload);
        };
        match (f.first().map(number).transpose()?, f.len()) {
            (Some(0), 1) => Ok(Self::Disabled),
            (Some(1), 2) => Ok(Self::Delay(u32_value(&f[1])?)),
            (Some(2), 2) => Ok(Self::AfterClose(u32_value(&f[1])?)),
            _ => Err(Error::InvalidPayload),
        }
    }
}
impl Wire for AuditPage {
    fn value(&self) -> Value {
        array(vec![
            array(self.events.iter().map(Wire::value).collect()),
            self.next_cursor.value(),
            self.gap.value(),
        ])
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let f = fields(v, 3)?;
        let Value::Array(events) = &f[0] else {
            return Err(Error::InvalidPayload);
        };
        if events.len() > 16 {
            return Err(Error::ObjectTooLarge);
        }
        Ok(Self {
            events: events
                .iter()
                .map(AuditEvent::parse)
                .collect::<Result<_, _>>()?,
            next_cursor: Wire::parse(&f[1])?,
            gap: Wire::parse(&f[2])?,
        })
    }
}
impl Wire for Action {
    fn value(&self) -> Value {
        let mut f = vec![self.opcode().value()];
        match self {
            Self::ApplyPolicy(x) | Self::FirmwareBegin(x) | Self::RotateDeviceKey(x) => {
                f.push(x.value())
            }
            Self::Operation(x) | Self::SetClock(x) => f.push(x.value()),
            Self::SetConfig(x) => f.push(x.value()),
            Self::ReadLog { after, limit } => f.extend([after.value(), limit.value()]),
            Self::ReplaceIssuer(x) => f.push(x.value()),
            Self::FirmwareChunk { offset, data } => f.extend([offset.value(), data.value()]),
            Self::Claim {
                setup_key,
                issuer,
                admin_credential,
            } => f.extend([setup_key.value(), issuer.value(), admin_credential.value()]),
            _ => (),
        };
        array(f)
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let Value::Array(f) = v else {
            return Err(Error::InvalidPayload);
        };
        let op = number(f.first().ok_or(Error::InvalidPayload)?)?;
        Ok(match (op, f.len()) {
            (0, 1) => Self::Unlock,
            (1, 1) => Self::Status,
            (2, 2) => Self::ApplyPolicy(Wire::parse(&f[1])?),
            (3, 1) => Self::Lock,
            (4, 1) => Self::Info,
            (5, 2) => Self::Operation(Wire::parse(&f[1])?),
            (6, 1) => Self::GetConfig,
            (7, 2) => Self::SetConfig(Wire::parse(&f[1])?),
            (8, 3) => {
                let limit = u32_value(&f[2])?;
                if limit == 0 || limit > 16 {
                    return Err(Error::InvalidPayload);
                }
                Self::ReadLog {
                    after: Wire::parse(&f[1])?,
                    limit,
                }
            }
            (9, 2) => Self::SetClock(Wire::parse(&f[1])?),
            (10, 1) => Self::Reboot,
            (11, 1) => Self::FactoryReset,
            (12, 2) => Self::ReplaceIssuer(Wire::parse(&f[1])?),
            (13, 2) => Self::FirmwareBegin(Wire::parse(&f[1])?),
            (14, 3) => {
                let data: Vec<u8> = Wire::parse(&f[2])?;
                if data.is_empty() || data.len() > 1024 {
                    return Err(Error::InvalidPayload);
                }
                Self::FirmwareChunk {
                    offset: Wire::parse(&f[1])?,
                    data,
                }
            }
            (15, 1) => Self::FirmwareFinish,
            (16, 1) => Self::FirmwareActivate,
            (17, 1) => Self::FirmwareAbort,
            (18, 1) => Self::FirmwareStatus,
            (19, 4) => Self::Claim {
                setup_key: Wire::parse(&f[1])?,
                issuer: Wire::parse(&f[2])?,
                admin_credential: Wire::parse(&f[3])?,
            },
            (22, 1) => Self::PairingStatus,
            (20, 1) => Self::CredentialStatus,
            (21, 2) => Self::RotateDeviceKey(Wire::parse(&f[1])?),
            _ => return Err(Error::InvalidPayload),
        })
    }
}
impl Wire for Command {
    fn value(&self) -> Value {
        array(vec![
            self.credential.value(),
            self.sequence.value(),
            self.action.value(),
        ])
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let f = fields(v, 3)?;
        let out = Self {
            credential: Wire::parse(&f[0])?,
            sequence: Wire::parse(&f[1])?,
            action: Wire::parse(&f[2])?,
        };
        out.validate()?;
        Ok(out)
    }
}
impl Wire for Reply {
    fn value(&self) -> Value {
        let (tag, data) = match self {
            Self::Operation(x) => (0, x.value()),
            Self::Status(x) => (1, x.value()),
            Self::Info(x) => (2, x.value()),
            Self::Config(x) => (3, x.value()),
            Self::Audit(x) => (4, x.value()),
            Self::Firmware(x) => (5, x.value()),
            Self::Pairing {
                epoch,
                generation,
                window_open,
            } => (
                8,
                array(vec![epoch.value(), generation.value(), window_open.value()]),
            ),
            Self::Claimed { epoch, generation } => {
                (6, array(vec![epoch.value(), generation.value()]))
            }
            Self::Credential {
                uses,
                max_uses,
                next_sequence,
            } => (
                7,
                array(vec![uses.value(), max_uses.value(), next_sequence.value()]),
            ),
        };
        array(vec![uint(tag), data])
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let f = fields(v, 2)?;
        Ok(match number(&f[0])? {
            0 => Self::Operation(Wire::parse(&f[1])?),
            1 => Self::Status(Wire::parse(&f[1])?),
            2 => Self::Info(Wire::parse(&f[1])?),
            3 => Self::Config(Wire::parse(&f[1])?),
            4 => Self::Audit(Wire::parse(&f[1])?),
            5 => Self::Firmware(Wire::parse(&f[1])?),
            8 => {
                let v = fields(&f[1], 3)?;
                Self::Pairing {
                    epoch: Wire::parse(&v[0])?,
                    generation: Wire::parse(&v[1])?,
                    window_open: Wire::parse(&v[2])?,
                }
            }
            6 => {
                let v = fields(&f[1], 2)?;
                Self::Claimed {
                    epoch: Wire::parse(&v[0])?,
                    generation: Wire::parse(&v[1])?,
                }
            }
            7 => {
                let v = fields(&f[1], 3)?;
                Self::Credential {
                    uses: Wire::parse(&v[0])?,
                    max_uses: Wire::parse(&v[1])?,
                    next_sequence: Wire::parse(&v[2])?,
                }
            }
            _ => return Err(Error::InvalidPayload),
        })
    }
}
impl Wire for Response {
    fn value(&self) -> Value {
        match &self.result {
            Ok(reply) => array(vec![self.opcode.value(), uint(0), reply.value()]),
            Err(code) => array(vec![self.opcode.value(), code.value(), Value::Null]),
        }
    }
    fn parse(v: &Value) -> Result<Self, Error> {
        let f = fields(v, 3)?;
        let opcode = u8::parse(&f[0])?;
        if opcode > 22 {
            return Err(Error::InvalidPayload);
        }
        let code = u32_value(&f[1])?;
        let result = if code == 0 {
            Ok(Reply::parse(&f[2])?)
        } else {
            if f[2] != Value::Null {
                return Err(Error::InvalidPayload);
            }
            Err(code)
        };
        let r = Self { opcode, result };
        validate_response(&r)?;
        Ok(r)
    }
}
pub fn validate_response(r: &Response) -> Result<(), Error> {
    if r.opcode > 22 {
        return Err(Error::InvalidPayload);
    }
    if let Ok(reply) = &r.result {
        let valid = match reply {
            Reply::Status(_) => r.opcode == 1,
            Reply::Info(_) => r.opcode == 4,
            Reply::Config(_) => r.opcode == 6,
            Reply::Audit(_) => r.opcode == 8,
            Reply::Firmware(_) => r.opcode == 18,
            Reply::Pairing { .. } => r.opcode == 22,
            Reply::Claimed { .. } => r.opcode == 19,
            Reply::Credential { .. } => r.opcode == 20,
            Reply::Operation(op) => r.opcode == 5 || op.opcode == r.opcode,
        };
        if !valid {
            return Err(Error::InvalidPayload);
        }
    } else if r.result == Err(0) {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}

record!(HardwareState; bolt,door,privacy,battery_percent);
