use crate::cbor::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use openlock_types::*;

const GRANT: &[u8] = b"openlock:v2:grant";
const POLICY: &[u8] = b"openlock:v2:policy";

fn protected() -> Value {
    Value::Map(vec![(uint(1), Value::Integer((-8).into()))])
}
fn structure(kind: &[u8], header: &[u8], payload: &[u8]) -> Value {
    array(vec![
        Value::Text("Signature1".into()),
        bytes(header),
        bytes(kind),
        bytes(payload),
    ])
}
pub fn sign_object(key: &SigningKey, kind: &[u8], payload: &Value) -> Result<Vec<u8>, Error> {
    let payload = encode(payload)?;
    let header = encode(&protected())?;
    let signature = key.sign(&encode(&structure(kind, &header, &payload))?);
    encode(&array(vec![
        bytes(&header),
        Value::Map(vec![]),
        bytes(&payload),
        bytes(&signature.to_bytes()),
    ]))
}
pub fn verify_object(key: &VerifyingKey, kind: &[u8], cose: &[u8]) -> Result<Value, Error> {
    let object = decode(cose)?;
    let f = fields(&object, 4).map_err(|_| Error::InvalidCose)?;
    let header = data(&f[0])?;
    if header != encode(&protected())? || f[1] != Value::Map(vec![]) {
        return Err(Error::InvalidCose);
    }
    let payload = data(&f[2])?;
    let signature = Signature::from_slice(data(&f[3])?).map_err(|_| Error::InvalidCose)?;
    key.verify_strict(&encode(&structure(kind, header, payload))?, &signature)
        .map_err(|_| Error::BadSignature)?;
    decode(payload)
}
pub fn grant_value(g: &Grant) -> Value {
    array(vec![
        uint(PROTOCOL_VERSION),
        Value::Text("grant".into()),
        bytes(&g.credential_id.0),
        bytes(&g.lock_id.0),
        bytes(&g.subject_key.0),
        uint(g.rights as u64),
        uint(g.epoch),
        g.validity.map_or(Value::Null, |v| {
            array(vec![uint(v.not_before), uint(v.not_after)])
        }),
        g.max_uses.map_or(Value::Null, |n| uint(n as u64)),
    ])
}
fn parse_grant(v: &Value) -> Result<Grant, Error> {
    let f = fields(v, 9)?;
    if number(&f[0])? != PROTOCOL_VERSION || f[1] != Value::Text("grant".into()) {
        return Err(Error::UnsupportedVersion);
    }
    let validity = if f[7] == Value::Null {
        None
    } else {
        let t = fields(&f[7], 2)?;
        Some(Validity {
            not_before: number(&t[0])?,
            not_after: number(&t[1])?,
        })
    };
    let grant = Grant {
        credential_id: CredentialId(fixed(&f[2])?),
        lock_id: LockId(fixed(&f[3])?),
        subject_key: SubjectKey(fixed(&f[4])?),
        rights: u32_value(&f[5])?,
        epoch: number(&f[6])?,
        validity,
        max_uses: optional_u32(&f[8])?,
    };
    validate_grant(&grant)?;
    Ok(grant)
}
fn validate_grant(g: &Grant) -> Result<(), Error> {
    if g.rights == 0
        || g.rights & !(RIGHTS_UNLOCK | RIGHTS_STATUS) != 0
        || g.max_uses == Some(0)
        || g.validity.is_some_and(|v| v.not_before >= v.not_after)
    {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}
pub fn sign_grant(key: &SigningKey, grant: &Grant) -> Result<Vec<u8>, Error> {
    validate_grant(grant)?;
    sign_object(key, GRANT, &grant_value(grant))
}
pub fn read_grant(key: &VerifyingKey, cose: &[u8]) -> Result<Grant, Error> {
    parse_grant(&verify_object(key, GRANT, cose)?)
}
pub fn verify_grant(key: &VerifyingKey, grant: &Grant, cose: &[u8]) -> Result<(), Error> {
    if read_grant(key, cose)? != *grant {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}
pub fn policy_value(p: &PolicyUpdate) -> Value {
    array(vec![
        uint(PROTOCOL_VERSION),
        Value::Text("policy".into()),
        bytes(&p.lock_id.0),
        uint(p.epoch),
        uint(p.version),
        array(p.revoked.iter().map(|id| bytes(&id.0)).collect()),
    ])
}
pub fn sign_policy(key: &SigningKey, policy: &PolicyUpdate) -> Result<Vec<u8>, Error> {
    sign_object(key, POLICY, &policy_value(policy))
}
pub fn read_policy(key: &VerifyingKey, cose: &[u8]) -> Result<PolicyUpdate, Error> {
    let v = verify_object(key, POLICY, cose)?;
    let f = fields(&v, 6)?;
    if number(&f[0])? != PROTOCOL_VERSION || f[1] != Value::Text("policy".into()) {
        return Err(Error::UnsupportedVersion);
    }
    let Value::Array(ids) = &f[5] else {
        return Err(Error::InvalidPayload);
    };
    let p = PolicyUpdate {
        lock_id: LockId(fixed(&f[2])?),
        epoch: number(&f[3])?,
        version: number(&f[4])?,
        revoked: ids
            .iter()
            .map(|v| fixed(v).map(CredentialId))
            .collect::<Result<_, _>>()?,
    };
    if policy_value(&p) != v {
        return Err(Error::InvalidPayload);
    }
    Ok(p)
}
pub fn verify_policy(key: &VerifyingKey, policy: &PolicyUpdate, cose: &[u8]) -> Result<(), Error> {
    if read_policy(key, cose)? != *policy {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}
