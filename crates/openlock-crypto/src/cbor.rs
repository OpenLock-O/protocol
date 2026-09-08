//! The v2 profile permits only definite, minimally encoded arrays, bytes and integers.
pub use ciborium::value::Value;
use ciborium::{de::from_reader, ser::into_writer};
use openlock_types::{Error, MAX_OBJECT_SIZE};
use std::io::Cursor;

pub fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}
pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
pub fn array(v: Vec<Value>) -> Value {
    Value::Array(v)
}
pub fn number(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Integer(n) => (*n).try_into().map_err(|_| Error::InvalidPayload),
        _ => Err(Error::InvalidPayload),
    }
}
pub fn u32_value(v: &Value) -> Result<u32, Error> {
    number(v)?.try_into().map_err(|_| Error::InvalidPayload)
}
pub fn data(v: &Value) -> Result<&[u8], Error> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(Error::InvalidPayload),
    }
}
pub fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    data(v)?.try_into().map_err(|_| Error::InvalidPayload)
}
pub fn fields(v: &Value, count: usize) -> Result<&[Value], Error> {
    match v {
        Value::Array(a) if a.len() == count => Ok(a),
        _ => Err(Error::InvalidPayload),
    }
}
pub fn optional_u32(v: &Value) -> Result<Option<u32>, Error> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(u32_value(v)?))
    }
}
pub fn encode(v: &Value) -> Result<Vec<u8>, Error> {
    encode_limit(v, MAX_OBJECT_SIZE)
}
pub fn encode_limit(v: &Value, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    into_writer(v, &mut out).map_err(|_| Error::InvalidPayload)?;
    if out.len() > limit {
        return Err(Error::ObjectTooLarge);
    }
    Ok(out)
}
pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
    decode_limit(bytes, MAX_OBJECT_SIZE)
}
pub fn decode_limit(bytes: &[u8], limit: usize) -> Result<Value, Error> {
    if bytes.len() > limit {
        return Err(Error::ObjectTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = from_reader(&mut cursor).map_err(|_| Error::InvalidPayload)?;
    if cursor.position() as usize != bytes.len() || encode_limit(&value, limit)? != bytes {
        return Err(Error::InvalidPayload);
    }
    Ok(value)
}
