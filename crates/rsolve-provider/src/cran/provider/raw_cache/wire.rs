use super::*;
pub(super) fn validate_header_string(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty()
        || value.trim() != value
        || value.len() > 8 * 1024
        || value.chars().any(char::is_control)
        || value.contains(['\r', '\n'])
    {
        return Err(RawCacheError::Invalid(
            "raw cache validator is invalid".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

pub(super) fn validate_cache_control(value: &CacheControlHeader) -> Result<(), RawCacheError> {
    if let CacheControlHeader::Valid(value) = value {
        validate_header_string(Some(value))?;
    }
    Ok(())
}

pub(super) fn validate_etag(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = validate_header_string(value)? else {
        return Ok(None);
    };
    let opaque = value.strip_prefix("W/").unwrap_or(&value);
    if !opaque.starts_with('"') || !opaque.ends_with('"') || opaque.len() < 2 {
        return Err(RawCacheError::Invalid("raw cache ETag is invalid".into()));
    }
    if !opaque[1..opaque.len() - 1]
        .bytes()
        .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte))
    {
        return Err(RawCacheError::Invalid("raw cache ETag is invalid".into()));
    }
    Ok(Some(value))
}

pub(super) fn validate_last_modified(value: Option<&str>) -> Result<Option<String>, RawCacheError> {
    let Some(value) = validate_header_string(value)? else {
        return Ok(None);
    };
    let parsed = jiff::civil::DateTime::strptime("%a, %d %b %Y %H:%M:%S GMT", &value)
        .map_err(|_| RawCacheError::Invalid("raw cache Last-Modified is invalid".into()))?;
    if parsed.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string() != value {
        return Err(RawCacheError::Invalid(
            "raw cache Last-Modified is not canonical IMF-fixdate".into(),
        ));
    }
    Ok(Some(value))
}

pub(super) fn parse_timestamp(value: &str) -> Result<jiff::Timestamp, RawCacheError> {
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(RawCacheError::Invalid(
            "raw cache timestamp is invalid".into(),
        ));
    }
    value.parse().map_err(|error| {
        RawCacheError::Invalid(format!("raw cache timestamp is invalid: {error}").into())
    })
}

pub(super) fn timestamp_string(timestamp: jiff::Timestamp) -> Result<String, RawCacheError> {
    let value = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    if value.len() != 20 || value.parse::<jiff::Timestamp>().is_err() {
        return Err(RawCacheError::Invalid(
            "raw cache timestamp cannot be represented canonically".into(),
        ));
    }
    Ok(value)
}

pub(super) fn parse_hex_32(value: &str) -> Result<[u8; 32], RawCacheError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RawCacheError::Invalid("raw cache digest is invalid".into()));
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Result<u8, RawCacheError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RawCacheError::Invalid("raw cache digest is invalid".into())),
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
