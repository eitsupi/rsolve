use std::error::Error;
use std::fmt;
use std::io::Read;
use std::rc::Rc;

use super::cache_policy::CacheControlHeader;

const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Request validators that may be sent to a server when revalidating a
/// previously observed representation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TransportValidators {
    pub(crate) if_none_match: Option<Box<str>>,
    pub(crate) if_modified_since: Option<Box<str>>,
}

impl TransportValidators {
    pub(crate) fn from_values(
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> Self {
        Self {
            if_none_match: validated_header_value(if_none_match),
            if_modified_since: validated_header_value(if_modified_since),
        }
    }
}

/// Response headers retained at the transport boundary.
///
/// Values are trimmed and bounded before they enter provider code. Invalid
/// header bytes are discarded, which is conservative for cache reuse.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TransportResponseHeaders {
    pub(crate) etag: Option<Box<str>>,
    pub(crate) last_modified: Option<Box<str>>,
    pub(crate) cache_control: CacheControlHeader,
}

impl TransportResponseHeaders {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn validators(&self) -> TransportValidators {
        TransportValidators {
            if_none_match: self.etag.clone(),
            if_modified_since: self.last_modified.clone(),
        }
    }
}

/// Extract response metadata from HeaderMap values without trusting duplicate
/// validators or dropping later Cache-Control directives.
fn extract_response_headers(
    etag_values: &[Option<&str>],
    last_modified_values: &[Option<&str>],
    cache_control_values: &[Option<&str>],
) -> TransportResponseHeaders {
    let etag = unique_validator(etag_values);
    let last_modified = unique_validator(last_modified_values);
    let cache_control = combined_cache_control(cache_control_values);
    TransportResponseHeaders {
        etag,
        last_modified,
        cache_control,
    }
}

fn unique_validator(values: &[Option<&str>]) -> Option<Box<str>> {
    (values.len() == 1)
        .then(|| validated_header_value(values[0]))
        .flatten()
}

fn combined_cache_control(values: &[Option<&str>]) -> CacheControlHeader {
    if values.is_empty() {
        return CacheControlHeader::Absent;
    }
    let mut combined = String::new();
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value else {
            return CacheControlHeader::Invalid;
        };
        if index > 0 {
            combined.push(',');
        }
        combined.push_str(value);
    }
    match validated_header_value(Some(&combined)) {
        Some(value) => CacheControlHeader::Valid(value),
        None => CacheControlHeader::Invalid,
    }
}

fn validated_header_value(value: Option<&str>) -> Option<Box<str>> {
    let value = value?;
    if value.contains(['\r', '\n']) {
        return None;
    }
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.into())
}

fn validate_response_body(
    status: u16,
    declared_size: Option<u64>,
    body: &[u8],
) -> Result<(), TransportError> {
    if status == 304 {
        return if body.is_empty() {
            Ok(())
        } else {
            Err(TransportError::new("304 response must not contain a body"))
        };
    }
    if body.len() as u64 > super::MAX_RESPONSE_BYTES
        || declared_size.is_some_and(|length| length != body.len() as u64)
    {
        return Err(TransportError::new(format!(
            "response size exceeds declared or {}-byte limit",
            super::MAX_RESPONSE_BYTES
        )));
    }
    Ok(())
}

/// A provider-local response used by both real and fixture transports.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: TransportResponseHeaders,
}

impl TransportResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: TransportResponseHeaders::default(),
        }
    }
}

/// A provider-local transport failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportError {
    pub diagnostic: Box<str>,
}

impl TransportError {
    pub(super) fn new(diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl Error for TransportError {}

/// The small synchronous seam used by the CRAN provider.
pub(crate) trait Transport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError>;

    /// Perform a request with optional HTTP validators. Implementations that
    /// only support unconditional requests retain the old behavior through
    /// this default method.
    fn get_with_validators(
        &self,
        url: &str,
        validators: &TransportValidators,
    ) -> Result<TransportResponse, TransportError> {
        let _ = validators;
        self.get(url)
    }
}

impl<T: Transport + ?Sized> Transport for Rc<T> {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.as_ref().get(url)
    }

    fn get_with_validators(
        &self,
        url: &str,
        validators: &TransportValidators,
    ) -> Result<TransportResponse, TransportError> {
        self.as_ref().get_with_validators(url, validators)
    }
}

pub(super) struct UreqTransport {
    pub(super) agent: ureq::Agent,
}

impl Transport for UreqTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.get_with_validators(url, &TransportValidators::default())
    }

    fn get_with_validators(
        &self,
        url: &str,
        validators: &TransportValidators,
    ) -> Result<TransportResponse, TransportError> {
        let mut request = self.agent.get(url);
        if let Some(value) = validators.if_none_match.as_deref() {
            request = request.header("If-None-Match", value);
        }
        if let Some(value) = validators.if_modified_since.as_deref() {
            request = request.header("If-Modified-Since", value);
        }
        let response = request
            .call()
            .map_err(|error| TransportError::new(format!("request failed: {error}")))?;
        let status = response.status().as_u16();
        let etag_values = response
            .headers()
            .get_all("ETag")
            .iter()
            .map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        let last_modified_values = response
            .headers()
            .get_all("Last-Modified")
            .iter()
            .map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        let cache_control_values = response
            .headers()
            .get_all("Cache-Control")
            .iter()
            .map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        let headers =
            extract_response_headers(&etag_values, &last_modified_values, &cache_control_values);
        let mut body = response.into_body();
        let declared_size = body.content_length();
        if status != 304 && declared_size.is_some_and(|length| length > super::MAX_RESPONSE_BYTES) {
            return Err(TransportError::new(format!(
                "response exceeds {}-byte limit",
                super::MAX_RESPONSE_BYTES
            )));
        }
        let mut bytes = Vec::new();
        body.as_reader()
            .take(super::MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| TransportError::new(format!("failed to read response: {error}")))?;
        validate_response_body(status, declared_size, &bytes)?;
        let mut result = TransportResponse::new(status, bytes);
        result.headers = headers;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_headers_are_bounded_and_project_validators() {
        let headers = extract_response_headers(
            &[Some("  \"tag-1\"  ")],
            &[Some("Wed, 21 Oct 2015 07:28:00 GMT")],
            &[Some("max-age=120")],
        );
        assert_eq!(headers.etag.as_deref(), Some("\"tag-1\""));
        assert_eq!(
            headers.cache_control,
            CacheControlHeader::Valid("max-age=120".into())
        );
        let validators = headers.validators();
        assert_eq!(validators.if_none_match.as_deref(), Some("\"tag-1\""));
        assert_eq!(
            validators.if_modified_since.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );

        let oversized = "x".repeat(MAX_HEADER_VALUE_BYTES + 1);
        let unsafe_headers = extract_response_headers(
            &[Some("etag\r\nforged: true")],
            &[Some(&oversized)],
            &[Some("no-cache\n")],
        );
        assert_eq!(unsafe_headers.etag, None);
        assert_eq!(unsafe_headers.last_modified, None);
        assert_eq!(unsafe_headers.cache_control, CacheControlHeader::Invalid);
    }

    #[test]
    fn conditional_not_modified_body_rule_ignores_virtual_content_length() {
        assert!(validate_response_body(304, Some(4096), &[]).is_ok());
        assert!(validate_response_body(304, None, b"unexpected").is_err());
        assert!(validate_response_body(200, Some(3), b"ok").is_err());
        assert!(validate_response_body(200, Some(2), b"ok").is_ok());
    }

    #[test]
    fn duplicate_validators_are_not_projected_and_cache_control_preserves_order() {
        let headers = extract_response_headers(
            &[Some("\"first\""), Some("\"second\"")],
            &[
                Some("Wed, 21 Oct 2015 07:28:00 GMT"),
                Some("Thu, 22 Oct 2015 07:28:00 GMT"),
            ],
            &[Some("max-age=120"), Some("no-cache")],
        );
        assert_eq!(headers.etag, None);
        assert_eq!(headers.last_modified, None);
        assert_eq!(
            headers.cache_control,
            CacheControlHeader::Valid("max-age=120,no-cache".into())
        );
        let validators = headers.validators();
        assert_eq!(validators.if_none_match, None);
        assert_eq!(validators.if_modified_since, None);
        assert_eq!(
            super::super::cache_policy::cache_control_policy(
                &headers.cache_control,
                std::time::Duration::from_secs(3600),
            ),
            super::super::cache_policy::CacheControlPolicy::Revalidate
        );
    }

    #[test]
    fn invalid_or_oversized_cache_control_is_marked_fail_closed() {
        let oversized = "x".repeat(MAX_HEADER_VALUE_BYTES + 1);
        for values in [&[None][..], &[Some(oversized.as_str())][..]] {
            let headers = extract_response_headers(&[], &[], values);
            assert_eq!(headers.cache_control, CacheControlHeader::Invalid);
        }
    }
}
