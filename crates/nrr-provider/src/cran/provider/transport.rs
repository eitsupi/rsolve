use std::error::Error;
use std::fmt;
use std::io::Read;
use std::rc::Rc;

/// A provider-local response used by both real and fixture transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
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
}

impl<T: Transport + ?Sized> Transport for Rc<T> {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.as_ref().get(url)
    }
}

pub(super) struct UreqTransport {
    pub(super) agent: ureq::Agent,
}

impl Transport for UreqTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        let response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| TransportError::new(format!("request failed: {error}")))?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let declared_size = body.content_length();
        if declared_size.is_some_and(|length| length > super::MAX_RESPONSE_BYTES) {
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
        if bytes.len() as u64 > super::MAX_RESPONSE_BYTES
            || declared_size.is_some_and(|length| length != bytes.len() as u64)
        {
            return Err(TransportError::new(format!(
                "response size exceeds declared or {}-byte limit",
                super::MAX_RESPONSE_BYTES
            )));
        }
        Ok(TransportResponse {
            status,
            body: bytes,
        })
    }
}
