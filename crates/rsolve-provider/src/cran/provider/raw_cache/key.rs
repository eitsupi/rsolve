use super::wire::hex;
use super::*;
use rsolve_core::RegistryId;
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Serialize)]
struct RawCacheKeyWire<'a> {
    format: &'static str,
    version: u32,
    registry_id: &'a str,
    endpoint: &'a str,
    representation: RawCacheRepresentation,
}

impl RawCacheKey {
    pub(crate) fn new(
        registry_id: &RegistryId,
        endpoint: &str,
        representation: RawCacheRepresentation,
    ) -> Result<Self, RawCacheError> {
        let endpoint = canonical_request_endpoint(endpoint)?;
        let registry_id = registry_id.to_string().into_boxed_str();
        let digest =
            canonical_key_digest(&registry_id, &endpoint, representation)?.into_boxed_str();
        Ok(Self {
            registry_id,
            endpoint,
            representation,
            digest,
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn representation(&self) -> RawCacheRepresentation {
        self.representation
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

pub(super) fn canonical_request_endpoint(input: &str) -> Result<Box<str>, RawCacheError> {
    let url = Url::parse(input.trim()).map_err(|error| {
        RawCacheError::Invalid(format!("invalid raw cache endpoint: {error}").into())
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RawCacheError::Invalid(
            "raw cache endpoint must be an HTTP(S) URL without userinfo, query, or fragment".into(),
        ));
    }
    Ok(url.to_string().into_boxed_str())
}

pub(super) fn is_canonical_endpoint(endpoint: &str) -> bool {
    canonical_request_endpoint(endpoint).is_ok_and(|canonical| canonical.as_ref() == endpoint)
}

pub(super) fn canonical_key_digest(
    registry_id: &str,
    endpoint: &str,
    representation: RawCacheRepresentation,
) -> Result<String, RawCacheError> {
    let wire = RawCacheKeyWire {
        format: RAW_KEY_FORMAT,
        version: 1,
        registry_id,
        endpoint,
        representation,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|error| {
        RawCacheError::Invalid(format!("unable to encode raw cache key: {error}").into())
    })?;
    Ok(hex(&Sha256::digest(bytes)))
}
