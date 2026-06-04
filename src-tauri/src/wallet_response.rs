use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bech32::ToBase32;
use secrecy::{ExposeSecret, Secret, SecretVec};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const DATA_DESCRIPTOR_KEY_HASH: [u8; 20] = [
    0x08, 0xa2, 0xeb, 0xb2, 0xc5, 0x5f, 0x83, 0xa8, 0xe2, 0xa4, 0x26, 0xa5, 0x33, 0x20, 0xed, 0x4d,
    0x42, 0x12, 0x4f, 0x4d,
];
const DATA_DESCRIPTOR_VERSION: u64 = 1;
const DATA_DESCRIPTOR_FLAGS_NONE: u64 = 0;
const APP_ENCRYPTION_FLAG_HAS_REQUEST_ID: u64 = 1;
const APP_ENCRYPTION_FLAG_HAS_EXTENDED_SPENDING_KEY: u64 = 2;
const EXTENDED_VIEWING_KEY_LEN: usize = 169;
const RESPONSE_ENCRYPTION_TTL_MS: u64 = 10 * 60 * 1000;
const PENDING_UNLOCK_TTL_MS: u64 = 10 * 60 * 1000;
const SAPLING_PAYMENT_ADDRESS_LEN: usize = 43;

#[derive(Default)]
pub struct ResponseEncryptionState {
    inner: Mutex<HashMap<String, ResponseDecryptKey>>,
}

#[derive(Default)]
pub struct PendingWalletUnlockState {
    inner: Mutex<HashMap<String, PendingWalletUnlockSession>>,
}

struct ResponseDecryptKey {
    address: String,
    created_at_ms: u64,
    incoming_viewing_key: Zeroizing<[u8; 32]>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareWalletResponseEncryptionOutput {
    pub encrypt_response_to_address: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub struct EncryptedWalletResponseInput {
    pub app_encryption_request_id: String,
    pub app_identity_i_address: String,
    pub chain: String,
    pub derivation_number: u64,
    pub device_id_hex: String,
    pub encrypted_data_hex: String,
    pub ephemeral_public_key_hex: String,
    pub expected_app_encryption_request_id: String,
    pub expected_app_encryption_request_id_hex: String,
    pub key_version: u64,
    pub response_encryption_key_id: String,
    pub wallet_signer_identity_i_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericWalletResponseInput {
    pub device_id_hex: String,
    pub response_base64_url: String,
    pub response_encryption_key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWalletUnlockSessionInput {
    #[serde(alias = "appEncryptionRequestID")]
    pub app_encryption_request_id: String,
    pub app_identity_i_address: String,
    pub chain: String,
    pub cloud_attestation_expires_at: u64,
    pub cloud_attestation_id: String,
    pub cloud_attestation_secret: String,
    pub derivation_number: u64,
    pub expires_at: u64,
    #[serde(alias = "appEncryptionRequestIDHex")]
    pub expected_app_encryption_request_id_hex: String,
    pub expected_signed_request_hash_hex: String,
    pub expected_unsigned_request_hash_hex: String,
    pub expected_wallet_signer_identity_i_address: Option<String>,
    pub key_version: u64,
    pub response_encryption_key_id: String,
    pub session_id: String,
    pub signer_base_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelWalletUnlockSessionInput {
    pub session_id: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PendingWalletUnlockSession {
    pub app_encryption_request_id: String,
    pub app_identity_i_address: String,
    pub chain: String,
    pub cloud_attestation_expires_at: u64,
    pub cloud_attestation_id: String,
    pub cloud_attestation_secret: Secret<String>,
    pub derivation_number: u64,
    pub expires_at: u64,
    pub expected_app_encryption_request_id_hex: String,
    pub expected_signed_request_hash_hex: String,
    pub expected_unsigned_request_hash_hex: String,
    pub expected_wallet_signer_identity_i_address: Option<String>,
    pub key_version: u64,
    pub response_encryption_key_id: String,
    pub session_id: String,
    pub signer_base_url: String,
}

pub struct DecryptedAppEncryptionResponse {
    pub app_encryption_address: String,
    pub incoming_viewing_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DecryptedAppEncryptionResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecryptedAppEncryptionResponse")
            .field("app_encryption_address", &self.app_encryption_address)
            .field("incoming_viewing_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum WalletResponseError {
    #[error("response encryption state lock poisoned")]
    LockPoisoned,
    #[error("pending wallet unlock state lock poisoned")]
    PendingSessionLockPoisoned,
    #[error("response encryption key was missing or already used")]
    MissingResponseEncryptionKey,
    #[error("wallet unlock session was missing or already consumed")]
    MissingPendingUnlockSession,
    #[error("wallet unlock session expired")]
    PendingUnlockSessionExpired,
    #[error("wallet unlock session is already registered")]
    DuplicatePendingUnlockSession,
    #[error("wallet unlock session is missing required signer policy: {0}")]
    MissingSignerPolicy(&'static str),
    #[error("random generation failed: {0}")]
    Random(String),
    #[error("response encryption address generation failed: {0}")]
    AddressGeneration(String),
    #[error("wallet response decryption failed: {0}")]
    Decryption(String),
    #[error("invalid hex for {name}: {source}")]
    InvalidHex {
        name: &'static str,
        source: hex::FromHexError,
    },
    #[error("expected {name} to be {expected} bytes, got {actual}")]
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("app encryption requestID mismatch")]
    RequestIdMismatch,
    #[error("wallet response is missing requestID")]
    MissingRequestId,
    #[error("wallet response returned an extended spending key")]
    ExtendedSpendingKeyReturned,
    #[error("wallet response contains unsupported app-encryption flags: {0}")]
    UnsupportedAppEncryptionFlags(u64),
    #[error("wallet response descriptor is malformed: {0}")]
    MalformedDescriptor(String),
    #[error("wallet response app-encryption details are malformed: {0}")]
    MalformedAppEncryptionDetails(String),
    #[error("sapling address encoding failed: {0}")]
    SaplingAddressEncoding(bech32::Error),
}

impl ResponseEncryptionState {
    fn insert(&self, key_id: String, key: ResponseDecryptKey) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        purge_expired_response_keys(&mut keys, now);
        keys.insert(key_id, key);
        Ok(())
    }

    pub fn ensure_fresh(&self, key_id: &str) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        purge_expired_response_keys(&mut keys, now);

        if keys.contains_key(key_id) {
            Ok(())
        } else {
            Err(WalletResponseError::MissingResponseEncryptionKey)
        }
    }

    fn remove(&self, key_id: &str) -> Result<ResponseDecryptKey, WalletResponseError> {
        let now = now_ms();
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        purge_expired_response_keys(&mut keys, now);

        keys.remove(key_id)
            .ok_or(WalletResponseError::MissingResponseEncryptionKey)
    }

    pub fn discard(&self, key_id: &str) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        purge_expired_response_keys(&mut keys, now);

        if let Some(mut key) = keys.remove(key_id) {
            key.incoming_viewing_key.zeroize();
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn purge_expired(&self) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        purge_expired_response_keys(&mut keys, now);
        Ok(())
    }

    pub fn clear(&self) -> Result<(), WalletResponseError> {
        let mut keys = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::LockPoisoned)?;
        for (_, mut key) in keys.drain() {
            key.incoming_viewing_key.zeroize();
        }
        Ok(())
    }
}

impl PendingWalletUnlockState {
    pub fn insert(
        &self,
        input: RegisterWalletUnlockSessionInput,
    ) -> Result<(), WalletResponseError> {
        let now = now_ms();
        if input.expires_at <= now {
            return Err(WalletResponseError::PendingUnlockSessionExpired);
        }
        if input.expires_at.saturating_sub(now) > PENDING_UNLOCK_TTL_MS {
            return Err(WalletResponseError::PendingUnlockSessionExpired);
        }
        if input
            .expected_app_encryption_request_id_hex
            .trim()
            .is_empty()
        {
            return Err(WalletResponseError::MissingSignerPolicy(
                "expected app-encryption requestID",
            ));
        }
        if input.expected_signed_request_hash_hex.trim().is_empty() {
            return Err(WalletResponseError::MissingSignerPolicy(
                "signed request hash",
            ));
        }
        if input.expected_unsigned_request_hash_hex.trim().is_empty() {
            return Err(WalletResponseError::MissingSignerPolicy(
                "unsigned request hash",
            ));
        }
        if input.cloud_attestation_id.trim().is_empty() {
            return Err(WalletResponseError::MissingSignerPolicy(
                "cloud attestation ID",
            ));
        }
        if input.cloud_attestation_secret.trim().is_empty() {
            return Err(WalletResponseError::MissingSignerPolicy(
                "cloud attestation secret",
            ));
        }
        if input.cloud_attestation_expires_at <= now
            || input.cloud_attestation_expires_at > input.expires_at
        {
            return Err(WalletResponseError::PendingUnlockSessionExpired);
        }

        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions(&mut sessions, now);
        if sessions.contains_key(&input.response_encryption_key_id)
            || sessions
                .values()
                .any(|session| session.session_id == input.session_id)
        {
            return Err(WalletResponseError::DuplicatePendingUnlockSession);
        }

        sessions.insert(
            input.response_encryption_key_id.clone(),
            PendingWalletUnlockSession {
                app_encryption_request_id: input.app_encryption_request_id,
                app_identity_i_address: input.app_identity_i_address,
                chain: input.chain,
                cloud_attestation_expires_at: input.cloud_attestation_expires_at,
                cloud_attestation_id: input.cloud_attestation_id,
                cloud_attestation_secret: Secret::new(input.cloud_attestation_secret),
                derivation_number: input.derivation_number,
                expires_at: input.expires_at,
                expected_app_encryption_request_id_hex: input
                    .expected_app_encryption_request_id_hex,
                expected_signed_request_hash_hex: input.expected_signed_request_hash_hex,
                expected_unsigned_request_hash_hex: input.expected_unsigned_request_hash_hex,
                expected_wallet_signer_identity_i_address: input
                    .expected_wallet_signer_identity_i_address,
                key_version: input.key_version,
                response_encryption_key_id: input.response_encryption_key_id,
                session_id: input.session_id,
                signer_base_url: input.signer_base_url,
            },
        );

        Ok(())
    }

    pub fn get_fresh_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<PendingWalletUnlockSession, WalletResponseError> {
        let now = now_ms();
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions(&mut sessions, now);

        let Some(session) = sessions
            .values()
            .find(|session| session.session_id == session_id)
            .cloned()
        else {
            return Err(WalletResponseError::MissingPendingUnlockSession);
        };

        Ok(session)
    }

    pub fn discard_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, WalletResponseError> {
        let now = now_ms();
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions(&mut sessions, now);

        let Some(key_id) = sessions.iter().find_map(|(key_id, session)| {
            (session.session_id == session_id).then(|| key_id.clone())
        }) else {
            return Ok(None);
        };
        sessions.remove(&key_id);
        Ok(Some(key_id))
    }

    pub fn get_fresh(
        &self,
        response_encryption_key_id: &str,
    ) -> Result<PendingWalletUnlockSession, WalletResponseError> {
        let now = now_ms();
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions_except(&mut sessions, now, response_encryption_key_id);

        let Some(session) = sessions.get(response_encryption_key_id) else {
            return Err(WalletResponseError::MissingPendingUnlockSession);
        };

        if session.expires_at <= now {
            sessions.remove(response_encryption_key_id);
            return Err(WalletResponseError::PendingUnlockSessionExpired);
        }

        Ok(session.clone())
    }

    pub fn discard(&self, response_encryption_key_id: &str) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions(&mut sessions, now);
        sessions.remove(response_encryption_key_id);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn purge_expired(&self) -> Result<(), WalletResponseError> {
        let now = now_ms();
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?;
        purge_expired_pending_sessions(&mut sessions, now);
        Ok(())
    }

    pub fn clear(&self) -> Result<(), WalletResponseError> {
        self.inner
            .lock()
            .map_err(|_| WalletResponseError::PendingSessionLockPoisoned)?
            .clear();
        Ok(())
    }
}

pub fn prepare_response_encryption(
    state: &ResponseEncryptionState,
) -> Result<PrepareWalletResponseEncryptionOutput, WalletResponseError> {
    let mut seed_bytes = [0u8; 32];
    getrandom::fill(&mut seed_bytes)
        .map_err(|error| WalletResponseError::Random(error.to_string()))?;
    let seed = SecretVec::new(seed_bytes.to_vec());
    seed_bytes.zeroize();

    let channel_keys =
        verus_zfunc::z_getencryptionaddress(Some(&seed), None, Some(0), 0, None, None, false)
            .map_err(|error| WalletResponseError::AddressGeneration(error.to_string()))?;

    let mut key_id_bytes = [0u8; 16];
    getrandom::fill(&mut key_id_bytes)
        .map_err(|error| WalletResponseError::Random(error.to_string()))?;
    let key_id = URL_SAFE_NO_PAD.encode(key_id_bytes);
    key_id_bytes.zeroize();

    let key = ResponseDecryptKey {
        address: channel_keys.address.clone(),
        created_at_ms: now_ms(),
        incoming_viewing_key: Zeroizing::new(*channel_keys.ivk_bytes.expose_secret()),
    };
    state.insert(key_id.clone(), key)?;

    Ok(PrepareWalletResponseEncryptionOutput {
        encrypt_response_to_address: channel_keys.address,
        key_id,
    })
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn decrypt_encrypted_app_response(
    input: &EncryptedWalletResponseInput,
    state: &ResponseEncryptionState,
) -> Result<DecryptedAppEncryptionResponse, WalletResponseError> {
    if input.app_encryption_request_id != input.expected_app_encryption_request_id {
        return Err(WalletResponseError::RequestIdMismatch);
    }

    let mut response_key = state.remove(&input.response_encryption_key_id)?;
    let _response_key_age_ms = now_ms().saturating_sub(response_key.created_at_ms);
    let _response_address = &response_key.address;
    let ephemeral_public_key =
        decode_fixed_hex::<32>("ephemeral public key", &input.ephemeral_public_key_hex)?;
    let encrypted_data = decode_hex("encrypted wallet response", &input.encrypted_data_hex)?;
    let expected_request_id = decode_hex(
        "expected app encryption requestID",
        &input.expected_app_encryption_request_id_hex,
    )?;

    let ivk = Secret::new(*response_key.incoming_viewing_key);
    response_key.incoming_viewing_key.zeroize();
    let encrypted_secret = SecretVec::new(encrypted_data);
    let decrypted = verus_zfunc::decrypt_data(
        Some(&ivk),
        Some(&ephemeral_public_key),
        &encrypted_secret,
        None,
    )
    .map_err(|error| WalletResponseError::Decryption(error.to_string()))?;
    let decrypted_bytes = decrypted.expose_secret();
    let app_response_bytes = parse_mobile_encrypted_descriptor(decrypted_bytes)?;
    let parsed_response =
        parse_app_encryption_response(app_response_bytes.as_slice(), &expected_request_id)?;

    Ok(parsed_response)
}

pub fn decrypt_verified_app_response(
    response_encryption_key_id: &str,
    encrypted_data: Vec<u8>,
    ephemeral_public_key: [u8; 32],
    expected_app_encryption_request_id_hex: &str,
    state: &ResponseEncryptionState,
) -> Result<DecryptedAppEncryptionResponse, WalletResponseError> {
    let mut response_key = state.remove(response_encryption_key_id)?;
    let expected_request_id = decode_hex(
        "expected app encryption requestID",
        expected_app_encryption_request_id_hex,
    )?;
    let _response_address = &response_key.address;

    let ivk = Secret::new(*response_key.incoming_viewing_key);
    response_key.incoming_viewing_key.zeroize();
    let encrypted_secret = SecretVec::new(encrypted_data);
    let decrypted = verus_zfunc::decrypt_data(
        Some(&ivk),
        Some(&ephemeral_public_key),
        &encrypted_secret,
        None,
    )
    .map_err(|error| WalletResponseError::Decryption(error.to_string()))?;
    let decrypted_bytes = decrypted.expose_secret();
    let app_response_bytes = parse_mobile_encrypted_descriptor(decrypted_bytes)?;
    parse_app_encryption_response(app_response_bytes.as_slice(), &expected_request_id)
}

fn parse_mobile_encrypted_descriptor(
    decrypted_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WalletResponseError> {
    let mut reader = BinaryReader::new(decrypted_bytes);
    let key = reader
        .read_fixed::<20>()
        .map_err(WalletResponseError::MalformedDescriptor)?;

    if key != DATA_DESCRIPTOR_KEY_HASH {
        return Err(WalletResponseError::MalformedDescriptor(
            "unexpected VDXF data descriptor key".to_string(),
        ));
    }

    let version = reader
        .read_varint()
        .map_err(WalletResponseError::MalformedDescriptor)?;
    if version != DATA_DESCRIPTOR_VERSION {
        return Err(WalletResponseError::MalformedDescriptor(format!(
            "unsupported VDXF data descriptor version {version}"
        )));
    }

    let descriptor_len = reader
        .read_compact_size()
        .map_err(WalletResponseError::MalformedDescriptor)?;
    let descriptor_bytes = reader
        .read_slice(descriptor_len)
        .map_err(WalletResponseError::MalformedDescriptor)?;

    if !reader.is_finished() {
        return Err(WalletResponseError::MalformedDescriptor(
            "unexpected trailing VDXF data".to_string(),
        ));
    }

    parse_plain_data_descriptor(descriptor_bytes)
}

fn parse_plain_data_descriptor(
    descriptor_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WalletResponseError> {
    let mut reader = BinaryReader::new(descriptor_bytes);
    let version = reader
        .read_varint()
        .map_err(WalletResponseError::MalformedDescriptor)?;
    if version != DATA_DESCRIPTOR_VERSION {
        return Err(WalletResponseError::MalformedDescriptor(format!(
            "unsupported inner data descriptor version {version}"
        )));
    }

    let flags = reader
        .read_varint()
        .map_err(WalletResponseError::MalformedDescriptor)?;
    if flags != DATA_DESCRIPTOR_FLAGS_NONE {
        return Err(WalletResponseError::MalformedDescriptor(format!(
            "unexpected inner data descriptor flags {flags}"
        )));
    }

    let objectdata_len = reader
        .read_compact_size()
        .map_err(WalletResponseError::MalformedDescriptor)?;
    let objectdata = Zeroizing::new(
        reader
            .read_slice(objectdata_len)
            .map_err(WalletResponseError::MalformedDescriptor)?
            .to_vec(),
    );

    if !reader.is_finished() {
        return Err(WalletResponseError::MalformedDescriptor(
            "unexpected trailing inner descriptor data".to_string(),
        ));
    }

    Ok(objectdata)
}

fn parse_app_encryption_response(
    response_bytes: &[u8],
    expected_request_id: &[u8],
) -> Result<DecryptedAppEncryptionResponse, WalletResponseError> {
    let mut reader = BinaryReader::new(response_bytes);
    let flags = reader
        .read_varint()
        .map_err(WalletResponseError::MalformedAppEncryptionDetails)?;
    let unsupported_flags = flags
        & !(APP_ENCRYPTION_FLAG_HAS_REQUEST_ID | APP_ENCRYPTION_FLAG_HAS_EXTENDED_SPENDING_KEY);
    if unsupported_flags != 0 {
        return Err(WalletResponseError::UnsupportedAppEncryptionFlags(flags));
    }

    if flags & APP_ENCRYPTION_FLAG_HAS_REQUEST_ID == 0 {
        return Err(WalletResponseError::MissingRequestId);
    }

    let request_id = reader
        .read_slice(expected_request_id.len())
        .map_err(WalletResponseError::MalformedAppEncryptionDetails)?;
    if request_id != expected_request_id {
        return Err(WalletResponseError::RequestIdMismatch);
    }

    if flags & APP_ENCRYPTION_FLAG_HAS_EXTENDED_SPENDING_KEY != 0 {
        return Err(WalletResponseError::ExtendedSpendingKeyReturned);
    }

    let incoming_viewing_key = reader
        .read_fixed::<32>()
        .map_err(WalletResponseError::MalformedAppEncryptionDetails)?;
    reader
        .read_slice(EXTENDED_VIEWING_KEY_LEN)
        .map_err(WalletResponseError::MalformedAppEncryptionDetails)?;
    let address_bytes = reader
        .read_fixed::<SAPLING_PAYMENT_ADDRESS_LEN>()
        .map_err(WalletResponseError::MalformedAppEncryptionDetails)?;

    if !reader.is_finished() {
        return Err(WalletResponseError::MalformedAppEncryptionDetails(
            "unexpected trailing app-encryption response data".to_string(),
        ));
    }

    Ok(DecryptedAppEncryptionResponse {
        app_encryption_address: encode_sapling_address(&address_bytes)?,
        incoming_viewing_key: Zeroizing::new(incoming_viewing_key),
    })
}

fn encode_sapling_address(
    bytes: &[u8; SAPLING_PAYMENT_ADDRESS_LEN],
) -> Result<String, WalletResponseError> {
    bech32::encode("zs", bytes.to_base32(), bech32::Variant::Bech32)
        .map_err(WalletResponseError::SaplingAddressEncoding)
}

fn decode_hex(name: &'static str, value: &str) -> Result<Vec<u8>, WalletResponseError> {
    hex::decode(value).map_err(|source| WalletResponseError::InvalidHex { name, source })
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
fn decode_fixed_hex<const N: usize>(
    name: &'static str,
    value: &str,
) -> Result<[u8; N], WalletResponseError> {
    let decoded = decode_hex(name, value)?;
    decoded
        .try_into()
        .map_err(|bytes: Vec<u8>| WalletResponseError::InvalidLength {
            name,
            expected: N,
            actual: bytes.len(),
        })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn purge_expired_response_keys(keys: &mut HashMap<String, ResponseDecryptKey>, now: u64) {
    keys.retain(|_, key| {
        let fresh = now.saturating_sub(key.created_at_ms) <= RESPONSE_ENCRYPTION_TTL_MS;
        if !fresh {
            key.incoming_viewing_key.zeroize();
        }
        fresh
    });
}

fn purge_expired_pending_sessions(
    sessions: &mut HashMap<String, PendingWalletUnlockSession>,
    now: u64,
) {
    sessions.retain(|_, session| session.expires_at > now);
}

fn purge_expired_pending_sessions_except(
    sessions: &mut HashMap<String, PendingWalletUnlockSession>,
    now: u64,
    except_key_id: &str,
) {
    sessions.retain(|key_id, session| key_id == except_key_id || session.expires_at > now);
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let slice = self.read_slice(N)?;
        slice.try_into().map_err(|_| format!("expected {N} bytes"))
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err(format!(
                "read beyond end: need {len} bytes at offset {}, total {}",
                self.offset,
                self.bytes.len()
            ));
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| "read beyond end".to_string())?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;

        for _ in 0..10 {
            let byte = self.read_byte()?;
            value = value
                .checked_shl(7)
                .ok_or_else(|| "varint overflow".to_string())?
                | u64::from(byte & 0x7f);

            if byte & 0x80 == 0 {
                return Ok(value);
            }

            value = value
                .checked_add(1)
                .ok_or_else(|| "varint overflow".to_string())?;
        }

        Err("varint too long".to_string())
    }

    fn read_compact_size(&mut self) -> Result<usize, String> {
        let first = self.read_byte()?;

        match first {
            0x00..=0xfc => Ok(first as usize),
            0xfd => {
                let raw = self.read_fixed::<2>()?;
                Ok(u16::from_le_bytes(raw) as usize)
            }
            0xfe => {
                let raw = self.read_fixed::<4>()?;
                Ok(u32::from_le_bytes(raw) as usize)
            }
            0xff => {
                let raw = self.read_fixed::<8>()?;
                let value = u64::from_le_bytes(raw);
                usize::try_from(value).map_err(|_| "compact size overflows usize".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_one_time_response_encryption_material() {
        let state = ResponseEncryptionState::default();
        let output = prepare_response_encryption(&state).unwrap();
        let stored = state.remove(&output.key_id).unwrap();

        assert!(output.encrypt_response_to_address.starts_with("zs1"));
        assert!(!output.key_id.is_empty());
        assert_eq!(stored.address, output.encrypt_response_to_address);
        assert_ne!(*stored.incoming_viewing_key, [0u8; 32]);
    }

    #[test]
    fn discards_one_time_response_encryption_material() {
        let state = ResponseEncryptionState::default();
        let output = prepare_response_encryption(&state).unwrap();

        state.discard(&output.key_id).unwrap();

        assert!(matches!(
            state.remove(&output.key_id),
            Err(WalletResponseError::MissingResponseEncryptionKey)
        ));
    }

    #[test]
    fn pending_wallet_unlock_sessions_are_one_time_and_expiring() {
        let state = PendingWalletUnlockState::default();
        let input = pending_session_input("key-1", now_ms() + 60_000);

        state.insert(input).unwrap();
        assert_eq!(
            state.get_fresh("key-1").unwrap().app_encryption_request_id,
            "request-1"
        );

        state.discard("key-1").unwrap();
        assert!(matches!(
            state.get_fresh("key-1"),
            Err(WalletResponseError::MissingPendingUnlockSession)
        ));
        assert!(matches!(
            state.insert(pending_session_input("key-2", now_ms())),
            Err(WalletResponseError::PendingUnlockSessionExpired)
        ));
    }

    #[test]
    fn pending_wallet_unlock_rejects_duplicate_session_ids() {
        let state = PendingWalletUnlockState::default();
        state
            .insert(pending_session_input("key-1", now_ms() + 60_000))
            .unwrap();

        assert!(matches!(
            state.insert(pending_session_input("key-2", now_ms() + 60_000)),
            Err(WalletResponseError::DuplicatePendingUnlockSession)
        ));
    }

    #[test]
    fn pending_wallet_unlock_rejects_missing_signer_policy() {
        let state = PendingWalletUnlockState::default();
        let mut input = pending_session_input("key-1", now_ms() + 60_000);
        input.expected_signed_request_hash_hex.clear();

        assert!(matches!(
            state.insert(input),
            Err(WalletResponseError::MissingSignerPolicy(
                "signed request hash"
            ))
        ));
    }

    #[test]
    fn pending_wallet_unlock_rejects_overlong_expiry() {
        let state = PendingWalletUnlockState::default();

        assert!(matches!(
            state.insert(pending_session_input(
                "key-1",
                now_ms() + 10 * 60 * 1000 + 1
            )),
            Err(WalletResponseError::PendingUnlockSessionExpired)
        ));
    }

    #[test]
    fn parses_mobile_data_descriptor_wrapper() {
        let wrapper =
            hex::decode("08a2ebb2c55f83a8e2a426a53320ed4d42124f4d0106010003010203").unwrap();

        let payload = parse_mobile_encrypted_descriptor(&wrapper).unwrap();

        assert_eq!(payload.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn parses_app_encryption_response_without_exported_spending_key() {
        let expected_request_id = hex::decode(
            "01012c76657275732d6e6f7465732d3030303030303030303030303030303030303030303030303030303030303030",
        )
        .unwrap();
        let mut response = vec![APP_ENCRYPTION_FLAG_HAS_REQUEST_ID as u8];
        response.extend_from_slice(&expected_request_id);
        response.extend_from_slice(&[7u8; 32]);
        response.extend_from_slice(&[9u8; EXTENDED_VIEWING_KEY_LEN]);
        response.extend_from_slice(&[10u8; SAPLING_PAYMENT_ADDRESS_LEN]);

        let parsed = parse_app_encryption_response(&response, &expected_request_id).unwrap();

        assert_eq!(*parsed.incoming_viewing_key, [7u8; 32]);
        assert!(parsed.app_encryption_address.starts_with("zs1"));
    }

    #[test]
    fn rejects_app_encryption_response_with_exported_spending_key() {
        let expected_request_id = hex::decode(
            "01012c76657275732d6e6f7465732d3030303030303030303030303030303030303030303030303030303030303030",
        )
        .unwrap();
        let mut response = vec![
            (APP_ENCRYPTION_FLAG_HAS_REQUEST_ID | APP_ENCRYPTION_FLAG_HAS_EXTENDED_SPENDING_KEY)
                as u8,
        ];
        response.extend_from_slice(&expected_request_id);

        let error = parse_app_encryption_response(&response, &expected_request_id).unwrap_err();

        assert!(matches!(
            error,
            WalletResponseError::ExtendedSpendingKeyReturned
        ));
    }

    fn pending_session_input(
        response_encryption_key_id: &str,
        expires_at: u64,
    ) -> RegisterWalletUnlockSessionInput {
        RegisterWalletUnlockSessionInput {
            app_encryption_request_id: "request-1".to_string(),
            app_identity_i_address: "i-app".to_string(),
            chain: "VRSCTEST".to_string(),
            cloud_attestation_expires_at: expires_at,
            cloud_attestation_id: "cloud-attestation-1".to_string(),
            cloud_attestation_secret: "cloud-attestation-secret-1".to_string(),
            derivation_number: 1,
            expires_at,
            expected_app_encryption_request_id_hex: "01".to_string(),
            expected_signed_request_hash_hex: "02".to_string(),
            expected_unsigned_request_hash_hex: "03".to_string(),
            expected_wallet_signer_identity_i_address: None,
            key_version: 1,
            response_encryption_key_id: response_encryption_key_id.to_string(),
            session_id: "session-1".to_string(),
            signer_base_url: "https://signer.example.test".to_string(),
        }
    }
}
