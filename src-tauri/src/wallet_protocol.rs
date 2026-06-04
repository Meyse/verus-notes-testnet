use std::error::Error as StdError;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, Secp256k1,
};
use serde::Deserialize;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

const COMPACT_ADDRESS_TYPE_FQN: u64 = 1;
const COMPACT_ADDRESS_TYPE_I_ADDRESS: u64 = 2;
const DATA_DESCRIPTOR_FLAG_ENCRYPTED_DATA: u64 = 1;
const DATA_DESCRIPTOR_FLAG_SALT_PRESENT: u64 = 2;
const DATA_DESCRIPTOR_FLAG_EPK_PRESENT: u64 = 4;
const DATA_DESCRIPTOR_FLAG_IVK_PRESENT: u64 = 8;
const DATA_DESCRIPTOR_FLAG_SSK_PRESENT: u64 = 0x10;
const DATA_DESCRIPTOR_FLAG_LABEL_PRESENT: u64 = 0x20;
const DATA_DESCRIPTOR_FLAG_MIME_PRESENT: u64 = 0x40;
const DATA_DESCRIPTOR_ORDINAL: u64 = 0;
const DATA_DESCRIPTOR_VERSION: u64 = 1;
const ENVELOPE_FLAG_SIGNED: u64 = 1;
const ENVELOPE_FLAG_HAS_REQUEST_ID: u64 = 2;
const ENVELOPE_FLAG_HAS_CREATED_AT: u64 = 4;
const ENVELOPE_FLAG_MULTI_DETAILS: u64 = 8;
const ENVELOPE_FLAG_HAS_SALT: u64 = 32;
const ENVELOPE_FLAG_HAS_APP_OR_DELEGATED_ID: u64 = 64;
const GENERIC_RESPONSE_FLAG_HAS_REQUEST_HASH: u64 = 128;
const GENERIC_RESPONSE_FLAG_HAS_HANDLED_BY: u64 = 256;
const HASH_TYPE_SHA256: u64 = 5;
const IDENTITY_SIGNATURE_VERSION: u8 = 2;
const I_ADDRESS_VERSION: u8 = 102;
const APP_ENCRYPTION_RESPONSE_ORDINAL: u64 = 8;
const SIGNATURE_FLAG_HAS_VDXF_KEYS: u64 = 1;
const SIGNATURE_FLAG_HAS_VDXF_KEY_NAMES: u64 = 2;
const SIGNATURE_FLAG_HAS_BOUND_HASHES: u64 = 4;
const SIGNATURE_FLAG_HAS_STATEMENTS: u64 = 8;
const SIGNATURE_FLAG_HAS_SYSTEM: u64 = 16;
const SIGNATURE_TIME_THRESHOLD_SECS: i64 = 3600;
const TESTNET_CHAIN_ID: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const VERUS_DATA_SIGNATURE_PREFIX: &[u8] = b"\x13Verus signed data:\n";
const VERUS_PUBKEY_HASH_VERSION: u8 = 0x3c;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BASE64URL_CHARS: usize = ((MAX_RESPONSE_BYTES + 2) / 3) * 4;
const MAX_DETAIL_COUNT: usize = 16;
const MAX_SIGNATURE_COUNT: usize = 16;
const MAX_VECTOR_COUNT: usize = 32;
const MAX_VECTOR_ITEM_BYTES: usize = 4 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 256 * 1024;
const MAX_ENCRYPTED_DATA_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct VerifiedWalletResponse {
    pub encrypted_data: Vec<u8>,
    pub ephemeral_public_key: [u8; 32],
    pub wallet_signer_identity_i_address: String,
    pub wallet_signer_identity_name: Option<String>,
}

#[derive(Debug)]
pub struct VerifyWalletResponseInput {
    pub allow_missing_request_hash: bool,
    pub chain: String,
    pub expected_signed_request_hash_hex: Option<String>,
    pub expected_unsigned_request_hash_hex: Option<String>,
    pub expected_wallet_signer_identity_i_address: Option<String>,
    pub response_base64_url: String,
}

#[derive(Debug, Error)]
pub enum WalletProtocolError {
    #[error("wallet response is not valid base64url: {0}")]
    InvalidBase64(base64::DecodeError),
    #[error("wallet response is too large: {actual} bytes exceeds {max} bytes")]
    ResponseTooLarge { actual: usize, max: usize },
    #[error("wallet response is malformed: {0}")]
    Malformed(String),
    #[error("wallet response has too many details: {actual} exceeds {max}")]
    TooManyDetails { actual: usize, max: usize },
    #[error("wallet response has too many signatures: {actual} exceeds {max}")]
    TooManySignatures { actual: usize, max: usize },
    #[error("wallet response vector has too many items: {actual} exceeds {max}")]
    TooManyVectorItems { actual: usize, max: usize },
    #[error("wallet response vector item is too large: {actual} bytes exceeds {max} bytes")]
    VectorItemTooLarge { actual: usize, max: usize },
    #[error("wallet response must be signed")]
    UnsignedResponse,
    #[error("wallet response is missing signature identityID")]
    MissingSignatureIdentity,
    #[error("wallet response signature uses unsupported features")]
    UnsupportedSignatureFeatures,
    #[error("wallet response signature uses unsupported hash type {0}")]
    UnsupportedHashType(u64),
    #[error("wallet response signature is invalid")]
    InvalidSignature,
    #[error("wallet response signer identity mismatch")]
    SignerIdentityMismatch,
    #[error("wallet response was signed by an inactive identity")]
    InactiveIdentity,
    #[error("wallet response signer identity has no primary addresses")]
    MissingPrimaryAddresses,
    #[error("wallet response signer identity minimum signatures were not satisfied")]
    InsufficientSignatures,
    #[error("wallet response createdAt is missing")]
    MissingCreatedAt,
    #[error("wallet response createdAt differs from signature block time by more than one hour")]
    StaleCreatedAt,
    #[error("wallet response chain mismatch")]
    ChainMismatch,
    #[error("wallet response request hash mismatch")]
    RequestHashMismatch,
    #[error("wallet response is missing request hash")]
    MissingRequestHash,
    #[error("wallet response included a request hash but no expected request hash was provided")]
    UnexpectedRequestHash,
    #[error("wallet response returned plaintext app-encryption details")]
    PlaintextAppEncryptionResponse,
    #[error("wallet response is missing encrypted app-encryption data")]
    MissingEncryptedAppEncryptionResponse,
    #[error("wallet response has duplicate encrypted app-encryption descriptors")]
    DuplicateEncryptedAppEncryptionDescriptor,
    #[error("wallet response encrypted data descriptor is too large: {actual} bytes exceeds {max} bytes")]
    DescriptorTooLarge { actual: usize, max: usize },
    #[error("wallet response encrypted app-encryption data is too large: {actual} bytes exceeds {max} bytes")]
    EncryptedDataTooLarge { actual: usize, max: usize },
    #[error("wallet response encrypted data descriptor includes forbidden key material: {0}")]
    MalformedForbiddenDescriptor(String),
    #[error("wallet response encrypted data descriptor is malformed: {0}")]
    MalformedEncryptedDescriptor(String),
    #[error("VERUS_API_BASE_URL must be configured at build time")]
    MissingVerusApiBaseUrl,
    #[error("Verus API request failed: {0}")]
    PublicData(String),
}

pub fn verify_wallet_generic_response(
    input: &VerifyWalletResponseInput,
) -> Result<VerifiedWalletResponse, WalletProtocolError> {
    let expected_chain = ExpectedChain::from_name(&input.chain)?;
    if input.response_base64_url.len() > MAX_RESPONSE_BASE64URL_CHARS {
        return Err(WalletProtocolError::ResponseTooLarge {
            actual: input.response_base64_url.len(),
            max: MAX_RESPONSE_BASE64URL_CHARS,
        });
    }

    let response_bytes = URL_SAFE_NO_PAD
        .decode(input.response_base64_url.as_bytes())
        .map_err(WalletProtocolError::InvalidBase64)?;
    if response_bytes.len() > MAX_RESPONSE_BYTES {
        return Err(WalletProtocolError::ResponseTooLarge {
            actual: response_bytes.len(),
            max: MAX_RESPONSE_BYTES,
        });
    }

    let response = GenericResponse::parse(&response_bytes, expected_chain)?;
    verify_response_policy(&response, input, expected_chain)?;

    let signature = response
        .signature
        .as_ref()
        .ok_or(WalletProtocolError::UnsignedResponse)?;
    let signer_identity = signature
        .identity_id
        .i_address()
        .ok_or(WalletProtocolError::MissingSignatureIdentity)?;

    if let Some(expected_signer) = &input.expected_wallet_signer_identity_i_address {
        if expected_signer != &signer_identity {
            return Err(WalletProtocolError::SignerIdentityMismatch);
        }
    }

    let identity_signature = IdentitySignature::parse(&signature.signature_as_vch)?;
    let public_data = VerusRpcPublicData::new(expected_chain.api_base_url()?)?;
    let identity =
        public_data.get_identity_at_height(&signer_identity, identity_signature.height)?;
    if identity.identity.identityaddress != signer_identity {
        return Err(WalletProtocolError::SignerIdentityMismatch);
    }
    let block_time = public_data.get_block_time(identity_signature.height)?;
    verify_created_at(response.created_at, block_time)?;

    let signature_hash = response.details_identity_signature_hash(identity_signature.height)?;
    verify_identity_signature(&identity_signature, &signature_hash, &identity)?;

    let descriptor = response.encrypted_app_encryption_descriptor()?;

    Ok(VerifiedWalletResponse {
        encrypted_data: descriptor.encrypted_data,
        ephemeral_public_key: descriptor.ephemeral_public_key,
        wallet_signer_identity_i_address: signer_identity,
        wallet_signer_identity_name: identity.display_name(),
    })
}

fn verify_response_policy(
    response: &GenericResponse,
    input: &VerifyWalletResponseInput,
    expected_chain: ExpectedChain,
) -> Result<(), WalletProtocolError> {
    if response.signature.is_none() {
        return Err(WalletProtocolError::UnsignedResponse);
    }

    let signature = response
        .signature
        .as_ref()
        .ok_or(WalletProtocolError::UnsignedResponse)?;
    let system_address = signature
        .system_id
        .i_address()
        .ok_or(WalletProtocolError::ChainMismatch)?;
    if system_address != expected_chain.chain_id {
        return Err(WalletProtocolError::ChainMismatch);
    }

    if response.has_plaintext_app_encryption_response() {
        return Err(WalletProtocolError::PlaintextAppEncryptionResponse);
    }

    let expects_request_hash = input.expected_signed_request_hash_hex.is_some()
        || input.expected_unsigned_request_hash_hex.is_some();

    if let Some(request_hash) = &response.request_hash {
        if request_hash.hash_type != HASH_TYPE_SHA256 {
            return Err(WalletProtocolError::UnsupportedHashType(
                request_hash.hash_type,
            ));
        }

        let request_hash_hex = hex::encode(&request_hash.hash);
        let matches_signed = input
            .expected_signed_request_hash_hex
            .as_deref()
            .is_some_and(|expected| expected.eq_ignore_ascii_case(&request_hash_hex));
        let matches_unsigned = input
            .expected_unsigned_request_hash_hex
            .as_deref()
            .is_some_and(|expected| expected.eq_ignore_ascii_case(&request_hash_hex));

        if !matches_signed && !matches_unsigned {
            if input.expected_signed_request_hash_hex.is_none()
                && input.expected_unsigned_request_hash_hex.is_none()
            {
                return Err(WalletProtocolError::UnexpectedRequestHash);
            }
            return Err(WalletProtocolError::RequestHashMismatch);
        }
    } else if expects_request_hash && !input.allow_missing_request_hash {
        return Err(WalletProtocolError::MissingRequestHash);
    }

    Ok(())
}

fn verify_created_at(created_at: Option<i64>, block_time: i64) -> Result<(), WalletProtocolError> {
    let created_at = created_at.ok_or(WalletProtocolError::MissingCreatedAt)?;
    if block_time.saturating_sub(created_at).abs() > SIGNATURE_TIME_THRESHOLD_SECS {
        return Err(WalletProtocolError::StaleCreatedAt);
    }

    Ok(())
}

fn verify_identity_signature(
    identity_signature: &IdentitySignature,
    signature_hash: &[u8; 32],
    identity: &IdentityResult,
) -> Result<(), WalletProtocolError> {
    if identity.status.as_deref() != Some("active") {
        return Err(WalletProtocolError::InactiveIdentity);
    }

    if identity.identity.primaryaddresses.is_empty() {
        return Err(WalletProtocolError::MissingPrimaryAddresses);
    }

    let minimum_signatures = identity.identity.minimumsignatures.max(1) as usize;
    let mut signed_by = Vec::<String>::new();

    for primary_address in &identity.identity.primaryaddresses {
        if signed_by.iter().any(|address| address == primary_address) {
            continue;
        }

        if identity_signature.verify_for_address(signature_hash, primary_address)? {
            signed_by.push(primary_address.clone());
        }

        if signed_by.len() >= minimum_signatures {
            return Ok(());
        }
    }

    Err(WalletProtocolError::InsufficientSignatures)
}

#[derive(Debug, Clone, Copy)]
struct ExpectedChain {
    chain_id: &'static str,
}

impl ExpectedChain {
    fn from_name(name: &str) -> Result<Self, WalletProtocolError> {
        match name {
            "VRSCTEST" => Ok(Self {
                chain_id: TESTNET_CHAIN_ID,
            }),
            _ => Err(WalletProtocolError::ChainMismatch),
        }
    }

    fn api_base_url(self) -> Result<&'static str, WalletProtocolError> {
        match option_env!("VERUS_API_BASE_URL") {
            Some(value) if !value.trim().is_empty() => Ok(value),
            _ => Err(WalletProtocolError::MissingVerusApiBaseUrl),
        }
    }
}

#[derive(Debug)]
struct GenericResponse {
    app_or_delegated_id_raw: Option<Vec<u8>>,
    created_at: Option<i64>,
    flags: u64,
    handled_by: Option<u64>,
    request_id_raw: Option<Vec<u8>>,
    request_hash: Option<ResponseRequestHash>,
    salt: Option<Vec<u8>>,
    signature: Option<VerifiableSignatureData>,
    details: Vec<OrdinalDetail>,
}

impl GenericResponse {
    fn parse(bytes: &[u8], expected_chain: ExpectedChain) -> Result<Self, WalletProtocolError> {
        let mut reader = BinaryReader::new(bytes);
        let version = reader.read_compact_size_u64()?;
        if version != 1 {
            return Err(WalletProtocolError::Malformed(format!(
                "unsupported response version {version}"
            )));
        }

        let flags = reader.read_compact_size_u64()?;
        let signature = if flags & ENVELOPE_FLAG_SIGNED != 0 {
            Some(VerifiableSignatureData::parse(&mut reader, expected_chain)?)
        } else {
            None
        };

        let request_id_raw = if flags & ENVELOPE_FLAG_HAS_REQUEST_ID != 0 {
            Some(read_compact_address_raw(&mut reader)?)
        } else {
            None
        };

        let created_at = if flags & ENVELOPE_FLAG_HAS_CREATED_AT != 0 {
            Some(reader.read_compact_size_u64()? as i64)
        } else {
            None
        };

        let salt = if flags & ENVELOPE_FLAG_HAS_SALT != 0 {
            Some(read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?.to_vec())
        } else {
            None
        };

        let app_or_delegated_id_raw = if flags & ENVELOPE_FLAG_HAS_APP_OR_DELEGATED_ID != 0 {
            Some(read_compact_address_raw(&mut reader)?)
        } else {
            None
        };

        let details = parse_details(&mut reader, flags)?;
        let request_hash = if flags & GENERIC_RESPONSE_FLAG_HAS_REQUEST_HASH != 0 {
            Some(ResponseRequestHash {
                hash_type: reader.read_compact_size_u64()?,
                hash: read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?.to_vec(),
            })
        } else {
            None
        };
        let handled_by = if flags & GENERIC_RESPONSE_FLAG_HAS_HANDLED_BY != 0 {
            Some(reader.read_compact_size_u64()?)
        } else {
            None
        };

        if !reader.is_finished() {
            return Err(WalletProtocolError::Malformed(
                "unexpected trailing response bytes".to_string(),
            ));
        }

        Ok(Self {
            app_or_delegated_id_raw,
            created_at,
            flags,
            handled_by,
            request_id_raw,
            request_hash,
            salt,
            signature,
            details,
        })
    }

    fn has_plaintext_app_encryption_response(&self) -> bool {
        self.details
            .iter()
            .any(|detail| detail.ordinal == APP_ENCRYPTION_RESPONSE_ORDINAL)
    }

    fn encrypted_app_encryption_descriptor(
        &self,
    ) -> Result<EncryptedDescriptor, WalletProtocolError> {
        let mut descriptor = None;

        for detail in &self.details {
            if detail.ordinal != DATA_DESCRIPTOR_ORDINAL {
                continue;
            }

            if descriptor.is_some() {
                return Err(WalletProtocolError::DuplicateEncryptedAppEncryptionDescriptor);
            }

            descriptor = Some(parse_encrypted_data_descriptor(&detail.data)?);
        }

        descriptor.ok_or(WalletProtocolError::MissingEncryptedAppEncryptionResponse)
    }

    fn details_identity_signature_hash(
        &self,
        height: u32,
    ) -> Result<[u8; 32], WalletProtocolError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or(WalletProtocolError::UnsignedResponse)?;
        signature.identity_hash(height, &self.raw_data_sha256(false)?)
    }

    fn raw_data_sha256(&self, include_signature: bool) -> Result<[u8; 32], WalletProtocolError> {
        let mut buffer = Vec::new();
        write_compact_size(&mut buffer, 1);
        write_compact_size(&mut buffer, self.flags);

        if include_signature && self.flags & ENVELOPE_FLAG_SIGNED != 0 {
            let signature = self
                .signature
                .as_ref()
                .ok_or(WalletProtocolError::UnsignedResponse)?;
            signature.write_to_buffer(&mut buffer, true)?;
        }

        if let Some(request_id_raw) = &self.request_id_raw {
            buffer.extend_from_slice(request_id_raw);
        }

        if let Some(created_at) = self.created_at {
            write_compact_size(&mut buffer, created_at as u64);
        }

        if let Some(salt) = &self.salt {
            write_var_slice(&mut buffer, salt);
        }

        if let Some(app_or_delegated_id_raw) = &self.app_or_delegated_id_raw {
            buffer.extend_from_slice(app_or_delegated_id_raw);
        }

        if self.flags & ENVELOPE_FLAG_MULTI_DETAILS != 0 {
            write_compact_size(&mut buffer, self.details.len() as u64);
        }
        for detail in &self.details {
            buffer.extend_from_slice(&detail.raw);
        }

        if let Some(request_hash) = &self.request_hash {
            write_compact_size(&mut buffer, request_hash.hash_type);
            write_var_slice(&mut buffer, &request_hash.hash);
        }

        if let Some(handled_by) = self.handled_by {
            write_compact_size(&mut buffer, handled_by);
        }

        Ok(Sha256::digest(&buffer).into())
    }
}

#[derive(Debug)]
struct ResponseRequestHash {
    hash_type: u64,
    hash: Vec<u8>,
}

#[derive(Debug)]
struct VerifiableSignatureData {
    bound_hashes_raw: Vec<Vec<u8>>,
    flags: u64,
    hash_type: u64,
    identity_id: CompactAddress,
    signature_as_vch: Vec<u8>,
    signature_version: u64,
    statements_raw: Vec<Vec<u8>>,
    system_id: CompactAddress,
    vdxf_key_names_raw: Vec<Vec<u8>>,
    vdxf_keys_raw: Vec<[u8; 20]>,
    version: u64,
}

impl VerifiableSignatureData {
    fn parse(
        reader: &mut BinaryReader<'_>,
        expected_chain: ExpectedChain,
    ) -> Result<Self, WalletProtocolError> {
        let version = reader.read_varint()?;
        let flags = reader.read_compact_size_u64()?;
        let signature_version = reader.read_compact_size_u64()?;
        let hash_type = reader.read_compact_size_u64()?;
        if hash_type != HASH_TYPE_SHA256 {
            return Err(WalletProtocolError::UnsupportedHashType(hash_type));
        }

        let system_id = if flags & SIGNATURE_FLAG_HAS_SYSTEM != 0 {
            CompactAddress::parse(reader)?
        } else {
            CompactAddress::from_i_address(expected_chain.chain_id)?
        };
        let identity_id = CompactAddress::parse(reader)?;

        let vdxf_keys_raw = if flags & SIGNATURE_FLAG_HAS_VDXF_KEYS != 0 {
            let count = reader.read_compact_size()?;
            if count > MAX_VECTOR_COUNT {
                return Err(WalletProtocolError::TooManyVectorItems {
                    actual: count,
                    max: MAX_VECTOR_COUNT,
                });
            }

            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                keys.push(reader.read_fixed::<20>()?);
            }
            keys
        } else {
            Vec::new()
        };

        let vdxf_key_names_raw = if flags & SIGNATURE_FLAG_HAS_VDXF_KEY_NAMES != 0 {
            read_vector(reader)?
        } else {
            Vec::new()
        };
        let bound_hashes_raw = if flags & SIGNATURE_FLAG_HAS_BOUND_HASHES != 0 {
            read_vector(reader)?
        } else {
            Vec::new()
        };
        let statements_raw = if flags & SIGNATURE_FLAG_HAS_STATEMENTS != 0 {
            read_vector(reader)?
        } else {
            Vec::new()
        };
        let signature_as_vch = read_bounded_var_slice(reader, MAX_VECTOR_ITEM_BYTES)?.to_vec();

        Ok(Self {
            bound_hashes_raw,
            flags,
            hash_type,
            identity_id,
            signature_as_vch,
            signature_version,
            statements_raw,
            system_id,
            vdxf_key_names_raw,
            vdxf_keys_raw,
            version,
        })
    }

    fn write_to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        for_hashing: bool,
    ) -> Result<(), WalletProtocolError> {
        write_varint(buffer, self.version)?;
        write_compact_size(buffer, self.flags);
        write_compact_size(buffer, self.signature_version);
        write_compact_size(buffer, self.hash_type);

        if for_hashing || self.flags & SIGNATURE_FLAG_HAS_SYSTEM != 0 {
            buffer.extend_from_slice(&self.system_id.raw);
        }
        buffer.extend_from_slice(&self.identity_id.raw);

        if self.flags & SIGNATURE_FLAG_HAS_VDXF_KEYS != 0 {
            write_compact_size(buffer, self.vdxf_keys_raw.len() as u64);
            for key in &self.vdxf_keys_raw {
                buffer.extend_from_slice(key);
            }
        }
        if self.flags & SIGNATURE_FLAG_HAS_VDXF_KEY_NAMES != 0 {
            write_vector(buffer, &self.vdxf_key_names_raw);
        }
        if self.flags & SIGNATURE_FLAG_HAS_BOUND_HASHES != 0 {
            write_vector(buffer, &self.bound_hashes_raw);
        }
        if self.flags & SIGNATURE_FLAG_HAS_STATEMENTS != 0 {
            write_vector(buffer, &self.statements_raw);
        }

        write_var_slice(buffer, &self.signature_as_vch);
        Ok(())
    }

    fn identity_hash(
        &self,
        height: u32,
        raw_data_hash: &[u8; 32],
    ) -> Result<[u8; 32], WalletProtocolError> {
        if self.hash_type != HASH_TYPE_SHA256 {
            return Err(WalletProtocolError::UnsupportedHashType(self.hash_type));
        }

        if self.signature_version != IDENTITY_SIGNATURE_VERSION as u64 {
            return Err(WalletProtocolError::Malformed(format!(
                "unsupported identity signature version {}",
                self.signature_version
            )));
        }

        if self.flags
            & (SIGNATURE_FLAG_HAS_VDXF_KEYS
                | SIGNATURE_FLAG_HAS_VDXF_KEY_NAMES
                | SIGNATURE_FLAG_HAS_BOUND_HASHES
                | SIGNATURE_FLAG_HAS_STATEMENTS)
            != 0
        {
            return Err(WalletProtocolError::UnsupportedSignatureFeatures);
        }

        let system_hash = self
            .system_id
            .hash160
            .ok_or(WalletProtocolError::ChainMismatch)?;
        let identity_hash = self
            .identity_id
            .hash160
            .ok_or(WalletProtocolError::MissingSignatureIdentity)?;

        let mut hasher = Sha256::new();
        hasher.update(system_hash);
        hasher.update(height.to_le_bytes());
        hasher.update(identity_hash);
        hasher.update(VERUS_DATA_SIGNATURE_PREFIX);
        hasher.update(raw_data_hash);
        Ok(hasher.finalize().into())
    }
}

#[derive(Debug)]
struct CompactAddress {
    address_type: u64,
    hash160: Option<[u8; 20]>,
    raw: Vec<u8>,
}

impl CompactAddress {
    fn parse(reader: &mut BinaryReader<'_>) -> Result<Self, WalletProtocolError> {
        let start = reader.offset();
        let _version = reader.read_compact_size_u64()?;
        let address_type = reader.read_compact_size_u64()?;
        let hash160 = match address_type {
            COMPACT_ADDRESS_TYPE_I_ADDRESS => Some(reader.read_fixed::<20>()?),
            COMPACT_ADDRESS_TYPE_FQN => {
                read_bounded_var_slice(reader, MAX_VECTOR_ITEM_BYTES)?;
                None
            }
            _ => {
                return Err(WalletProtocolError::Malformed(format!(
                    "unsupported compact address type {address_type}"
                )));
            }
        };
        let raw = reader.bytes_from(start).to_vec();
        Ok(Self {
            address_type,
            hash160,
            raw,
        })
    }

    fn from_i_address(address: &str) -> Result<Self, WalletProtocolError> {
        let hash160 = decode_base58check_hash20(address, I_ADDRESS_VERSION)?;
        let mut raw = Vec::new();
        write_compact_size(&mut raw, 1);
        write_compact_size(&mut raw, COMPACT_ADDRESS_TYPE_I_ADDRESS);
        raw.extend_from_slice(&hash160);
        Ok(Self {
            address_type: COMPACT_ADDRESS_TYPE_I_ADDRESS,
            hash160: Some(hash160),
            raw,
        })
    }

    fn i_address(&self) -> Option<String> {
        if self.address_type != COMPACT_ADDRESS_TYPE_I_ADDRESS {
            return None;
        }
        self.hash160
            .as_ref()
            .and_then(|hash| encode_base58check(I_ADDRESS_VERSION, hash).ok())
    }
}

fn read_compact_address_raw(reader: &mut BinaryReader<'_>) -> Result<Vec<u8>, WalletProtocolError> {
    let address = CompactAddress::parse(reader)?;
    Ok(address.raw)
}

#[derive(Debug)]
struct IdentitySignature {
    height: u32,
    signatures: Vec<Vec<u8>>,
}

impl IdentitySignature {
    fn parse(bytes: &[u8]) -> Result<Self, WalletProtocolError> {
        let mut reader = BinaryReader::new(bytes);
        let version = reader.read_byte()?;
        let hash_type = if version == IDENTITY_SIGNATURE_VERSION {
            reader.read_byte()?
        } else {
            return Err(WalletProtocolError::Malformed(format!(
                "unsupported identity signature wire version {version}"
            )));
        };
        if u64::from(hash_type) != HASH_TYPE_SHA256 {
            return Err(WalletProtocolError::UnsupportedHashType(u64::from(
                hash_type,
            )));
        }

        let height = u32::from_le_bytes(reader.read_fixed::<4>()?);
        let count = usize::from(reader.read_byte()?);
        if count > MAX_SIGNATURE_COUNT {
            return Err(WalletProtocolError::TooManySignatures {
                actual: count,
                max: MAX_SIGNATURE_COUNT,
            });
        }

        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?.to_vec());
        }
        if !reader.is_finished() {
            return Err(WalletProtocolError::Malformed(
                "unexpected trailing identity signature bytes".to_string(),
            ));
        }

        Ok(Self { height, signatures })
    }

    fn verify_for_address(
        &self,
        signature_hash: &[u8; 32],
        address: &str,
    ) -> Result<bool, WalletProtocolError> {
        let secp = Secp256k1::verification_only();
        let message = Message::from_digest_slice(signature_hash)
            .map_err(|_| WalletProtocolError::InvalidSignature)?;

        for compact_signature in &self.signatures {
            if compact_signature.len() != 65 {
                continue;
            }

            let flag_byte = compact_signature[0].saturating_sub(27);
            if flag_byte != (flag_byte & 7) {
                continue;
            }

            let recovery_id = RecoveryId::from_i32(i32::from(flag_byte & 3))
                .map_err(|_| WalletProtocolError::InvalidSignature)?;
            let recoverable =
                RecoverableSignature::from_compact(&compact_signature[1..65], recovery_id)
                    .map_err(|_| WalletProtocolError::InvalidSignature)?;
            let public_key = secp
                .recover_ecdsa(&message, &recoverable)
                .map_err(|_| WalletProtocolError::InvalidSignature)?;
            let recovered_address = public_key_to_verus_address(&public_key.serialize())?;

            if recovered_address != address {
                continue;
            }

            let regular_signature = Signature::from_compact(&compact_signature[1..65])
                .map_err(|_| WalletProtocolError::InvalidSignature)?;
            if secp
                .verify_ecdsa(&message, &regular_signature, &public_key)
                .is_ok()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[derive(Debug)]
struct OrdinalDetail {
    data: Vec<u8>,
    ordinal: u64,
    raw: Vec<u8>,
}

fn parse_details(
    reader: &mut BinaryReader<'_>,
    flags: u64,
) -> Result<Vec<OrdinalDetail>, WalletProtocolError> {
    let detail_count = if flags & ENVELOPE_FLAG_MULTI_DETAILS != 0 {
        reader.read_compact_size()?
    } else {
        1
    };
    if detail_count > MAX_DETAIL_COUNT {
        return Err(WalletProtocolError::TooManyDetails {
            actual: detail_count,
            max: MAX_DETAIL_COUNT,
        });
    }

    let mut details = Vec::with_capacity(detail_count);
    for _ in 0..detail_count {
        let start = reader.offset();
        let ordinal = reader.read_compact_size_u64()?;
        if matches!(ordinal, 102..=104) {
            return Err(WalletProtocolError::Malformed(format!(
                "unsupported custom VDXF ordinal type {ordinal}"
            )));
        }

        let version = reader.read_varint()?;
        if version != 1 {
            return Err(WalletProtocolError::Malformed(format!(
                "unsupported ordinal version {version}"
            )));
        }
        let data = reader.read_var_slice()?.to_vec();
        let raw = reader.bytes_from(start).to_vec();
        details.push(OrdinalDetail { data, ordinal, raw });
    }

    Ok(details)
}

#[derive(Debug)]
struct EncryptedDescriptor {
    encrypted_data: Vec<u8>,
    ephemeral_public_key: [u8; 32],
}

fn parse_encrypted_data_descriptor(
    bytes: &[u8],
) -> Result<EncryptedDescriptor, WalletProtocolError> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(WalletProtocolError::DescriptorTooLarge {
            actual: bytes.len(),
            max: MAX_DESCRIPTOR_BYTES,
        });
    }

    let mut reader = BinaryReader::new(bytes);
    let version = reader
        .read_varint()
        .map_err(|error| WalletProtocolError::MalformedEncryptedDescriptor(error.to_string()))?;
    if version != DATA_DESCRIPTOR_VERSION {
        return Err(WalletProtocolError::MalformedEncryptedDescriptor(format!(
            "unsupported descriptor version {version}"
        )));
    }

    let flags = reader
        .read_varint()
        .map_err(|error| WalletProtocolError::MalformedEncryptedDescriptor(error.to_string()))?;
    if flags & DATA_DESCRIPTOR_FLAG_ENCRYPTED_DATA == 0 {
        return Err(WalletProtocolError::MalformedEncryptedDescriptor(
            "descriptor is not encrypted".to_string(),
        ));
    }
    if flags & DATA_DESCRIPTOR_FLAG_EPK_PRESENT == 0 {
        return Err(WalletProtocolError::MalformedEncryptedDescriptor(
            "descriptor is missing epk".to_string(),
        ));
    }
    if flags & (DATA_DESCRIPTOR_FLAG_IVK_PRESENT | DATA_DESCRIPTOR_FLAG_SSK_PRESENT) != 0 {
        return Err(WalletProtocolError::MalformedForbiddenDescriptor(
            "descriptor includes forbidden key material".to_string(),
        ));
    }

    let encrypted_data_len = reader
        .read_compact_size()
        .map_err(|error| WalletProtocolError::MalformedEncryptedDescriptor(error.to_string()))?;
    if encrypted_data_len > MAX_ENCRYPTED_DATA_BYTES {
        return Err(WalletProtocolError::EncryptedDataTooLarge {
            actual: encrypted_data_len,
            max: MAX_ENCRYPTED_DATA_BYTES,
        });
    }
    let encrypted_data = reader
        .read_slice(encrypted_data_len)
        .map_err(|error| WalletProtocolError::MalformedEncryptedDescriptor(error.to_string()))?
        .to_vec();

    if flags & DATA_DESCRIPTOR_FLAG_LABEL_PRESENT != 0 {
        read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?;
    }
    if flags & DATA_DESCRIPTOR_FLAG_MIME_PRESENT != 0 {
        read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?;
    }
    if flags & DATA_DESCRIPTOR_FLAG_SALT_PRESENT != 0 {
        read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?;
    }
    let ephemeral_public_key = read_bounded_var_slice(&mut reader, MAX_VECTOR_ITEM_BYTES)?;
    if ephemeral_public_key.len() != 32 {
        return Err(WalletProtocolError::MalformedEncryptedDescriptor(format!(
            "expected epk to be 32 bytes, got {}",
            ephemeral_public_key.len()
        )));
    }
    if !reader.is_finished() {
        return Err(WalletProtocolError::MalformedEncryptedDescriptor(
            "unexpected trailing descriptor bytes".to_string(),
        ));
    }

    Ok(EncryptedDescriptor {
        encrypted_data,
        ephemeral_public_key: ephemeral_public_key.try_into().map_err(|_| {
            WalletProtocolError::MalformedEncryptedDescriptor("invalid epk length".to_string())
        })?,
    })
}

#[derive(Debug, Deserialize)]
struct VerusRpcResponse<T> {
    error: Option<VerusRpcError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct VerusRpcError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct IdentityResult {
    #[serde(default)]
    friendlyname: Option<String>,
    #[serde(default)]
    fqn: Option<String>,
    #[serde(default)]
    fullyqualifiedname: Option<String>,
    #[serde(default, rename = "fullyQualifiedName")]
    fully_qualified_name: Option<String>,
    identity: IdentityBody,
    #[serde(default)]
    status: Option<String>,
}

impl IdentityResult {
    fn display_name(&self) -> Option<String> {
        [
            self.fullyqualifiedname.as_deref(),
            self.fully_qualified_name.as_deref(),
            self.fqn.as_deref(),
            self.friendlyname.as_deref(),
            self.identity.fullyqualifiedname.as_deref(),
            self.identity.fully_qualified_name.as_deref(),
            self.identity.fqn.as_deref(),
            self.identity.friendlyname.as_deref(),
            self.identity.name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|name| !name.is_empty() && !name.starts_with('i'))
        .map(ToOwned::to_owned)
    }
}

#[derive(Debug, Deserialize)]
struct IdentityBody {
    #[serde(default)]
    friendlyname: Option<String>,
    #[serde(default)]
    fqn: Option<String>,
    #[serde(default)]
    fullyqualifiedname: Option<String>,
    #[serde(default, rename = "fullyQualifiedName")]
    fully_qualified_name: Option<String>,
    identityaddress: String,
    #[serde(default)]
    minimumsignatures: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    primaryaddresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BlockResult {
    time: i64,
}

struct VerusRpcPublicData {
    base_url: String,
    agent: ureq::Agent,
}

impl VerusRpcPublicData {
    fn new(base_url: &str) -> Result<Self, WalletProtocolError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .build();
        Ok(Self {
            base_url: format!("{}/", base_url.trim_end_matches('/')),
            agent,
        })
    }

    fn get_identity_at_height(
        &self,
        identity: &str,
        height: u32,
    ) -> Result<IdentityResult, WalletProtocolError> {
        let response: VerusRpcResponse<IdentityResult> =
            self.rpc("getidentity", serde_json::json!([identity, height]))?;
        response.into_result("getidentity")
    }

    fn get_block_time(&self, height: u32) -> Result<i64, WalletProtocolError> {
        let response: VerusRpcResponse<BlockResult> =
            self.rpc("getblock", serde_json::json!([height.to_string()]))?;
        Ok(response.into_result("getblock")?.time)
    }

    fn rpc<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<VerusRpcResponse<T>, WalletProtocolError> {
        self.agent
            .post(&self.base_url)
            .set("Content-Type", "application/json")
            .set("X-VRPC-API-Version", "2")
            .send_json(serde_json::json!({
                "jsonrpc": "1.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .map_err(public_data_error)?
            .into_json::<VerusRpcResponse<T>>()
            .map_err(public_data_error)
    }
}

fn public_data_error(error: impl StdError) -> WalletProtocolError {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        message.push_str(": ");
        message.push_str(&error.to_string());
        source = error.source();
    }
    WalletProtocolError::PublicData(message)
}

impl<T> VerusRpcResponse<T> {
    fn into_result(self, method: &str) -> Result<T, WalletProtocolError> {
        if let Some(error) = self.error {
            return Err(WalletProtocolError::PublicData(format!(
                "{method}: {}",
                error.message
            )));
        }
        self.result
            .ok_or_else(|| WalletProtocolError::PublicData(format!("{method}: missing result")))
    }
}

fn read_vector(reader: &mut BinaryReader<'_>) -> Result<Vec<Vec<u8>>, WalletProtocolError> {
    let count = reader.read_compact_size()?;
    if count > MAX_VECTOR_COUNT {
        return Err(WalletProtocolError::TooManyVectorItems {
            actual: count,
            max: MAX_VECTOR_COUNT,
        });
    }

    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_bounded_var_slice(reader, MAX_VECTOR_ITEM_BYTES)?.to_vec());
    }
    Ok(values)
}

fn read_bounded_var_slice<'a>(
    reader: &mut BinaryReader<'a>,
    max: usize,
) -> Result<&'a [u8], WalletProtocolError> {
    let len = reader.read_compact_size()?;
    if len > max {
        return Err(WalletProtocolError::VectorItemTooLarge { actual: len, max });
    }
    reader.read_slice(len)
}

fn write_vector(buffer: &mut Vec<u8>, values: &[Vec<u8>]) {
    write_compact_size(buffer, values.len() as u64);
    for value in values {
        write_var_slice(buffer, value);
    }
}

fn public_key_to_verus_address(
    compressed_public_key: &[u8],
) -> Result<String, WalletProtocolError> {
    encode_base58check(VERUS_PUBKEY_HASH_VERSION, &hash160(compressed_public_key))
}

fn hash160(value: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(value);
    <Ripemd160 as RipemdDigest>::digest(sha).into()
}

fn decode_base58check_hash20(
    value: &str,
    expected_version: u8,
) -> Result<[u8; 20], WalletProtocolError> {
    let decoded = bs58::decode(value)
        .with_check(None)
        .into_vec()
        .map_err(|error| WalletProtocolError::Malformed(format!("invalid base58check: {error}")))?;
    if decoded.len() != 21 || decoded[0] != expected_version {
        return Err(WalletProtocolError::Malformed(
            "unexpected base58check address version or length".to_string(),
        ));
    }
    decoded[1..21]
        .try_into()
        .map_err(|_| WalletProtocolError::Malformed("invalid address hash length".to_string()))
}

fn encode_base58check(version: u8, hash: &[u8; 20]) -> Result<String, WalletProtocolError> {
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(hash);
    Ok(bs58::encode(payload).with_check().into_string())
}

fn write_var_slice(buffer: &mut Vec<u8>, value: &[u8]) {
    write_compact_size(buffer, value.len() as u64);
    buffer.extend_from_slice(value);
}

fn write_compact_size(buffer: &mut Vec<u8>, value: u64) {
    match value {
        0x00..=0xfc => buffer.push(value as u8),
        0xfd..=0xffff => {
            buffer.push(0xfd);
            buffer.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buffer.push(0xfe);
            buffer.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            buffer.push(0xff);
            buffer.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn write_varint(buffer: &mut Vec<u8>, value: u64) -> Result<(), WalletProtocolError> {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    let mut n = value;
    loop {
        tmp[len] = (n & 0x7f) as u8;
        len += 1;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7).saturating_sub(1);
    }

    for index in (0..len).rev() {
        let mut byte = tmp[index];
        if index != 0 {
            byte |= 0x80;
        }
        buffer.push(byte);
    }

    Ok(())
}

#[derive(Clone)]
struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes_from(&self, start: usize) -> &'a [u8] {
        &self.bytes[start..self.offset]
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn read_byte(&mut self) -> Result<u8, WalletProtocolError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| WalletProtocolError::Malformed("read beyond end".to_string()))?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], WalletProtocolError> {
        let slice = self.read_slice(N)?;
        slice
            .try_into()
            .map_err(|_| WalletProtocolError::Malformed(format!("expected {N} bytes")))
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], WalletProtocolError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| WalletProtocolError::Malformed("length overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(WalletProtocolError::Malformed(format!(
                "read beyond end: need {len} bytes at offset {}, total {}",
                self.offset,
                self.bytes.len()
            )));
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_varint(&mut self) -> Result<u64, WalletProtocolError> {
        let mut value = 0u64;

        for _ in 0..10 {
            let byte = self.read_byte()?;
            value = value
                .checked_shl(7)
                .ok_or_else(|| WalletProtocolError::Malformed("varint overflow".to_string()))?
                | u64::from(byte & 0x7f);

            if byte & 0x80 == 0 {
                return Ok(value);
            }

            value = value
                .checked_add(1)
                .ok_or_else(|| WalletProtocolError::Malformed("varint overflow".to_string()))?;
        }

        Err(WalletProtocolError::Malformed(
            "varint too long".to_string(),
        ))
    }

    fn read_compact_size(&mut self) -> Result<usize, WalletProtocolError> {
        let value = self.read_compact_size_u64()?;
        usize::try_from(value)
            .map_err(|_| WalletProtocolError::Malformed("compact size overflows usize".to_string()))
    }

    fn read_compact_size_u64(&mut self) -> Result<u64, WalletProtocolError> {
        let first = self.read_byte()?;
        match first {
            0x00..=0xfc => Ok(u64::from(first)),
            0xfd => Ok(u64::from(u16::from_le_bytes(self.read_fixed::<2>()?))),
            0xfe => Ok(u64::from(u32::from_le_bytes(self.read_fixed::<4>()?))),
            0xff => Ok(u64::from_le_bytes(self.read_fixed::<8>()?)),
        }
    }

    fn read_var_slice(&mut self) -> Result<&'a [u8], WalletProtocolError> {
        let len = self.read_compact_size()?;
        self.read_slice(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, SecretKey};

    const ENVELOPE_FLAG_IS_TESTNET: u64 = 16;

    #[test]
    fn parses_signed_encrypted_generic_response() {
        let fixture = signed_response_fixture();
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let descriptor = response.encrypted_app_encryption_descriptor().unwrap();

        assert_eq!(descriptor.encrypted_data, fixture.encrypted_data);
        assert_eq!(
            descriptor.ephemeral_public_key,
            fixture.ephemeral_public_key
        );
        assert_eq!(
            response.signature.unwrap().identity_id.i_address().unwrap(),
            fixture.identity_i_address
        );
    }

    #[test]
    fn rejects_unsigned_generic_response() {
        let mut response = Vec::new();
        write_compact_size(&mut response, 1);
        write_compact_size(&mut response, ENVELOPE_FLAG_IS_TESTNET);
        response.extend_from_slice(&descriptor_detail(&[1, 2, 3], &[4u8; 32]));

        let parsed =
            GenericResponse::parse(&response, ExpectedChain::from_name("VRSCTEST").unwrap())
                .unwrap();
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: false,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: None,
            expected_unsigned_request_hash_hex: None,
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: URL_SAFE_NO_PAD.encode(response),
        };

        assert!(matches!(
            verify_response_policy(
                &parsed,
                &input,
                ExpectedChain::from_name("VRSCTEST").unwrap()
            ),
            Err(WalletProtocolError::UnsignedResponse)
        ));
    }

    #[test]
    fn rejects_request_hash_mismatch_when_present() {
        let fixture = signed_response_fixture_with_request_hash([9u8; 32]);
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: false,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: Some(hex::encode([8u8; 32])),
            expected_unsigned_request_hash_hex: None,
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: URL_SAFE_NO_PAD.encode(&fixture.response),
        };

        assert!(matches!(
            verify_response_policy(&response, &input, fixture.chain),
            Err(WalletProtocolError::RequestHashMismatch)
        ));
    }

    #[test]
    fn rejects_missing_request_hash_when_expected() {
        let fixture = signed_response_fixture();
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: false,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: Some(hex::encode([8u8; 32])),
            expected_unsigned_request_hash_hex: Some(hex::encode([9u8; 32])),
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: URL_SAFE_NO_PAD.encode(&fixture.response),
        };

        assert!(matches!(
            verify_response_policy(&response, &input, fixture.chain),
            Err(WalletProtocolError::MissingRequestHash)
        ));
    }

    #[test]
    fn accepts_missing_request_hash_when_app_encryption_request_id_will_be_enforced() {
        let fixture = signed_response_fixture();
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: true,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: Some(hex::encode([8u8; 32])),
            expected_unsigned_request_hash_hex: Some(hex::encode([9u8; 32])),
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: URL_SAFE_NO_PAD.encode(&fixture.response),
        };

        verify_response_policy(&response, &input, fixture.chain).unwrap();
    }

    #[test]
    fn accepts_missing_envelope_testnet_flag_when_signature_system_matches() {
        let fixture = signed_response_fixture_with_options([0u8; 32], false);
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: false,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: None,
            expected_unsigned_request_hash_hex: None,
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: URL_SAFE_NO_PAD.encode(&fixture.response),
        };

        verify_response_policy(&response, &input, fixture.chain).unwrap();
    }

    #[test]
    fn rejects_oversized_response_before_decoding() {
        let input = VerifyWalletResponseInput {
            allow_missing_request_hash: false,
            chain: "VRSCTEST".to_string(),
            expected_signed_request_hash_hex: None,
            expected_unsigned_request_hash_hex: None,
            expected_wallet_signer_identity_i_address: None,
            response_base64_url: "A".repeat(MAX_RESPONSE_BASE64URL_CHARS + 1),
        };

        assert!(matches!(
            verify_wallet_generic_response(&input),
            Err(WalletProtocolError::ResponseTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_too_many_details() {
        let mut response = Vec::new();
        write_compact_size(&mut response, 1);
        write_compact_size(&mut response, ENVELOPE_FLAG_MULTI_DETAILS);
        write_compact_size(&mut response, (MAX_DETAIL_COUNT + 1) as u64);

        assert!(matches!(
            GenericResponse::parse(&response, ExpectedChain::from_name("VRSCTEST").unwrap()),
            Err(WalletProtocolError::TooManyDetails { .. })
        ));
    }

    #[test]
    fn rejects_too_many_identity_signatures() {
        let mut signature = Vec::new();
        signature.push(IDENTITY_SIGNATURE_VERSION);
        signature.push(HASH_TYPE_SHA256 as u8);
        signature.extend_from_slice(&100u32.to_le_bytes());
        signature.push((MAX_SIGNATURE_COUNT + 1) as u8);

        assert!(matches!(
            IdentitySignature::parse(&signature),
            Err(WalletProtocolError::TooManySignatures { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_encrypted_descriptors() {
        let mut response_bytes = Vec::new();
        write_compact_size(&mut response_bytes, 1);
        write_compact_size(&mut response_bytes, ENVELOPE_FLAG_MULTI_DETAILS);
        write_compact_size(&mut response_bytes, 2);
        response_bytes.extend_from_slice(&descriptor_detail(&[1, 2, 3], &[4u8; 32]));
        response_bytes.extend_from_slice(&descriptor_detail(&[5, 6, 7], &[8u8; 32]));

        let response = GenericResponse::parse(
            &response_bytes,
            ExpectedChain::from_name("VRSCTEST").unwrap(),
        )
        .unwrap();

        assert!(matches!(
            response.encrypted_app_encryption_descriptor(),
            Err(WalletProtocolError::DuplicateEncryptedAppEncryptionDescriptor)
        ));
    }

    #[test]
    fn rejects_descriptor_with_forbidden_key_material_flags() {
        let detail = descriptor_detail_with_flags(
            &[1, 2, 3],
            &[4u8; 32],
            DATA_DESCRIPTOR_FLAG_ENCRYPTED_DATA
                | DATA_DESCRIPTOR_FLAG_EPK_PRESENT
                | DATA_DESCRIPTOR_FLAG_IVK_PRESENT,
        );
        let mut response_bytes = Vec::new();
        write_compact_size(&mut response_bytes, 1);
        write_compact_size(&mut response_bytes, 0);
        response_bytes.extend_from_slice(&detail);
        let response = GenericResponse::parse(
            &response_bytes,
            ExpectedChain::from_name("VRSCTEST").unwrap(),
        )
        .unwrap();

        assert!(matches!(
            response.encrypted_app_encryption_descriptor(),
            Err(WalletProtocolError::MalformedForbiddenDescriptor(_))
        ));
    }

    #[test]
    fn returns_malformed_descriptor_errors() {
        let mut detail = Vec::new();
        write_compact_size(&mut detail, DATA_DESCRIPTOR_ORDINAL);
        write_varint(&mut detail, 1).unwrap();
        write_var_slice(&mut detail, &[0xff]);

        let mut response_bytes = Vec::new();
        write_compact_size(&mut response_bytes, 1);
        write_compact_size(&mut response_bytes, 0);
        response_bytes.extend_from_slice(&detail);
        let response = GenericResponse::parse(
            &response_bytes,
            ExpectedChain::from_name("VRSCTEST").unwrap(),
        )
        .unwrap();

        assert!(matches!(
            response.encrypted_app_encryption_descriptor(),
            Err(WalletProtocolError::MalformedEncryptedDescriptor(_))
        ));
    }

    #[test]
    fn verifies_identity_signature_against_primary_address() {
        let fixture = signed_response_fixture();
        let response = GenericResponse::parse(&fixture.response, fixture.chain).unwrap();
        let signature = response.signature.as_ref().unwrap();
        let identity_signature = IdentitySignature::parse(&signature.signature_as_vch).unwrap();
        let signature_hash = response
            .details_identity_signature_hash(identity_signature.height)
            .unwrap();
        let identity = IdentityResult {
            friendlyname: Some("Test Identity".to_string()),
            fqn: None,
            fullyqualifiedname: None,
            fully_qualified_name: None,
            identity: IdentityBody {
                friendlyname: None,
                fqn: None,
                fullyqualifiedname: None,
                fully_qualified_name: None,
                identityaddress: fixture.identity_i_address,
                minimumsignatures: 1,
                name: None,
                primaryaddresses: vec![fixture.primary_address],
            },
            status: Some("active".to_string()),
        };

        verify_identity_signature(&identity_signature, &signature_hash, &identity).unwrap();
        assert_eq!(identity.display_name().as_deref(), Some("Test Identity"));
    }

    struct SignedResponseFixture {
        chain: ExpectedChain,
        encrypted_data: Vec<u8>,
        ephemeral_public_key: [u8; 32],
        identity_i_address: String,
        primary_address: String,
        response: Vec<u8>,
    }

    fn signed_response_fixture() -> SignedResponseFixture {
        signed_response_fixture_with_request_hash([0u8; 32])
    }

    fn signed_response_fixture_with_request_hash(request_hash: [u8; 32]) -> SignedResponseFixture {
        signed_response_fixture_with_options(request_hash, true)
    }

    fn signed_response_fixture_with_options(
        request_hash: [u8; 32],
        include_envelope_testnet_flag: bool,
    ) -> SignedResponseFixture {
        let chain = ExpectedChain::from_name("VRSCTEST").unwrap();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let primary_address = public_key_to_verus_address(&public_key.serialize()).unwrap();
        let identity_hash = [7u8; 20];
        let identity_i_address = encode_base58check(I_ADDRESS_VERSION, &identity_hash).unwrap();
        let encrypted_data = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let ephemeral_public_key = [0xee; 32];
        let details = descriptor_detail(&encrypted_data, &ephemeral_public_key);
        let mut response = unsigned_signed_response_prefix_with_signature(
            chain,
            &identity_i_address,
            &details,
            &[],
            request_hash,
            include_envelope_testnet_flag,
        );

        let parsed = GenericResponse::parse(&response, chain).unwrap();
        let hash = parsed.details_identity_signature_hash(100).unwrap();
        let message = Message::from_digest_slice(&hash).unwrap();
        let recoverable = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, compact) = recoverable.serialize_compact();
        let mut compact_signature = Vec::with_capacity(65);
        compact_signature.push(27 + recovery_id.to_i32() as u8 + 4);
        compact_signature.extend_from_slice(&compact);
        let identity_signature = identity_signature_bytes(100, &compact_signature);

        response = unsigned_signed_response_prefix_with_signature(
            chain,
            &identity_i_address,
            &details,
            &identity_signature,
            request_hash,
            include_envelope_testnet_flag,
        );

        SignedResponseFixture {
            chain,
            encrypted_data,
            ephemeral_public_key,
            identity_i_address,
            primary_address,
            response,
        }
    }

    fn unsigned_signed_response_prefix_with_signature(
        chain: ExpectedChain,
        identity_i_address: &str,
        details: &[u8],
        signature_as_vch: &[u8],
        request_hash: [u8; 32],
        include_envelope_testnet_flag: bool,
    ) -> Vec<u8> {
        let mut response = Vec::new();
        let mut flags = ENVELOPE_FLAG_SIGNED | ENVELOPE_FLAG_HAS_CREATED_AT;
        if include_envelope_testnet_flag {
            flags |= ENVELOPE_FLAG_IS_TESTNET;
        }
        if request_hash != [0u8; 32] {
            flags |= GENERIC_RESPONSE_FLAG_HAS_REQUEST_HASH;
        }
        write_compact_size(&mut response, 1);
        write_compact_size(&mut response, flags);
        write_signature_data(&mut response, chain, identity_i_address, signature_as_vch);
        write_compact_size(&mut response, 1000);
        response.extend_from_slice(details);
        if request_hash != [0u8; 32] {
            write_compact_size(&mut response, HASH_TYPE_SHA256);
            write_var_slice(&mut response, &request_hash);
        }
        response
    }

    fn write_signature_data(
        buffer: &mut Vec<u8>,
        chain: ExpectedChain,
        identity_i_address: &str,
        signature_as_vch: &[u8],
    ) {
        write_varint(buffer, 1).unwrap();
        write_compact_size(buffer, SIGNATURE_FLAG_HAS_SYSTEM);
        write_compact_size(buffer, IDENTITY_SIGNATURE_VERSION as u64);
        write_compact_size(buffer, HASH_TYPE_SHA256);
        buffer.extend_from_slice(&CompactAddress::from_i_address(chain.chain_id).unwrap().raw);
        buffer.extend_from_slice(
            &CompactAddress::from_i_address(identity_i_address)
                .unwrap()
                .raw,
        );
        write_var_slice(buffer, signature_as_vch);
    }

    fn descriptor_detail(encrypted_data: &[u8], ephemeral_public_key: &[u8; 32]) -> Vec<u8> {
        descriptor_detail_with_flags(
            encrypted_data,
            ephemeral_public_key,
            DATA_DESCRIPTOR_FLAG_ENCRYPTED_DATA | DATA_DESCRIPTOR_FLAG_EPK_PRESENT,
        )
    }

    fn descriptor_detail_with_flags(
        encrypted_data: &[u8],
        ephemeral_public_key: &[u8; 32],
        flags: u64,
    ) -> Vec<u8> {
        let mut descriptor = Vec::new();
        write_varint(&mut descriptor, DATA_DESCRIPTOR_VERSION).unwrap();
        write_varint(&mut descriptor, flags).unwrap();
        write_var_slice(&mut descriptor, encrypted_data);
        write_var_slice(&mut descriptor, ephemeral_public_key);

        let mut detail = Vec::new();
        write_compact_size(&mut detail, DATA_DESCRIPTOR_ORDINAL);
        write_varint(&mut detail, 1).unwrap();
        write_var_slice(&mut detail, &descriptor);
        detail
    }

    fn identity_signature_bytes(height: u32, compact_signature: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(IDENTITY_SIGNATURE_VERSION);
        bytes.push(HASH_TYPE_SHA256 as u8);
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(1);
        write_var_slice(&mut bytes, compact_signature);
        bytes
    }
}
