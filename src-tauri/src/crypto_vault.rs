use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const VAULT_CONTEXT_PROTOCOL: &str = "verus-notes.wallet-vault.v1";
const VAULT_ROOT_INFO: &[u8] = b"verus-notes/vault-root/v1";
const RECORD_TOMBSTONE_PROTOCOL: &str = "verus-notes.record-tombstone.v1";
const PADDED_PLAINTEXT_PROTOCOL: &str = "verus-notes.padded-plaintext.v1";
const PADDED_PLAINTEXT_BUCKETS: [usize; 6] = [1024, 4096, 16_384, 65_536, 262_144, 524_288];
pub const CIPHERTEXT_SCHEMA_VERSION: u64 = 2;
pub const MIN_CIPHERTEXT_SCHEMA_VERSION: u64 = 1;
pub const BACKEND_AUTH_ALGORITHM: &str = "ed25519-v1";
pub const BACKEND_AUTH_KEY_VERSION: u64 = 1;

#[derive(Debug, Error)]
pub enum CryptoVaultError {
    #[error("expected {name} to be {expected} bytes, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid hex for {name}: {source}")]
    InvalidHex {
        name: &'static str,
        source: hex::FromHexError,
    },
    #[error("invalid base64url for {name}: {source}")]
    InvalidBase64 {
        name: &'static str,
        source: base64::DecodeError,
    },
    #[error("hkdf output length is invalid")]
    InvalidHkdfLength,
    #[error("canonical json serialization failed: {0}")]
    CanonicalJson(serde_json::Error),
    #[error("note encryption failed")]
    Encrypt,
    #[error("note decryption failed")]
    Decrypt,
    #[error("vault policy violation: {0}")]
    Policy(String),
    #[cfg(test)]
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultContext {
    pub app_encryption_address: String,
    pub app_identity_i_address: String,
    pub chain: String,
    pub derivation_number: u64,
    pub key_version: u64,
    pub wallet_signer_identity_i_address: String,
}

impl VaultContext {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("appEncryptionAddress", json!(self.app_encryption_address)),
            ("appIdentityIAddress", json!(self.app_identity_i_address)),
            ("chain", json!(self.chain)),
            ("derivationNumber", json!(self.derivation_number)),
            ("keyVersion", json!(self.key_version)),
            ("protocol", json!(VAULT_CONTEXT_PROTOCOL)),
            (
                "walletSignerIdentityIAddress",
                json!(self.wallet_signer_identity_i_address),
            ),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendAuthChallenge {
    pub app_encryption_request_id: String,
    pub app_identity_i_address: String,
    pub backend_auth_algorithm: String,
    pub backend_auth_key_id: String,
    pub backend_auth_public_key: String,
    pub backend_auth_key_version: u64,
    pub challenge: String,
    pub derivation_number: u64,
    pub expires_at_ms: u64,
    pub session_id: String,
    pub vault_id: String,
    pub wallet_signer_identity_i_address: String,
}

impl BackendAuthChallenge {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            (
                "appEncryptionRequestID",
                json!(self.app_encryption_request_id),
            ),
            ("appIdentityIAddress", json!(self.app_identity_i_address)),
            ("backendAuthAlgorithm", json!(self.backend_auth_algorithm)),
            ("backendAuthKeyId", json!(self.backend_auth_key_id)),
            ("backendAuthPublicKey", json!(self.backend_auth_public_key)),
            (
                "backendAuthKeyVersion",
                json!(self.backend_auth_key_version),
            ),
            ("challenge", json!(self.challenge)),
            ("derivationNumber", json!(self.derivation_number)),
            ("expiresAtMs", json!(self.expires_at_ms)),
            ("protocol", json!("verus-notes.backend-auth.challenge.v2")),
            ("sessionId", json!(self.session_id)),
            ("vaultId", json!(self.vault_id)),
            (
                "walletSignerIdentityIAddress",
                json!(self.wallet_signer_identity_i_address),
            ),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CiphertextHeader {
    pub algorithm: String,
    pub content_version: u64,
    pub key_version: u64,
    pub note_id: String,
    pub schema_version: u64,
    pub vault_id: String,
}

impl CiphertextHeader {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("algorithm", json!(self.algorithm)),
            ("contentVersion", json!(self.content_version)),
            ("keyVersion", json!(self.key_version)),
            ("noteId", json!(self.note_id)),
            ("schemaVersion", json!(self.schema_version)),
            ("vaultId", json!(self.vault_id)),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderCiphertextHeader {
    pub algorithm: String,
    pub content_version: u64,
    pub folder_id: String,
    pub key_version: u64,
    pub schema_version: u64,
    pub vault_id: String,
}

impl FolderCiphertextHeader {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("algorithm", json!(self.algorithm)),
            ("contentVersion", json!(self.content_version)),
            ("folderId", json!(self.folder_id)),
            ("keyVersion", json!(self.key_version)),
            ("schemaVersion", json!(self.schema_version)),
            ("vaultId", json!(self.vault_id)),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaintextNoteDocument {
    pub body_markdown: String,
    pub created_at_ms: u64,
    #[serde(default = "default_folder_id")]
    pub folder_id: String,
    pub tags: Vec<String>,
    pub title: String,
    pub updated_at_ms: u64,
}

impl PlaintextNoteDocument {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("bodyMarkdown", json!(self.body_markdown)),
            ("createdAtMs", json!(self.created_at_ms)),
            ("folderId", json!(self.folder_id)),
            ("tags", json!(self.tags)),
            ("title", json!(self.title)),
            ("updatedAtMs", json!(self.updated_at_ms)),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaintextFolderDocument {
    pub created_at_ms: u64,
    pub name: String,
    pub sort_order: u64,
    pub updated_at_ms: u64,
}

impl PlaintextFolderDocument {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("createdAtMs", json!(self.created_at_ms)),
            ("name", json!(self.name)),
            ("sortOrder", json!(self.sort_order)),
            ("updatedAtMs", json!(self.updated_at_ms)),
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordTombstoneDocument {
    pub protocol: String,
    pub kind: String,
    pub vault_id: String,
    pub record_id: String,
    pub content_version: u64,
    pub deleted_at_ms: u64,
}

impl RecordTombstoneDocument {
    fn note(header: &CiphertextHeader, deleted_at_ms: u64) -> Self {
        Self {
            protocol: RECORD_TOMBSTONE_PROTOCOL.to_string(),
            kind: "note".to_string(),
            vault_id: header.vault_id.clone(),
            record_id: header.note_id.clone(),
            content_version: header.content_version,
            deleted_at_ms,
        }
    }

    fn folder(header: &FolderCiphertextHeader, deleted_at_ms: u64) -> Self {
        Self {
            protocol: RECORD_TOMBSTONE_PROTOCOL.to_string(),
            kind: "folder".to_string(),
            vault_id: header.vault_id.clone(),
            record_id: header.folder_id.clone(),
            content_version: header.content_version,
            deleted_at_ms,
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoVaultError> {
        canonical_json_bytes(BTreeMap::from([
            ("contentVersion", json!(self.content_version)),
            ("deletedAtMs", json!(self.deleted_at_ms)),
            ("kind", json!(self.kind)),
            ("protocol", json!(self.protocol)),
            ("recordId", json!(self.record_id)),
            ("vaultId", json!(self.vault_id)),
        ]))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaddedPlaintextEnvelope {
    padding: String,
    payload: String,
    payload_length: usize,
    protocol: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedNote {
    pub header: CiphertextHeader,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedFolder {
    pub header: FolderCiphertextHeader,
    pub nonce: String,
    pub ciphertext: String,
}

pub struct VaultMaterial {
    context_hash: [u8; 32],
    context: VaultContext,
    note_root_key: Secret32,
    folder_root_key: Secret32,
    #[allow(dead_code)]
    local_cache_key: Secret32,
    backend_auth_seed: Secret32,
    export_check_key: Secret32,
    export_archive_key: Secret32,
    backend_auth_public_key: [u8; 32],
    backend_auth_key_id: String,
    vault_id: String,
}

impl VaultMaterial {
    pub fn derive(
        mut incoming_viewing_key: [u8; 32],
        context: VaultContext,
        device_id: &[u8],
    ) -> Result<Self, CryptoVaultError> {
        let context_hash = sha256(&context.canonical_bytes()?);
        let vault_root_key = Zeroizing::new(hkdf_32(
            &incoming_viewing_key,
            &context_hash,
            VAULT_ROOT_INFO,
        )?);
        incoming_viewing_key.zeroize();

        let mut note_root_key = derive_child(&vault_root_key[..], &context_hash, "note-root", b"")?;
        let mut folder_root_key =
            derive_child(&vault_root_key[..], &context_hash, "folder-root", b"")?;
        let mut local_cache_key =
            derive_child(&vault_root_key[..], &context_hash, "local-cache", device_id)?;
        let mut backend_auth_seed = derive_child(
            &vault_root_key[..],
            &context_hash,
            "backend-auth-ed25519-seed",
            b"",
        )?;
        let mut vault_id_seed = derive_child(&vault_root_key[..], &context_hash, "vault-id", b"")?;
        let mut export_check_key =
            derive_child(&vault_root_key[..], &context_hash, "export-check", b"")?;
        let mut export_archive_key =
            derive_child(&vault_root_key[..], &context_hash, "export-archive", b"")?;

        let backend_signing_key = SigningKey::from_bytes(&backend_auth_seed);
        let backend_auth_public_key = backend_signing_key.verifying_key().to_bytes();
        let backend_auth_public_key_b64 = encode_b64(&backend_auth_public_key);
        let backend_auth_key_id = backend_auth_key_id_from_public_key(
            BACKEND_AUTH_ALGORITHM,
            BACKEND_AUTH_KEY_VERSION,
            &backend_auth_public_key_b64,
        )?;
        let vault_id = vault_id_from_seed(&vault_id_seed);

        let material = Self {
            context_hash,
            context,
            note_root_key: Secret32::new(note_root_key),
            folder_root_key: Secret32::new(folder_root_key),
            local_cache_key: Secret32::new(local_cache_key),
            backend_auth_seed: Secret32::new(backend_auth_seed),
            export_check_key: Secret32::new(export_check_key),
            export_archive_key: Secret32::new(export_archive_key),
            backend_auth_public_key,
            backend_auth_key_id,
            vault_id,
        };

        note_root_key.zeroize();
        folder_root_key.zeroize();
        local_cache_key.zeroize();
        backend_auth_seed.zeroize();
        vault_id_seed.zeroize();
        export_check_key.zeroize();
        export_archive_key.zeroize();

        Ok(material)
    }

    pub fn context(&self) -> &VaultContext {
        &self.context
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn backend_auth_public_key_b64(&self) -> String {
        encode_b64(&self.backend_auth_public_key)
    }

    pub fn backend_auth_algorithm(&self) -> &'static str {
        BACKEND_AUTH_ALGORITHM
    }

    pub fn backend_auth_key_id(&self) -> &str {
        &self.backend_auth_key_id
    }

    pub fn backend_auth_key_version(&self) -> u64 {
        BACKEND_AUTH_KEY_VERSION
    }

    pub fn export_check_hash(&self) -> String {
        let mut data = b"verus-notes/export-check/v1".to_vec();
        data.extend_from_slice(self.export_check_key.as_bytes());
        encode_b64(&sha256(&data))
    }

    pub fn sign_backend_challenge(
        &self,
        challenge: &BackendAuthChallenge,
    ) -> Result<String, CryptoVaultError> {
        let signing_key = SigningKey::from_bytes(self.backend_auth_seed.as_bytes());
        let signature = signing_key.sign(&challenge.canonical_bytes()?);
        Ok(encode_b64(&signature.to_bytes()))
    }

    pub fn encrypt_archive_bytes(
        &self,
        plaintext: &[u8],
        nonce: [u8; 24],
    ) -> Result<String, CryptoVaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.export_archive_key.as_bytes())
            .map_err(|_| CryptoVaultError::Encrypt)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"verus-notes-backup/v1",
                },
            )
            .map_err(|_| CryptoVaultError::Encrypt)?;

        Ok(encode_b64(&ciphertext))
    }

    pub fn decrypt_archive_bytes(
        &self,
        nonce_b64: &str,
        ciphertext_b64: &str,
    ) -> Result<Vec<u8>, CryptoVaultError> {
        let nonce = decode_fixed_b64::<24>("backup nonce", nonce_b64)?;
        let ciphertext = decode_b64("backup ciphertext", ciphertext_b64)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.export_archive_key.as_bytes())
            .map_err(|_| CryptoVaultError::Decrypt)?;

        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: b"verus-notes-backup/v1",
                },
            )
            .map_err(|_| CryptoVaultError::Decrypt)
    }

    pub fn encrypt_note_document(
        &self,
        header: CiphertextHeader,
        document: &PlaintextNoteDocument,
        nonce: [u8; 24],
    ) -> Result<EncryptedNote, CryptoVaultError> {
        let plaintext = document.canonical_bytes()?;
        self.encrypt_note_payload(header, &plaintext, nonce)
    }

    pub fn decrypt_note_document(
        &self,
        encrypted: &EncryptedNote,
    ) -> Result<PlaintextNoteDocument, CryptoVaultError> {
        let plaintext = self.decrypt_note_payload(encrypted)?;
        serde_json::from_slice(&plaintext).map_err(CryptoVaultError::CanonicalJson)
    }

    pub fn encrypt_note_tombstone(
        &self,
        header: CiphertextHeader,
        deleted_at_ms: u64,
        nonce: [u8; 24],
    ) -> Result<EncryptedNote, CryptoVaultError> {
        let tombstone = RecordTombstoneDocument::note(&header, deleted_at_ms);
        let plaintext = tombstone.canonical_bytes()?;
        self.encrypt_note_payload(header, &plaintext, nonce)
    }

    pub fn decrypt_note_tombstone(
        &self,
        encrypted: &EncryptedNote,
    ) -> Result<RecordTombstoneDocument, CryptoVaultError> {
        let plaintext = self.decrypt_note_payload(encrypted)?;
        let tombstone: RecordTombstoneDocument =
            serde_json::from_slice(&plaintext).map_err(CryptoVaultError::CanonicalJson)?;
        validate_tombstone(
            &tombstone,
            "note",
            &encrypted.header.vault_id,
            &encrypted.header.note_id,
            encrypted.header.content_version,
        )?;
        Ok(tombstone)
    }

    pub fn encrypt_folder_document(
        &self,
        header: FolderCiphertextHeader,
        document: &PlaintextFolderDocument,
        nonce: [u8; 24],
    ) -> Result<EncryptedFolder, CryptoVaultError> {
        let plaintext = document.canonical_bytes()?;
        self.encrypt_folder_payload(header, &plaintext, nonce)
    }

    pub fn decrypt_folder_document(
        &self,
        encrypted: &EncryptedFolder,
    ) -> Result<PlaintextFolderDocument, CryptoVaultError> {
        let plaintext = self.decrypt_folder_payload(encrypted)?;
        serde_json::from_slice(&plaintext).map_err(CryptoVaultError::CanonicalJson)
    }

    pub fn encrypt_folder_tombstone(
        &self,
        header: FolderCiphertextHeader,
        deleted_at_ms: u64,
        nonce: [u8; 24],
    ) -> Result<EncryptedFolder, CryptoVaultError> {
        let tombstone = RecordTombstoneDocument::folder(&header, deleted_at_ms);
        let plaintext = tombstone.canonical_bytes()?;
        self.encrypt_folder_payload(header, &plaintext, nonce)
    }

    pub fn decrypt_folder_tombstone(
        &self,
        encrypted: &EncryptedFolder,
    ) -> Result<RecordTombstoneDocument, CryptoVaultError> {
        let plaintext = self.decrypt_folder_payload(encrypted)?;
        let tombstone: RecordTombstoneDocument =
            serde_json::from_slice(&plaintext).map_err(CryptoVaultError::CanonicalJson)?;
        validate_tombstone(
            &tombstone,
            "folder",
            &encrypted.header.vault_id,
            &encrypted.header.folder_id,
            encrypted.header.content_version,
        )?;
        Ok(tombstone)
    }

    fn encrypt_note_payload(
        &self,
        header: CiphertextHeader,
        plaintext: &[u8],
        nonce: [u8; 24],
    ) -> Result<EncryptedNote, CryptoVaultError> {
        let note_key = Zeroizing::new(self.derive_note_key(&header.note_id, header.key_version)?);
        let cipher = XChaCha20Poly1305::new_from_slice(&note_key[..])
            .map_err(|_| CryptoVaultError::Encrypt)?;
        let aad = header.canonical_bytes()?;
        let plaintext = plaintext_for_encryption(header.schema_version, plaintext)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoVaultError::Encrypt)?;

        Ok(EncryptedNote {
            header,
            nonce: encode_b64(&nonce),
            ciphertext: encode_b64(&ciphertext),
        })
    }

    fn decrypt_note_payload(&self, encrypted: &EncryptedNote) -> Result<Vec<u8>, CryptoVaultError> {
        let nonce = decode_fixed_b64::<24>("nonce", &encrypted.nonce)?;
        let ciphertext = decode_b64("ciphertext", &encrypted.ciphertext)?;
        let aad = encrypted.header.canonical_bytes()?;
        let note_key = Zeroizing::new(
            self.derive_note_key(&encrypted.header.note_id, encrypted.header.key_version)?,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&note_key[..])
            .map_err(|_| CryptoVaultError::Decrypt)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoVaultError::Decrypt)?;

        plaintext_after_decryption(encrypted.header.schema_version, &plaintext)
    }

    fn encrypt_folder_payload(
        &self,
        header: FolderCiphertextHeader,
        plaintext: &[u8],
        nonce: [u8; 24],
    ) -> Result<EncryptedFolder, CryptoVaultError> {
        let folder_key =
            Zeroizing::new(self.derive_folder_key(&header.folder_id, header.key_version)?);
        let cipher = XChaCha20Poly1305::new_from_slice(&folder_key[..])
            .map_err(|_| CryptoVaultError::Encrypt)?;
        let aad = header.canonical_bytes()?;
        let plaintext = plaintext_for_encryption(header.schema_version, plaintext)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoVaultError::Encrypt)?;

        Ok(EncryptedFolder {
            header,
            nonce: encode_b64(&nonce),
            ciphertext: encode_b64(&ciphertext),
        })
    }

    fn decrypt_folder_payload(
        &self,
        encrypted: &EncryptedFolder,
    ) -> Result<Vec<u8>, CryptoVaultError> {
        let nonce = decode_fixed_b64::<24>("nonce", &encrypted.nonce)?;
        let ciphertext = decode_b64("ciphertext", &encrypted.ciphertext)?;
        let aad = encrypted.header.canonical_bytes()?;
        let folder_key = Zeroizing::new(
            self.derive_folder_key(&encrypted.header.folder_id, encrypted.header.key_version)?,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&folder_key[..])
            .map_err(|_| CryptoVaultError::Decrypt)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoVaultError::Decrypt)?;

        plaintext_after_decryption(encrypted.header.schema_version, &plaintext)
    }

    fn derive_note_key(
        &self,
        note_id: &str,
        key_version: u64,
    ) -> Result<[u8; 32], CryptoVaultError> {
        let context = format!("{note_id}\0{key_version}");
        derive_child(
            self.note_root_key.as_bytes(),
            &self.context_hash,
            "note",
            context.as_bytes(),
        )
    }

    fn derive_folder_key(
        &self,
        folder_id: &str,
        key_version: u64,
    ) -> Result<[u8; 32], CryptoVaultError> {
        let context = format!("{folder_id}\0{key_version}");
        derive_child(
            self.folder_root_key.as_bytes(),
            &self.context_hash,
            "folder",
            context.as_bytes(),
        )
    }
}

fn validate_tombstone(
    tombstone: &RecordTombstoneDocument,
    kind: &str,
    vault_id: &str,
    record_id: &str,
    content_version: u64,
) -> Result<(), CryptoVaultError> {
    if tombstone.protocol != RECORD_TOMBSTONE_PROTOCOL
        || tombstone.kind != kind
        || tombstone.vault_id != vault_id
        || tombstone.record_id != record_id
        || tombstone.content_version != content_version
    {
        return Err(CryptoVaultError::Policy(format!(
            "{kind} tombstone does not match ciphertext header"
        )));
    }

    Ok(())
}

fn plaintext_for_encryption(
    schema_version: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoVaultError> {
    if schema_version < CIPHERTEXT_SCHEMA_VERSION {
        return Ok(plaintext.to_vec());
    }
    padded_plaintext_bytes(plaintext)
}

fn plaintext_after_decryption(
    schema_version: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoVaultError> {
    if schema_version < CIPHERTEXT_SCHEMA_VERSION {
        return Ok(plaintext.to_vec());
    }

    if !PADDED_PLAINTEXT_BUCKETS.contains(&plaintext.len()) {
        return Err(CryptoVaultError::Policy(
            "padded plaintext bucket is unsupported".to_string(),
        ));
    }

    let envelope: PaddedPlaintextEnvelope =
        serde_json::from_slice(plaintext).map_err(CryptoVaultError::CanonicalJson)?;
    if envelope.protocol != PADDED_PLAINTEXT_PROTOCOL {
        return Err(CryptoVaultError::Policy(
            "padded plaintext protocol is unsupported".to_string(),
        ));
    }
    if !envelope.padding.bytes().all(|byte| byte == b'0') {
        return Err(CryptoVaultError::Policy(
            "padded plaintext padding is invalid".to_string(),
        ));
    }

    let payload = decode_b64("padded plaintext payload", &envelope.payload)?;
    if payload.len() != envelope.payload_length {
        return Err(CryptoVaultError::Policy(
            "padded plaintext payload length mismatch".to_string(),
        ));
    }

    Ok(payload)
}

fn padded_plaintext_bytes(plaintext: &[u8]) -> Result<Vec<u8>, CryptoVaultError> {
    let payload = encode_b64(plaintext);
    let base = padded_plaintext_envelope_bytes(&payload, plaintext.len(), "")?;
    let bucket = PADDED_PLAINTEXT_BUCKETS
        .iter()
        .copied()
        .find(|bucket| base.len() <= *bucket)
        .ok_or_else(|| {
            CryptoVaultError::Policy("plaintext is too large for padded encryption".to_string())
        })?;
    let padding = "0".repeat(bucket - base.len());
    let padded = padded_plaintext_envelope_bytes(&payload, plaintext.len(), &padding)?;
    if padded.len() != bucket {
        return Err(CryptoVaultError::Policy(
            "padded plaintext bucket calculation failed".to_string(),
        ));
    }
    Ok(padded)
}

fn padded_plaintext_envelope_bytes(
    payload: &str,
    payload_length: usize,
    padding: &str,
) -> Result<Vec<u8>, CryptoVaultError> {
    canonical_json_bytes(BTreeMap::from([
        ("padding", json!(padding)),
        ("payload", json!(payload)),
        ("payloadLength", json!(payload_length)),
        ("protocol", json!(PADDED_PLAINTEXT_PROTOCOL)),
    ]))
}

fn default_folder_id() -> String {
    "my-notes".to_string()
}

#[cfg(test)]
pub fn decode_32_hex(name: &'static str, value: &str) -> Result<[u8; 32], CryptoVaultError> {
    decode_fixed_hex(name, value)
}

pub fn decode_16_hex(name: &'static str, value: &str) -> Result<[u8; 16], CryptoVaultError> {
    decode_fixed_hex(name, value)
}

#[cfg(test)]
pub fn verify_backend_challenge_signature(
    public_key_b64: &str,
    challenge: &BackendAuthChallenge,
    signature_b64: &str,
) -> Result<bool, CryptoVaultError> {
    let public_key = decode_fixed_b64::<32>("backend auth public key", public_key_b64)?;
    let signature_bytes = decode_fixed_b64::<64>("backend auth signature", signature_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoVaultError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);

    Ok(verifying_key
        .verify(&challenge.canonical_bytes()?, &signature)
        .is_ok())
}

fn canonical_json_bytes(map: BTreeMap<&'static str, Value>) -> Result<Vec<u8>, CryptoVaultError> {
    serde_json::to_vec(&map).map_err(CryptoVaultError::CanonicalJson)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hkdf_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoVaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoVaultError::InvalidHkdfLength)?;
    Ok(out)
}

fn derive_child(
    root_key: &[u8],
    salt: &[u8],
    label: &str,
    context: &[u8],
) -> Result<[u8; 32], CryptoVaultError> {
    let mut info = format!("verus-notes/{label}/v1").into_bytes();
    info.push(0);
    info.extend_from_slice(context);
    hkdf_32(root_key, salt, &info)
}

fn vault_id_from_seed(seed: &[u8; 32]) -> String {
    let mut data = b"verus-notes/vault-id/v2\0".to_vec();
    data.extend_from_slice(seed);
    encode_b64(&sha256(&data))
}

fn backend_auth_key_id_from_public_key(
    algorithm: &str,
    key_version: u64,
    public_key: &str,
) -> Result<String, CryptoVaultError> {
    let canonical = canonical_json_bytes(BTreeMap::from([
        ("algorithm", json!(algorithm)),
        ("keyVersion", json!(key_version)),
        ("protocol", json!("verus-notes.backend-auth-key-id.v1")),
        ("publicKey", json!(public_key)),
    ]))?;
    Ok(encode_b64(&sha256(&canonical)))
}

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64(name: &'static str, value: &str) -> Result<Vec<u8>, CryptoVaultError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|source| CryptoVaultError::InvalidBase64 { name, source })
}

fn decode_fixed_b64<const N: usize>(
    name: &'static str,
    value: &str,
) -> Result<[u8; N], CryptoVaultError> {
    let bytes = decode_b64(name, value)?;
    fixed_bytes(name, bytes)
}

fn decode_fixed_hex<const N: usize>(
    name: &'static str,
    value: &str,
) -> Result<[u8; N], CryptoVaultError> {
    let bytes =
        hex::decode(value).map_err(|source| CryptoVaultError::InvalidHex { name, source })?;
    fixed_bytes(name, bytes)
}

fn fixed_bytes<const N: usize>(
    name: &'static str,
    bytes: Vec<u8>,
) -> Result<[u8; N], CryptoVaultError> {
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| CryptoVaultError::InvalidLength {
            name,
            expected: N,
            actual,
        })
}

struct Secret32([u8; 32]);

impl Secret32 {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> VaultContext {
        VaultContext {
            app_encryption_address:
                "zs15pu2knhknqn7dfl4u4pdmcsjssu3aqpvzphuakwhftr73k08wh9m0h874uvl76kugrg3qz9rel7"
                    .to_string(),
            app_identity_i_address: "i8LSGzcdqqzcs5XBfSVnXaXTMWt6QYjAuQ".to_string(),
            chain: "VRSCTEST".to_string(),
            derivation_number: 1,
            key_version: 1,
            wallet_signer_identity_i_address: "iLY1eeZKt2HZv6Noeidmg1EFTqaMSLejK5".to_string(),
        }
    }

    fn sample_vault() -> VaultMaterial {
        VaultMaterial::derive([7u8; 32], sample_context(), &[3u8; 16]).unwrap()
    }

    fn sample_header(vault_id: &str) -> CiphertextHeader {
        CiphertextHeader {
            algorithm: "XCHACHA20-POLY1305".to_string(),
            content_version: 1,
            key_version: 1,
            note_id: "note-01".to_string(),
            schema_version: CIPHERTEXT_SCHEMA_VERSION,
            vault_id: vault_id.to_string(),
        }
    }

    fn sample_folder_header(vault_id: &str) -> FolderCiphertextHeader {
        FolderCiphertextHeader {
            algorithm: "XCHACHA20-POLY1305".to_string(),
            content_version: 1,
            folder_id: "my-notes".to_string(),
            key_version: 1,
            schema_version: CIPHERTEXT_SCHEMA_VERSION,
            vault_id: vault_id.to_string(),
        }
    }

    fn sample_note() -> PlaintextNoteDocument {
        PlaintextNoteDocument {
            body_markdown: "first encrypted note".to_string(),
            created_at_ms: 1_779_030_000_000,
            folder_id: "my-notes".to_string(),
            tags: vec!["mvp".to_string()],
            title: "Vault test".to_string(),
            updated_at_ms: 1_779_030_001_000,
        }
    }

    fn sample_folder() -> PlaintextFolderDocument {
        PlaintextFolderDocument {
            created_at_ms: 1_779_030_000_000,
            name: "My notes".to_string(),
            sort_order: 0,
            updated_at_ms: 1_779_030_001_000,
        }
    }

    #[test]
    fn derives_stable_vault_identity_from_same_inputs() {
        let first = sample_vault();
        let second = sample_vault();

        assert_eq!(first.vault_id(), second.vault_id());
        assert_eq!(first.backend_auth_key_id(), second.backend_auth_key_id());
        assert_eq!(
            first.backend_auth_public_key_b64(),
            second.backend_auth_public_key_b64()
        );
        assert_eq!(first.export_check_hash(), second.export_check_hash());
    }

    #[test]
    fn changes_vault_identity_when_context_changes() {
        let first = sample_vault();
        let mut changed_context = sample_context();
        changed_context.derivation_number = 2;
        let changed = VaultMaterial::derive([7u8; 32], changed_context, &[3u8; 16]).unwrap();

        assert_ne!(first.vault_id(), changed.vault_id());
        assert_ne!(
            first.backend_auth_public_key_b64(),
            changed.backend_auth_public_key_b64()
        );
    }

    #[test]
    fn derives_vault_id_separately_from_backend_auth_public_key() {
        let vault = sample_vault();
        let public_key = decode_fixed_b64::<32>(
            "backend auth public key",
            &vault.backend_auth_public_key_b64(),
        )
        .unwrap();
        let legacy_vault_id = {
            let mut data = b"verus-notes/vault-id/v1".to_vec();
            data.extend_from_slice(&public_key);
            encode_b64(&sha256(&data))
        };

        assert_ne!(vault.vault_id(), legacy_vault_id);
        assert_eq!(vault.backend_auth_algorithm(), BACKEND_AUTH_ALGORITHM);
        assert_eq!(vault.backend_auth_key_version(), BACKEND_AUTH_KEY_VERSION);
        assert!(!vault.backend_auth_key_id().is_empty());
    }

    #[test]
    fn encrypts_and_decrypts_note_document() {
        let vault = sample_vault();
        let header = sample_header(vault.vault_id());
        let note = sample_note();
        let encrypted = vault
            .encrypt_note_document(header, &note, [9u8; 24])
            .unwrap();
        let decrypted = vault.decrypt_note_document(&encrypted).unwrap();
        let ciphertext = decode_b64("note ciphertext", &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted, note);
        assert!(PADDED_PLAINTEXT_BUCKETS.contains(&(ciphertext.len() - 16)));
        assert_ne!(
            encrypted.ciphertext.as_bytes(),
            note.body_markdown.as_bytes()
        );
    }

    #[test]
    fn encrypts_and_decrypts_folder_document() {
        let vault = sample_vault();
        let header = sample_folder_header(vault.vault_id());
        let folder = sample_folder();
        let encrypted = vault
            .encrypt_folder_document(header, &folder, [4u8; 24])
            .unwrap();
        let decrypted = vault.decrypt_folder_document(&encrypted).unwrap();

        assert_eq!(decrypted, folder);
        assert_ne!(encrypted.ciphertext.as_bytes(), folder.name.as_bytes());
    }

    #[test]
    fn decrypts_legacy_v1_raw_note_document() {
        let vault = sample_vault();
        let mut header = sample_header(vault.vault_id());
        header.schema_version = 1;
        let note = sample_note();
        let encrypted = vault
            .encrypt_note_document(header, &note, [9u8; 24])
            .unwrap();
        let decrypted = vault.decrypt_note_document(&encrypted).unwrap();
        let ciphertext = decode_b64("legacy note ciphertext", &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted, note);
        assert!(!PADDED_PLAINTEXT_BUCKETS.contains(&(ciphertext.len() - 16)));
    }

    #[test]
    fn encrypts_and_decrypts_note_tombstone() {
        let vault = sample_vault();
        let mut header = sample_header(vault.vault_id());
        header.content_version = 2;
        let encrypted = vault
            .encrypt_note_tombstone(header.clone(), 1_779_030_002_000, [5u8; 24])
            .unwrap();
        let decrypted = vault.decrypt_note_tombstone(&encrypted).unwrap();

        assert_eq!(decrypted.protocol, RECORD_TOMBSTONE_PROTOCOL);
        assert_eq!(decrypted.kind, "note");
        assert_eq!(decrypted.vault_id, header.vault_id);
        assert_eq!(decrypted.record_id, header.note_id);
        assert_eq!(decrypted.content_version, 2);
        assert_eq!(decrypted.deleted_at_ms, 1_779_030_002_000);
    }

    #[test]
    fn encrypts_and_decrypts_folder_tombstone() {
        let vault = sample_vault();
        let mut header = sample_folder_header(vault.vault_id());
        header.content_version = 2;
        let encrypted = vault
            .encrypt_folder_tombstone(header.clone(), 1_779_030_002_000, [6u8; 24])
            .unwrap();
        let decrypted = vault.decrypt_folder_tombstone(&encrypted).unwrap();

        assert_eq!(decrypted.protocol, RECORD_TOMBSTONE_PROTOCOL);
        assert_eq!(decrypted.kind, "folder");
        assert_eq!(decrypted.vault_id, header.vault_id);
        assert_eq!(decrypted.record_id, header.folder_id);
        assert_eq!(decrypted.content_version, 2);
        assert_eq!(decrypted.deleted_at_ms, 1_779_030_002_000);
    }

    #[test]
    fn rejects_tampered_note_tombstone_binding() {
        let vault = sample_vault();
        let mut header = sample_header(vault.vault_id());
        header.content_version = 2;
        let encrypted = vault
            .encrypt_note_tombstone(header, 1_779_030_002_000, [5u8; 24])
            .unwrap();

        let mut tampered_header = encrypted.clone();
        tampered_header.header.note_id = "other-note".to_string();
        assert!(vault.decrypt_note_tombstone(&tampered_header).is_err());

        let mut tampered_ciphertext = encrypted.clone();
        tampered_ciphertext.ciphertext = "not-a-valid-ciphertext".to_string();
        assert!(vault.decrypt_note_tombstone(&tampered_ciphertext).is_err());
    }

    #[test]
    fn rejects_tampered_folder_tombstone_binding() {
        let vault = sample_vault();
        let mut header = sample_folder_header(vault.vault_id());
        header.content_version = 2;
        let encrypted = vault
            .encrypt_folder_tombstone(header, 1_779_030_002_000, [6u8; 24])
            .unwrap();

        let mut tampered_header = encrypted.clone();
        tampered_header.header.content_version = 3;
        assert!(vault.decrypt_folder_tombstone(&tampered_header).is_err());

        let mut tampered_nonce = encrypted.clone();
        tampered_nonce.nonce = "bad-nonce".to_string();
        assert!(vault.decrypt_folder_tombstone(&tampered_nonce).is_err());
    }

    #[test]
    fn defaults_legacy_notes_to_my_notes_folder() {
        let legacy = serde_json::from_value::<PlaintextNoteDocument>(json!({
            "bodyMarkdown": "legacy encrypted note",
            "createdAtMs": 1_779_030_000_000u64,
            "tags": [],
            "title": "Legacy",
            "updatedAtMs": 1_779_030_001_000u64
        }))
        .unwrap();

        assert_eq!(legacy.folder_id, "my-notes");
    }

    #[test]
    fn rejects_tampered_header_aad() {
        let vault = sample_vault();
        let header = sample_header(vault.vault_id());
        let note = sample_note();
        let mut encrypted = vault
            .encrypt_note_document(header, &note, [9u8; 24])
            .unwrap();
        encrypted.header.content_version = 2;

        assert!(matches!(
            vault.decrypt_note_document(&encrypted),
            Err(CryptoVaultError::Decrypt)
        ));
    }

    #[test]
    fn signs_and_verifies_backend_auth_challenge() {
        let vault = sample_vault();
        let context = sample_context();
        let challenge = BackendAuthChallenge {
            app_encryption_request_id: "verus-notes-a4af90ff2565654a8afb753e5c56a69c".to_string(),
            app_identity_i_address: context.app_identity_i_address,
            backend_auth_algorithm: vault.backend_auth_algorithm().to_string(),
            backend_auth_key_id: vault.backend_auth_key_id().to_string(),
            backend_auth_public_key: vault.backend_auth_public_key_b64(),
            backend_auth_key_version: vault.backend_auth_key_version(),
            challenge: "challenge-bytes".to_string(),
            derivation_number: context.derivation_number,
            expires_at_ms: 1_779_030_600_000,
            session_id: "session-01".to_string(),
            vault_id: vault.vault_id().to_string(),
            wallet_signer_identity_i_address: context.wallet_signer_identity_i_address,
        };
        let signature = vault.sign_backend_challenge(&challenge).unwrap();

        assert!(verify_backend_challenge_signature(
            &vault.backend_auth_public_key_b64(),
            &challenge,
            &signature
        )
        .unwrap());

        let mut tampered = challenge;
        tampered.session_id = "session-02".to_string();
        assert!(!verify_backend_challenge_signature(
            &vault.backend_auth_public_key_b64(),
            &tampered,
            &signature
        )
        .unwrap());
    }

    #[test]
    fn rejects_wrong_ivk_length() {
        let err = decode_32_hex("incoming viewing key", "abcd").unwrap_err();

        assert!(matches!(
            err,
            CryptoVaultError::InvalidLength {
                name: "incoming viewing key",
                expected: 32,
                actual: 2
            }
        ));
    }
}
