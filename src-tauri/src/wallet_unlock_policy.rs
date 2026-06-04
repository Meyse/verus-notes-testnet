#[derive(Clone, Copy, Debug)]
pub struct WalletUnlockPolicy {
    pub signer_base_url: &'static str,
    pub callback_base_url: &'static str,
    pub chain: &'static str,
    pub app_identity_i_address: &'static str,
    pub derivation_number: u64,
    pub key_version: u64,
}

pub fn active_wallet_unlock_policy() -> WalletUnlockPolicy {
    WalletUnlockPolicy {
        signer_base_url: env!(
            "VERUS_NOTES_SIGNER_BASE_URL",
            "VERUS_NOTES_SIGNER_BASE_URL must be configured at build time",
        ),
        callback_base_url: env!(
            "VERUS_NOTES_CALLBACK_BASE_URL",
            "VERUS_NOTES_CALLBACK_BASE_URL must be configured at build time",
        ),
        chain: "VRSCTEST",
        app_identity_i_address: "iPEdLctTcVvfRCSN4Zjrc2H1ueDa2JmiEx",
        derivation_number: 1,
        key_version: 1,
    }
}
