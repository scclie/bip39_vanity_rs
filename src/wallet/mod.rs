pub mod bech32;
pub mod doge;
pub mod evm;

use std::sync::Arc;

pub trait Wallet: Send + Sync {
    fn name(&self) -> &str;
    fn derive_address(&self, seed: &[u8]) -> Option<String>;
    fn valid_chars(&self) -> &str;
    fn verify_address(&self, address: &str) -> bool;

    fn validate_pattern(&self, pattern: &str) -> Result<(), Vec<char>> {
        let valid = self.valid_chars();
        let bad: Vec<char> = pattern.chars().filter(|c| !valid.contains(*c)).collect();
        if bad.is_empty() { Ok(()) } else { Err(bad) }
    }
}

impl dyn Wallet {
    pub fn derive_from_phrase(&self, phrase: &str) -> Option<String> {
        let Ok(mnemonic) = phrase.parse::<bip39::Mnemonic>() else { return None; };
        let seed = mnemonic.to_seed_normalized("");
        self.derive_address(&seed)
    }
}

pub fn by_name(name: &str) -> Option<Arc<dyn Wallet>> {
    match name.to_lowercase().as_str() {
        "btc" | "bitcoin" => Some(Arc::new(bech32::Btc)),
        "ltc" | "litecoin" => Some(Arc::new(bech32::Ltc)),
        "eth" | "evm" | "ethereum" => Some(Arc::new(evm::Evm)),
        "doge" | "dogecoin" => Some(Arc::new(doge::Doge)),
        _ => None,
    }
}
