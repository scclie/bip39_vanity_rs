use bitcoin::address::KnownHrp;
use bitcoin::bech32::{segwit, Hrp};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, Network, PubkeyHash};

use crate::wallet::Wallet;

pub struct Btc;
pub struct Ltc;

impl Wallet for Btc {
    fn name(&self) -> &str { "bitcoin" }
    fn derive_address(&self, seed: &[u8]) -> Option<String> { derive_bech32(seed, 0, "bc") }
    fn valid_chars(&self) -> &str { "bc1qpzry9x8gf2tvdw0s3jn54khce6mua7l" }
    fn verify_address(&self, address: &str) -> bool {
        use bitcoin::address::NetworkUnchecked;
        use std::str::FromStr;
        bitcoin::Address::<NetworkUnchecked>::from_str(address).is_ok()
    }
}

impl Wallet for Ltc {
    fn name(&self) -> &str { "litecoin" }
    fn derive_address(&self, seed: &[u8]) -> Option<String> { derive_bech32(seed, 2, "ltc") }
    fn valid_chars(&self) -> &str { "ltc1qpzry9x8gf2tvdw0s3jn54khce6mua7l" }
    fn verify_address(&self, address: &str) -> bool {
        // Bech32 structure: hrp + "1" + data + checksum
        if !address.starts_with("ltc1q") { return false; }
        let Some((_, data)) = address.rsplit_once('1') else { return false; };
        if data.len() < 6 { return false; }
        let chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        data.chars().all(|c| chars.contains(c))
    }
}

fn derive_bech32(seed: &[u8], coin_type: u32, hrp: &str) -> Option<String> {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).ok()?;
    let path: DerivationPath = format!("m/84'/{coin_type}'/0'/0/0").parse().ok()?;
    let child = root.derive_priv(&secp, &path).ok()?;
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    let public_key = private_key.public_key(&secp);
    let compressed = CompressedPublicKey::try_from(public_key).ok()?;

    let addr = if hrp == "bc" {
        bitcoin::Address::p2wpkh(&compressed, KnownHrp::Mainnet).to_string()
    } else {
        let hash: PubkeyHash = compressed.into();
        let bytes = hash.to_byte_array();
        let hrp = Hrp::parse(hrp).ok()?;
        segwit::encode_v0(hrp, &bytes).ok()?
    };
    Some(addr)
}
