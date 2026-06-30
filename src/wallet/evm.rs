use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use tiny_keccak::{Hasher, Keccak};

use crate::wallet::Wallet;

pub struct Evm;

impl Wallet for Evm {
    fn name(&self) -> &str { "evm" }

    fn derive_address(&self, seed: &[u8]) -> Option<String> {
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).ok()?;
        let path: DerivationPath = "m/44'/60'/0'/0/0".parse().ok()?;
        let child = root.derive_priv(&secp, &path).ok()?;
        let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
        let public_key = private_key.public_key(&secp);

        let uncomp = public_key.inner.serialize_uncompressed();
        let xy = &uncomp[1..];

        let mut keccak = Keccak::v256();
        keccak.update(xy);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        Some(format!("0x{}", hex_encode(&hash[12..])))
    }

    fn valid_chars(&self) -> &str { "0x0123456789abcdef" }
    fn address_prefix(&self) -> &str { "0x" }

    fn verify_address(&self, address: &str) -> bool {
        let addr = address.strip_prefix("0x").unwrap_or(address);
        addr.len() == 40 && addr.chars().all(|c| c.is_ascii_hexdigit())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
