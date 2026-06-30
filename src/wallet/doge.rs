use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, Network, PubkeyHash};

use crate::wallet::Wallet;

pub struct Doge;

impl Wallet for Doge {
    fn name(&self) -> &str { "dogecoin" }

    fn derive_address(&self, seed: &[u8]) -> Option<String> {
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).ok()?;
        let path: DerivationPath = "m/44'/3'/0'/0/0".parse().ok()?;
        let child = root.derive_priv(&secp, &path).ok()?;
        let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
        let public_key = private_key.public_key(&secp);
        let compressed = CompressedPublicKey::try_from(public_key).ok()?;

        let pk_hash: PubkeyHash = compressed.into();
        let hash160 = pk_hash.to_byte_array();

        let mut payload = Vec::with_capacity(25);
        payload.push(0x1e);
        payload.extend_from_slice(&hash160);

        let checksum = double_sha256_first4(&payload);
        payload.extend_from_slice(&checksum);

        Some(base58_encode(&payload))
    }

    fn valid_chars(&self) -> &str {
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    }

    fn address_prefix(&self) -> &str { "d" }

    fn verify_address(&self, address: &str) -> bool {
        verify_base58check(address)
    }
}

fn double_sha256_first4(data: &[u8]) -> [u8; 4] {
    let h1 = Sha256::hash(data);
    let h2 = Sha256::hash(h1.as_byte_array());
    let bytes = h2.to_byte_array();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn verify_base58check(address: &str) -> bool {
    const ALPH: &[u8]= b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if !address.starts_with('D') { return false; }
    if address.len() < 27 || address.len() > 34 { return false; }
    address.bytes().all(|c| ALPH.contains(&c))
}

fn base58_encode(data: &[u8]) -> String {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut leading = 0usize;
    for &b in data {
        if b == 0 { leading += 1; } else { break; }
    }

    let mut digits = Vec::new();
    for &b in &data[leading..] {
        let mut carry = b as u32;
        for d in &mut digits {
            carry += *d as u32 * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::new();
    for _ in 0..leading {
        result.push('1');
    }
    for d in digits.iter().rev() {
        result.push(ALPH[*d as usize] as char);
    }
    result
}
