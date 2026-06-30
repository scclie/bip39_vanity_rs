use bitcoin::address::KnownHrp;
use bitcoin::bech32::{segwit, Hrp};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, Network, PubkeyHash};

use crate::wallet::Wallet;

// --- BIP84 Native SegWit bech32 ---

pub struct Bech32 {
    display_name: String,
    hrp: String,
    coin_type: u32,
    valid: String,
    addr_prefix: String,
}

impl Bech32 {
    pub fn new(hrp: &str, coin_type: u32) -> Self {
        let display_name = match hrp {
            "bc" => "bitcoin".to_string(),
            "ltc" => "litecoin".to_string(),
            _ => format!("bech32({})", hrp),
        };
        let valid = format!("{}1qpzry9x8gf2tvdw0s3jn54khce6mua7l", hrp);
        let addr_prefix = format!("{}1q", hrp);
        Bech32 { display_name, hrp: hrp.to_string(), coin_type, valid, addr_prefix }
    }
}

impl Wallet for Bech32 {
    fn name(&self) -> &str { &self.display_name }
    fn derive_address(&self, seed: &[u8]) -> Option<String> { derive_bech32(seed, self.coin_type, &self.hrp) }
    fn valid_chars(&self) -> &str { &self.valid }
    fn address_prefix(&self) -> &str { &self.addr_prefix }
    fn verify_address(&self, address: &str) -> bool {
        if !address.starts_with(&self.addr_prefix) { return false; }
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

// --- Base58 P2SH-P2WPKH (BIP49) and P2PKH (BIP44) for BTC/LTC ---

const BASE58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub struct BtcBase58 {
    display_name: &'static str,
    coin_type: u32,
    is_p2sh: bool,
}

pub struct LtcBase58 {
    display_name: &'static str,
    coin_type: u32,
    is_p2sh: bool,
}

impl BtcBase58 {
    pub fn new(is_p2sh: bool) -> Self {
        BtcBase58 {
            display_name: if is_p2sh { "bitcoin (P2SH)" } else { "bitcoin (legacy)" },
            coin_type: 0,
            is_p2sh,
        }
    }
}

impl LtcBase58 {
    pub fn new(is_p2sh: bool) -> Self {
        LtcBase58 {
            display_name: if is_p2sh { "litecoin (P2SH)" } else { "litecoin (legacy)" },
            coin_type: 2,
            is_p2sh,
        }
    }
}

impl Wallet for BtcBase58 {
    fn name(&self) -> &str { self.display_name }
    fn derive_address(&self, seed: &[u8]) -> Option<String> {
        derive_btc_base58(seed, self.coin_type, self.is_p2sh)
    }
    fn valid_chars(&self) -> &str { BASE58_CHARS }
    fn address_prefix(&self) -> &str { if self.is_p2sh { "3" } else { "1" } }
    fn verify_address(&self, address: &str) -> bool {
        use bitcoin::address::NetworkUnchecked;
        use std::str::FromStr;
        bitcoin::Address::<NetworkUnchecked>::from_str(address).is_ok()
    }
}

impl Wallet for LtcBase58 {
    fn name(&self) -> &str { self.display_name }
    fn derive_address(&self, seed: &[u8]) -> Option<String> {
        derive_ltc_base58(seed, self.coin_type, self.is_p2sh)
    }
    fn valid_chars(&self) -> &str { BASE58_CHARS }
    fn address_prefix(&self) -> &str { if self.is_p2sh { "m" } else { "l" } }
    fn verify_address(&self, address: &str) -> bool {
        let prefix = if self.is_p2sh { 'M' } else { 'L' };
        if !address.starts_with(prefix) { return false; }
        if address.len() < 26 || address.len() > 35 { return false; }
        address.bytes().all(|c| BASE58_CHARS.as_bytes().contains(&c))
    }
}

fn derive_key(seed: &[u8], coin_type: u32, path_tmpl: &str) -> Option<CompressedPublicKey> {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).ok()?;
    let path: DerivationPath = format!("{path_tmpl}{coin_type}'/0'/0/0").parse().ok()?;
    let child = root.derive_priv(&secp, &path).ok()?;
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    let public_key = private_key.public_key(&secp);
    CompressedPublicKey::try_from(public_key).ok()
}

fn derive_btc_base58(seed: &[u8], coin_type: u32, is_p2sh: bool) -> Option<String> {
    let compressed = derive_key(seed, coin_type, if is_p2sh { "m/49'/" } else { "m/44'/" })?;
    if is_p2sh {
        Some(bitcoin::Address::p2shwpkh(&compressed, Network::Bitcoin).to_string())
    } else {
        Some(bitcoin::Address::p2pkh(&compressed, Network::Bitcoin).to_string())
    }
}

fn derive_ltc_base58(seed: &[u8], coin_type: u32, is_p2sh: bool) -> Option<String> {
    let compressed = derive_key(seed, coin_type, if is_p2sh { "m/49'/" } else { "m/44'/" })?;
    let pk_hash: PubkeyHash = compressed.into();
    let hash160 = pk_hash.to_byte_array();

    if is_p2sh {
        let redeem = build_p2wpkh_redeem_script(&hash160);
        let script_hash = hash160_bytes(&redeem);
        Some(base58check_encode(&script_hash, 0x32))
    } else {
        Some(base58check_encode(&hash160, 0x30))
    }
}

fn build_p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash);
    script
}

fn hash160_bytes(data: &[u8]) -> [u8; 20] {
    let h = PubkeyHash::hash(data);
    h.to_byte_array()
}

fn base58check_encode(data: &[u8], version: u8) -> String {
    let mut payload = Vec::with_capacity(data.len() + 5);
    payload.push(version);
    payload.extend_from_slice(data);
    let checksum = double_sha256_first4(&payload);
    payload.extend_from_slice(&checksum);
    base58_encode(&payload)
}

fn double_sha256_first4(data: &[u8]) -> [u8; 4] {
    let h1 = Sha256::hash(data);
    let h2 = Sha256::hash(h1.as_byte_array());
    let bytes = h2.to_byte_array();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn base58_encode(data: &[u8]) -> String {
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let leading = data.iter().take_while(|&&b| b == 0).count();
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
    for _ in 0..leading { result.push('1'); }
    for d in digits.iter().rev() { result.push(ALPH[*d as usize] as char); }
    result
}
