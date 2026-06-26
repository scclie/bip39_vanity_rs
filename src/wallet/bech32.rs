use bitcoin::address::KnownHrp;
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
        bech32_encode(hrp, &bytes)
    };
    Some(addr)
}

// Bech32 encoding (BIP-0173).
// The alphabet omits ambiguous characters (1/l/i, 0/o) to minimize errors in manual entry.
// All characters are lowercase; the checksum uses a BCH code.
fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    const ALPH: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const M: u32 = 0x2bc830a3;

    let mut values: Vec<u32> = Vec::new();
    for &b in hrp.as_bytes() {
        values.push((b >> 5) as u32);
    }
    values.push(0);
    for &b in hrp.as_bytes() {
        values.push((b & 31) as u32);
    }

    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut fived: Vec<u32> = vec![0];
    for &v in data {
        acc = (acc << 8) | (v as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            fived.push((acc >> bits) & 31);
            acc &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        fived.push((acc << (5 - bits)) & 31);
    }

    values.extend(&fived);
    values.extend(&[0u32; 6]);

    let mut chk = 1u32;
    for &v in &values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for i in 0..5 {
            chk ^= if (top >> i) & 1 != 0 { GEN[i] } else { 0 };
        }
    }
    let polymod = chk ^ M;

    for i in 0..6 {
        fived.push((polymod >> (5 * (5 - i))) & 31);
    }

    let mut addr = hrp.to_string() + "1";
    for &d in &fived {
        addr.push(ALPH[d as usize] as char);
    }
    addr
}
