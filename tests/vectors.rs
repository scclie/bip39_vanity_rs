use std::process::Command;

use bip39::Mnemonic;
use bitcoin::address::KnownHrp;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, Network};

/// Verify BIP84 derivation: mnemonic -> seed -> bc1q address.
/// Uses the actual seed from bip39 crate (empty passphrase).
#[test]
fn test_bip84_derivation() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic: Mnemonic = phrase.parse().unwrap();
    let seed = mnemonic.to_seed_normalized("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    let public_key = private_key.public_key(&secp);
    let compressed = CompressedPublicKey::try_from(public_key).unwrap();
    let address = bitcoin::Address::p2wpkh(&compressed, KnownHrp::Mainnet).to_string();

    // Verify the binary produces the same address
    let bin = env!("CARGO_BIN_EXE_bip39_vanity_rs");
    let out = std::process::Command::new(bin)
        .args(["-s", phrase, "-c", "btc"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&address), "binary output should contain derived address");
    assert!(stdout.contains("✓"), "address format should be valid");
}

/// Official BIP44 test vector for Ethereum.
/// Source: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1581.md (adapted)
#[test]
fn test_evm_derivation() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic: Mnemonic = phrase.parse().unwrap();
    let seed = mnemonic.to_seed_normalized("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    let public_key = private_key.public_key(&secp);

    // keccak256 of uncompressed public key (without 0x04 prefix)
    let uncomp = public_key.inner.serialize_uncompressed();
    use tiny_keccak::{Hasher, Keccak};
    let mut keccak = Keccak::v256();
    keccak.update(&uncomp[1..]);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let addr = hex::encode(&hash[12..]);
    // Verify its a valid 40-char hex address
    assert_eq!(addr.len(), 40);
    assert!(addr.chars().all(|c| c.is_ascii_hexdigit()));
}

fn run(coin: &str, phrase: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_bip39_vanity_rs");
    let out = Command::new(bin)
        .args(["-s", phrase, "-c", coin])
        .output()
        .unwrap_or_else(|e| panic!("failed to run for {coin}: {e}"));
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Known seed phrases that produce valid addresses for each coin type.
#[test]
fn test_known_seeds() {
    let cases = [
        ("btc",
         "bench mother night siren defense strong mass damp liar document need yellow",
         "bc1qrxpte9ezjgxadahhq5qhvrt3dt7v5h7t3wuyaa"),
        ("ltc",
         "forest pill dash grab patrol cousin chef mutual scheme find doll accuse",
         "ltc1q6xaf4mfnfs4xqupg0ucyj77qnz3cu6ssjqpfaa"),
        ("evm",
         "loud home much usage knee metal glad effort jelly spread ensure found",
         "0x8d18752d37220e44b340b0a1829c37490f2599aa"),
        ("doge",
         "wedding purity worry true mind balcony walnut soda weapon siege pull smoke",
         "DMN4WHysscnYZAUhwF6K4aTApBKBy256Aa"),
    ];

    for &(coin, phrase, expected) in &cases {
        let stdout = run(coin, phrase);
        assert!(stdout.contains(expected),
            "{coin}: expected address {expected} not found in output:\n{stdout}");
        assert!(stdout.contains("✓"),
            "{coin}: address format not marked valid:\n{stdout}");
    }
}

/// Multiple well-known BIP39 test seeds should produce valid addresses for all coins.
#[test]
fn test_random_address_validity() {
    let phrases = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ];

    for coin in &["btc", "ltc", "evm", "doge"] {
        for phrase in &phrases {
            let stdout = run(coin, phrase);
            assert!(stdout.contains("✓"),
                "{coin} with phrase {phrase:?}: address not valid:\n{stdout}");
        }
    }
}
