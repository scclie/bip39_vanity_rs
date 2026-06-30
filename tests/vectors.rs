use std::process::Command;

use bip39::Mnemonic;
use bitcoin::address::KnownHrp;
use bitcoin::bech32::{segwit, Hrp};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, Network, PubkeyHash};
use tiny_keccak::{Hasher, Keccak};

use bip39_vanity_rs::search::wildcard_match;

// ============================================================
//  wildcard_match unit tests
// ============================================================

#[test]
fn match_contains_substring() {
    assert!(wildcard_match("abc123", "c12"));
    assert!(!wildcard_match("abc123", "x"));
}

#[test]
fn match_prefix() {
    assert!(wildcard_match("abc123", "abc*"));
    assert!(!wildcard_match("abc123", "xyz*"));
}

#[test]
fn match_suffix() {
    assert!(wildcard_match("abc123", "*123"));
    assert!(!wildcard_match("abc123", "*xyz"));
}

#[test]
fn match_prefix_and_suffix() {
    assert!(wildcard_match("abc123xyz", "abc*xyz"));
    assert!(!wildcard_match("abc123xyz", "abc*abc"));
}

#[test]
fn match_exact() {
    assert!(wildcard_match("abc", "abc"));
    assert!(!wildcard_match("abc", "abcd"));
}

#[test]
fn match_empty_or_wildcard_only() {
    assert!(wildcard_match("anything", ""));
    assert!(wildcard_match("anything", "*"));
}

#[test]
fn match_multi_segment() {
    assert!(wildcard_match("ab-cd-ef", "ab*cd*ef"));
    assert!(!wildcard_match("ab-cd-ef", "ab*xy*ef"));
}

#[test]
fn match_double_wildcard() {
    assert!(wildcard_match("abc123", "*c1*"));
    assert!(wildcard_match("abc123", "*abc*"));
}

// ============================================================
//  Pattern validation via CLI
// ============================================================

#[test]
fn reject_impossible_prefix_btc_segwit() {
    let out = run_bin(&["-c", "btc", "0xdead*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected failure, got success");
    assert!(stderr.contains("can never match"), "stderr: {stderr}");
    assert!(stderr.contains("bc1q"), "should hint at prefix bc1q");
}

#[test]
fn reject_impossible_prefix_btc_p2sh() {
    let out = run_bin(&["-c", "btc", "-a", "p2sh", "1abc*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("can never match"));
}

#[test]
fn reject_impossible_prefix_btc_legacy() {
    let out = run_bin(&["-c", "btc", "-a", "legacy", "3abc*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("can never match"));
}

#[test]
fn reject_impossible_prefix_evm() {
    let out = run_bin(&["-c", "evm", "dead*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("can never match"));
    assert!(stderr.contains("0x"));
}

#[test]
fn reject_impossible_prefix_doge() {
    let out = run_bin(&["-c", "doge", "Xdead*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("can never match"));
}

#[test]
fn accept_valid_prefix_btc_segwit() {
    let out = run_bin(&["-c", "btc", "bc1qa*"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

// ============================================================
//  Error paths
// ============================================================

#[test]
fn reject_invalid_seed_phrase() {
    let out = run_bin(&["-s", "not a valid seed phrase", "-c", "btc"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("Invalid seed phrase"));
}

#[test]
fn reject_invalid_chars_bech32() {
    let out = run_bin(&["-c", "btc", "i*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("can never appear"), "stderr: {stderr}");
}

#[test]
fn reject_unknown_addr_type() {
    let out = run_bin(&["-c", "btc", "-a", "foo", "abc*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("Unknown coin or address type"));
}

// ============================================================
//  Custom HRP (testnet, regtest)
// ============================================================

#[test]
fn custom_hrp_tb_btc() {
    let out = run_bin(&[
        "-c", "btc", "--hrp", "tb", "-s",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tb1q"), "expected testnet address, got: {stdout}");
    assert!(stdout.contains("✓"), "address should be valid: {stdout}");
}

#[test]
fn custom_hrp_bcrt_btc() {
    let out = run_bin(&[
        "-c", "btc", "--hrp", "bcrt", "-s",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("Coin:"), "unexpected output: {stdout}");
    let addr_line = stdout.lines().find(|l| l.starts_with("Address:")).unwrap();
    assert!(addr_line.contains("bcrt1q"), "expected regtest address, got: {stdout}");
}

#[test]
fn custom_hrp_ltc_testnet() {
    let out = run_bin(&[
        "-c", "ltc", "--hrp", "tltc", "-s",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let addr_line = stdout.lines().find(|l| l.starts_with("Address:")).unwrap();
    assert!(addr_line.contains("tltc1q"), "expected ltc testnet, got: {stdout}");
}

// ============================================================
//  Derivation tests (existing)
// ============================================================

fn derive_key(seed: &[u8], path: &str) -> CompressedPublicKey {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = path.parse().unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    let public_key = private_key.public_key(&secp);
    CompressedPublicKey::try_from(public_key).unwrap()
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

fn base58check_encode(data: &[u8], version: u8) -> String {
    let mut payload = Vec::with_capacity(data.len() + 5);
    payload.push(version);
    payload.extend_from_slice(data);
    let checksum = double_sha256_first4(&payload);
    payload.extend_from_slice(&checksum);
    base58_encode(&payload)
}

fn run(coin: &str, addr_type: &str, phrase: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_bip39_vanity_rs");
    let out = Command::new(bin)
        .args(["-s", phrase, "-c", coin, "-a", addr_type])
        .output()
        .unwrap_or_else(|e| panic!("failed to run for {coin} {addr_type}: {e}"));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn run_bin(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_bip39_vanity_rs");
    Command::new(bin).args(args).output().unwrap()
}

fn get_address(coin: &str, addr_type: &str, phrase: &str) -> String {
    let stdout = run(coin, addr_type, phrase);
    for line in stdout.lines() {
        if let Some(addr) = line.strip_prefix("Address:  ") {
            return addr.to_string();
        }
    }
    panic!("no Address line in output:\n{stdout}");
}

struct Case {
    coin: &'static str,
    addr_type: &'static str,
    phrase: &'static str,
    address: &'static str,
}

const SUFFIX_CASES: &[Case] = &[
    Case { coin: "btc", addr_type: "segwit", phrase: "clinic betray laugh catch peanut act parent cousin clump suffer squirrel ski", address: "bc1qm8dlqk06mfnyyc5dp7x0580cq626wcxxs4pcaa" },
    Case { coin: "btc", addr_type: "p2sh",   phrase: "winner cause trap cherry chef wave cream display paddle horn light vanish", address: "3JXBxKWY5UuaTWYpvBNBrGmjveHf35QBaA" },
    Case { coin: "btc", addr_type: "legacy", phrase: "unknown post cute sweet photo spin secret cereal bundle satoshi bulk soda", address: "1HNZtD2FxgfkMPk7omNog3NfMnfyjz5Haa" },
    Case { coin: "ltc", addr_type: "segwit", phrase: "hope where win kind fitness obey board jar wealth rescue soft acoustic", address: "ltc1qydxj4lyeq6rqqs8k8q59dxgthz26jfffm5r2aa" },
    Case { coin: "ltc", addr_type: "p2sh",   phrase: "level choose slight process jazz rely lemon dwarf cattle finish erupt wing", address: "MR4ZupNrk58rRZeYY4SRCZSGs6GiW4iNAa" },
    Case { coin: "ltc", addr_type: "legacy", phrase: "reform device until raven wasp extra faith issue gain clarify refuse coffee", address: "Lcc6DZuqUFoZWNzKbFwWV7R2GBeZ5gauAA" },
    Case { coin: "evm", addr_type: "segwit", phrase: "curve frequent urge hair leopard spin timber jazz urge side update share", address: "0xc9d8568e1c2263eedd996032557cb43ddc1ce0aa" },
    Case { coin: "doge", addr_type: "segwit", phrase: "image fetch apart oppose blood powder budget fashion zoo square fire course", address: "DEbuWrFE73BuAP8G6fiz7Udk5zFkD49JAA" },
];

const PREFIX_CASES: &[Case] = &[
    Case { coin: "btc", addr_type: "segwit", phrase: "illegal curve swap report gallery alley shrimp youth receive begin attract fly", address: "bc1qaz2dn9ttfskhwfqwg8385auslc3unf5wwcze4k" },
    Case { coin: "btc", addr_type: "p2sh",   phrase: "speak travel neglect pear cabbage pink vast ignore congress wagon scale boss", address: "3AGKSo1RanLUjSVwXWAnhqiXSNBYEdaRB4" },
    Case { coin: "btc", addr_type: "legacy", phrase: "practice wreck wall pelican alarm cake stadium ship length short lunar sniff", address: "1AyUf7PxrVhSzc7Uh5zdLKnn7aSNZCMsNn" },
    Case { coin: "ltc", addr_type: "segwit", phrase: "cash arrest rare calm same adjust stomach area twenty mass absorb rifle", address: "ltc1qacdqddaxzl0yuacqrgpu6hnh2zhac2xlny3zdk" },
    Case { coin: "ltc", addr_type: "p2sh",   phrase: "spray square drill chuckle prevent impact walk page small allow happy senior", address: "MAbeaDCqWFHV2DG8JWkWbKHW8BepPXkJNQ" },
    Case { coin: "ltc", addr_type: "legacy", phrase: "insect shoe drama sentence close evoke gaze trial false solution exercise jungle", address: "La74UqiBPyquzf1xmXvhV8nxzuAELx8dmz" },
    Case { coin: "evm", addr_type: "segwit", phrase: "another shallow east there canoe much matrix sense proof logic perfect depth", address: "0xaaaa6fff901f29e59b904df0d9a2b1c2b70ade30" },
    Case { coin: "doge", addr_type: "segwit", phrase: "true festival champion dolphin organ rather scheme vocal clip feel razor hand", address: "DAAhozUb7VVtJmvt3MY4dPuMsZbLe3fABL" },
];

#[test]
fn test_suffix_derivation() {
    for c in SUFFIX_CASES {
        let got = get_address(c.coin, c.addr_type, c.phrase);
        assert_eq!(got, c.address, "{} {} suffix: expected {}, got {}",
            c.coin, c.addr_type, c.address, got);
        let lower = got.to_lowercase();
        assert!(lower.ends_with("aa"),
            "{} {} address {} does not end with 'aa'", c.coin, c.addr_type, got);
    }
}

#[test]
fn test_prefix_derivation() {
    for c in PREFIX_CASES {
        let got = get_address(c.coin, c.addr_type, c.phrase);
        assert_eq!(got, c.address, "{} {} prefix: expected {}, got {}",
            c.coin, c.addr_type, c.address, got);
        let lower = got.to_lowercase();
        let prefix = coin_prefix(c.coin, c.addr_type);
        assert!(lower.starts_with(&prefix),
            "{} {} address {} does not start with '{}'", c.coin, c.addr_type, got, prefix);
    }
}

fn coin_prefix(coin: &str, addr_type: &str) -> &'static str {
    match (coin, addr_type) {
        ("btc", "segwit") => "bc1qa",
        ("btc", "p2sh")   => "3a",
        ("btc", "legacy") => "1a",
        ("ltc", "segwit") => "ltc1qa",
        ("ltc", "p2sh")   => "ma",
        ("ltc", "legacy") => "la",
        ("evm", _)        => "0xa",
        ("doge", _)       => "da",
        _ => panic!("unknown {coin} {addr_type}"),
    }
}

#[test]
fn test_derivation_matches_binary() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic: Mnemonic = phrase.parse().unwrap();
    let seed = mnemonic.to_seed_normalized("");

    // BTC segwit (BIP84 m/84'/0'/0'/0/0)
    let pk84 = derive_key(&seed, "m/84'/0'/0'/0/0");
    let btc_segwit = bitcoin::Address::p2wpkh(&pk84, KnownHrp::Mainnet).to_string();
    assert!(run("btc", "segwit", phrase).contains(&btc_segwit));

    // BTC p2sh (BIP49 m/49'/0'/0'/0/0)
    let pk49 = derive_key(&seed, "m/49'/0'/0'/0/0");
    let btc_p2sh = bitcoin::Address::p2shwpkh(&pk49, Network::Bitcoin).to_string();
    assert!(run("btc", "p2sh", phrase).contains(&btc_p2sh));

    // BTC legacy (BIP44 m/44'/0'/0'/0/0)
    let pk44 = derive_key(&seed, "m/44'/0'/0'/0/0");
    let btc_legacy = bitcoin::Address::p2pkh(&pk44, Network::Bitcoin).to_string();
    assert!(run("btc", "legacy", phrase).contains(&btc_legacy));

    // LTC segwit (BIP84 m/84'/2'/0'/0/0)
    let pk = derive_key(&seed, "m/84'/2'/0'/0/0");
    let hash: PubkeyHash = pk.into();
    let ltc_segwit = segwit::encode_v0(Hrp::parse("ltc").unwrap(), &hash.to_byte_array()).unwrap();
    assert!(run("ltc", "segwit", phrase).contains(&ltc_segwit));

    // LTC p2sh (BIP49 m/49'/2'/0'/0/0)
    let pk = derive_key(&seed, "m/49'/2'/0'/0/0");
    let hash160: PubkeyHash = pk.into();
    let redeem = build_p2wpkh_redeem_script(&hash160.to_byte_array());
    let script_hash = pubkey_hash_bytes(&redeem);
    let ltc_p2sh = base58check_encode(&script_hash, 0x32);
    assert!(run("ltc", "p2sh", phrase).contains(&ltc_p2sh));

    // LTC legacy (BIP44 m/44'/2'/0'/0/0)
    let pk = derive_key(&seed, "m/44'/2'/0'/0/0");
    let hash160: PubkeyHash = pk.into();
    let ltc_legacy = base58check_encode(&hash160.to_byte_array(), 0x30);
    assert!(run("ltc", "legacy", phrase).contains(&ltc_legacy));

    // EVM (BIP44 m/44'/60'/0'/0/0)
    let pubkey = derive_pubkey(&seed, "m/44'/60'/0'/0/0");
    let uncomp = pubkey.inner.serialize_uncompressed();
    let xy = &uncomp[1..];
    let mut keccak = Keccak::v256();
    keccak.update(xy);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    let evm_addr = format!("0x{}", hex::encode(&hash[12..]));
    assert!(run("evm", "segwit", phrase).contains(&evm_addr));

    // DOGE (BIP44 m/44'/3'/0'/0/0)
    let pk = derive_key(&seed, "m/44'/3'/0'/0/0");
    let pk_hash: PubkeyHash = pk.into();
    let hash160 = pk_hash.to_byte_array();
    let mut payload = Vec::with_capacity(25);
    payload.push(0x1e);
    payload.extend_from_slice(&hash160);
    let checksum = double_sha256_first4(&payload);
    payload.extend_from_slice(&checksum);
    let doge_addr = base58_encode(&payload);
    assert!(run("doge", "segwit", phrase).contains(&doge_addr));
}

fn derive_pubkey(seed: &[u8], path: &str) -> bitcoin::key::PublicKey {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let p: DerivationPath = path.parse().unwrap();
    let child = root.derive_priv(&secp, &p).unwrap();
    let private_key = PrivateKey::new(child.private_key, Network::Bitcoin);
    private_key.public_key(&secp)
}

fn build_p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(pubkey_hash);
    script
}

fn pubkey_hash_bytes(data: &[u8]) -> [u8; 20] {
    let h = PubkeyHash::hash(data);
    h.to_byte_array()
}

#[test]
fn test_all_types_valid() {
    let phrases = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ];

    for &(coin, addr_type) in &[
        ("btc", "segwit"), ("btc", "p2sh"), ("btc", "legacy"),
        ("ltc", "segwit"), ("ltc", "p2sh"), ("ltc", "legacy"),
        ("evm", "segwit"),
        ("doge", "segwit"),
    ] {
        for phrase in &phrases {
            let stdout = run(coin, addr_type, phrase);
            assert!(stdout.contains("✓"),
                "{coin} {addr_type} with {phrase:?}: not valid:\n{stdout}");
        }
    }
}
