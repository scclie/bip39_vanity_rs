# bip39_vanity_rs

Finds cool addresses for your crypto wallets.  
Works with BTC, LTC, EVM, DOGE.

## How It Works

Each seed phrase always produces the same address. Which path depends on the coin:

| Coin  | Path |
|-------|------|
| BTC   | `m/84'/0'/0'/0/0`  (BIP84 Native SegWit) |
| LTC   | `m/84'/2'/0'/0/0`  (BIP84 Native SegWit) |
| EVM   | `m/44'/60'/0'/0/0` (BIP44) |
| DOGE  | `m/44'/3'/0'/0/0`  (BIP44) |

The `/0` at the end is the address index — always the first one your wallet shows after you import the seed phrase.

Want to check? Generate a phrase with the tool, import it into Cake Wallet, MetaMask, or whatever, and compare the first address.

*Some wallets generate extra addresses (change addresses, other accounts), but index 0 is the first one.*

## Building

```sh
cargo build --release
```

Only Linux builds in releases.

## Usage

```
bip39_vanity_rs [options] <pattern> [pattern...]

Options:
  -c <coin>    Coin: btc, ltc, evm/eth, doge  (default: btc)
  -m <mode>    Match mode: prefix, suffix, anywhere  (default: suffix)
  -n <num>     Stop after N matches  (default: 1)
  -t <num>     Thread count  (default: auto)
  -h           Show this help
```

### Examples

```sh
# BTC address ending with sccl
bip39_vanity_rs -c btc -m suffix sccl

# EVM address ending with dead or beef
bip39_vanity_rs -c evm -m suffix dead beef

# Find 3 Dogecoin addresses with prefix D9
bip39_vanity_rs -c doge -m prefix -n 3 D9

# LTC address containing cake
bip39_vanity_rs -c ltc -m anywhere cake
```

## Architecture

```
src/
  main.rs       // CLI entry point
  search.rs     // multi-threaded search engine (coin-agnostic)
  wallet/
    mod.rs      // Wallet trait + registry
    bech32.rs   // BTC / LTC (BIP84 Native SegWit bech32)
    evm.rs      // EVM / Ethereum / BSC / Polygon / etc. (0x-hex)
    doge.rs     // Dogecoin (base58)
```

## Performance

How fast it goes depends on your CPU and thread count (`-t`).

Address characters (after the prefix) are random. Chance of a match is `1 / alphabet^n` per try for an n-character pattern.

The table shows how many keys you'd need on average for a ~63% chance (`alphabet^n`).  
For 50% multiply by ~0.7, for 90% by ~2.3.

Estimated time = `alphabet^n / keys_per_second`.

| Length | BTC/LTC (32) | EVM (16) | DOGE (58) |
|-------:|:------------:|:--------:|:---------:|
| 1      | < 1 sec      | < 1 sec  | < 1 sec   |
| 2      | ~ 1 sec      | < 1 sec  | ~ 3 sec   |
| 3      | ~ 33 sec     | ~ 4 sec  | ~ 3 min   |
| 4      | ~ 18 min     | ~ 1 min  | ~ 3 h     |
| 5      | ~ 9 h        | ~ 18 min | ~ 8 days  |
| 6      | ~ 12 days    | ~ 5 h    | ~ 1.3 yr  |
| 7      | ~ 1 yr       | ~ 3 days | ~ 74 yr   |
| 8      | ~ 34 yr      | ~ 50 days| —         |

*At 1000 key/s.*  
At ~3000 key/s divide times by 3.  
Multiple patterns scale too.

## Trust

The heavy lifting is done by these crates:

| Crate | Used for |
|-------|----------|
| [`bip39`](https://crates.io/crates/bip39) | Mnemonic generation & seed derivation |
| [`bitcoin`](https://crates.io/crates/bitcoin) | BIP32 key derivation, BIP84 addresses |
| [`tiny-keccak`](https://crates.io/crates/tiny-keccak) | Keccak-256 for EVM addresses |
| [`rand`](https://crates.io/crates/rand) | Random entropy via OsRng |

The code just wires them together.

### Tests

```sh
cargo test --release
```

Tests are in `tests/vectors.rs`:
- `test_known_seeds` — checks the test vectors below match
- `test_random_address_validity` — generates addresses from 4 known BIP39 seeds and checks format

## Test Vectors

These addresses end with `aa`. Verify with `-s`:

```sh
bip39_vanity_rs -s "bench mother night siren defense strong mass damp liar document need yellow" -c btc
bip39_vanity_rs -s "prize filter arch flee off hope banner unique tired intact wink ill" -c ltc
bip39_vanity_rs -s "loud home much usage knee metal glad effort jelly spread ensure found" -c evm
bip39_vanity_rs -s "wedding purity worry true mind balcony walnut soda weapon siege pull smoke" -c doge
```

| Coin | Seed phrase | Address |
|------|-------------|---------|
| BTC | `bench mother night siren defense strong mass damp liar document need yellow` | `bc1qrxpte9ezjgxadahhq5qhvrt3dt7v5h7t3wuyaa` |
| LTC | `prize filter arch flee off hope banner unique tired intact wink ill` | `ltc1qkv8zmwq3era56csh7p5slhlvv2k9a6xy0qpmaa` |
| EVM | `loud home much usage knee metal glad effort jelly spread ensure found` | `0x8d18752d37220e44b340b0a1829c37490f2599aa` |
| DOGE | `wedding purity worry true mind balcony walnut soda weapon siege pull smoke` | `DMN4WHysscnYZAUhwF6K4aTApBKBy256Aa` |

## Notes

- One seed phrase, one address. Import the phrase into a wallet and you own it.
- EVM address is the same on all EVM chains (Ethereum, BSC, Polygon, etc.).
- `OsRng` for entropy.
- `-s "<phrase>"` derives an address from an existing phrase without searching.
