# bip39_vanity_rs

Finds cool addresses for your crypto wallets.  
Works with BTC, LTC, EVM, DOGE.

## How It Works

Each seed phrase always produces the same address. Which path depends on the coin:

| Coin  | Paths |
|-------|-------|
| BTC   | BIP84 segwit (`m/84'/0'/0'/0/0`), BIP49 p2sh (`m/49'/0'/0'/0/0`), BIP44 legacy (`m/44'/0'/0'/0/0`) |
| LTC   | BIP84 segwit (`m/84'/2'/0'/0/0`), BIP49 p2sh (`m/49'/2'/0'/0/0`), BIP44 legacy (`m/44'/2'/0'/0/0`) |
| EVM   | `m/44'/60'/0'/0/0` (BIP44) |
| DOGE  | `m/44'/3'/0'/0/0`  (BIP44) |

The `/0` at the end is the address index - always the first one your wallet shows after you import the seed phrase.

Want to check? Generate a phrase with the tool, import it into Cake Wallet, MetaMask, or whatever, and compare the first address.

You can also verify manually on [iancoleman.io/bip39](https://iancoleman.io/bip39/) - paste the seed phrase, pick the right coin and derivation path from the table above, and check the first address.

*Some wallets generate extra addresses (change addresses, other accounts), but index 0 is the first one.*

## Building

```sh
cargo build --release
```

Only Linux builds in [releases](https://github.com/scclie/bip39_vanity_rs/releases).

## Usage

```
bip39_vanity_rs [options] <pattern> [pattern...]

Options:
  -c <coin>    Coin: btc, ltc, evm/eth, doge  (default: btc)
  -a <type>    Addr type for BTC/LTC: segwit, p2sh, legacy  (default: segwit)
  -n <num>     Stop after N matches  (default: 1)
  -t <num>     Thread count  (default: auto)
  -s <phrase>  Derive address from seed phrase (no search)
  --hrp <str>  Custom bech32 HRP (for -a segwit)  (default: bc/ltc)
  -h           Show this help

Patterns:
  <str>        Address contains <str> (substring match)
  <str>*       Address starts with <str>
  *<str>       Address ends with <str>
  *<str>*      Address contains <str>
  <a>*<b>      Address starts with <a> AND ends with <b>
  <a>*<b>*<c>  Segments <a>, <b>, <c> appear in order in address

Note: prefix patterns must include the coin's address prefix:
  EVM → '0xdead*'          BTC segwit → 'bc1qr*'      BTC p2sh → '3abc*'
  BTC legacy → '1abc*'     LTC segwit → 'ltc1q*'      LTC p2sh → 'Mabc*'
  LTC legacy → 'Labc*'     DOGE → 'Dabc*'
Otherwise the program will warn that the pattern can never match.
```

### Examples

```sh
# BTC address ending with sccl
bip39_vanity_rs -c btc '*sccl'

# EVM address ending with dead or beef
bip39_vanity_rs -c evm '*dead' '*beef'

# Find 3 Dogecoin addresses with prefix D9
bip39_vanity_rs -c doge -n 3 'D9*'

# LTC address containing cake
bip39_vanity_rs -c ltc '*cake*'

# BTC segwit starting with bc1qdead AND ending with beef
bip39_vanity_rs -c btc 'bc1qdead*beef'

# BTC P2SH starting with 3abc
bip39_vanity_rs -c btc -a p2sh '3abc*'

# LTC legacy starting with Ldead
bip39_vanity_rs -c ltc -a legacy 'Ldead*'

# Testnet BTC segwit (custom HRP tb)
bip39_vanity_rs -c btc --hrp tb 'tb1qdead*beef'
```

## Architecture

```
src/
  lib.rs        // library root (tests import from here)
  main.rs       // CLI entry point
  search.rs     // multi-threaded search engine + wildcard_match()
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
| 8      | ~ 34 yr      | ~ 50 days| -         |

*At 1000 key/s.*  
At ~5000 key/s divide times by 5.  
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
cargo test
```

All 24 tests in `tests/vectors.rs`:

| Group | Tests | What it checks |
|-------|-------|----------------|
| `match_*` | 8 | `wildcard_match()` - prefix, suffix, contains, prefix+suffix, multi-segment, exact, empty/wildcard-only |
| `reject_impossible_prefix_*` | 5 | Invalid prefix (e.g. `0xdead*` on BTC segwit) rejected with error + hint |
| `reject_*` | 3 | Invalid seed phrase, invalid chars (`i*` on bech32), unknown addr type - exit 1 |
| `custom_hrp_*` | 3 | Custom bech32 HRP (`--hrp`) works: `tb`, `bcrt`, `tltc` |
| `accept_valid_prefix_*` | 1 | Valid prefix (`bc1qa*` on BTC segwit) accepted |
| `test_suffix_derivation` | 1 | 8 `(coin, addr_type)` combos - address ends with `*aa` |
| `test_prefix_derivation` | 1 | 8 `(coin, addr_type)` combos - address starts with `{prefix}a` |
| `test_derivation_matches_binary` | 1 | All 8 types independently computed via `bitcoin` + `tiny-keccak` crates, matches binary |
| `test_all_types_valid` | 1 | Format validity for 4 BIP39 seeds on all 8 types |

## Test Vectors: Suffix & Prefix Search

Every pattern can be verified with `-s` - no search needed:

```sh
bip39_vanity_rs -s "<seed>" -c <coin> [-a <type>]
```

### Suffix search: addresses ending with `aa` (`*aa`)

| Coin | Type | Seed phrase | Address |
|------|------|-------------|---------|
| BTC | BIP84 segwit | clinic betray laugh catch peanut act parent cousin clump suffer squirrel ski | `bc1qm8dlqk06mfnyyc5dp7x0580cq626wcxxs4pcaa` |
| BTC | BIP49 p2sh | winner cause trap cherry chef wave cream display paddle horn light vanish | `3JXBxKWY5UuaTWYpvBNBrGmjveHf35QBaA` |
| BTC | BIP44 legacy | unknown post cute sweet photo spin secret cereal bundle satoshi bulk soda | `1HNZtD2FxgfkMPk7omNog3NfMnfyjz5Haa` |
| LTC | BIP84 segwit | hope where win kind fitness obey board jar wealth rescue soft acoustic | `ltc1qydxj4lyeq6rqqs8k8q59dxgthz26jfffm5r2aa` |
| LTC | BIP49 p2sh | level choose slight process jazz rely lemon dwarf cattle finish erupt wing | `MR4ZupNrk58rRZeYY4SRCZSGs6GiW4iNAa` |
| LTC | BIP44 legacy | reform device until raven wasp extra faith issue gain clarify refuse coffee | `Lcc6DZuqUFoZWNzKbFwWV7R2GBeZ5gauAA` |
| EVM | BIP44 | curve frequent urge hair leopard spin timber jazz urge side update share | `0xc9d8568e1c2263eedd996032557cb43ddc1ce0aa` |
| DOGE | BIP44 | image fetch apart oppose blood powder budget fashion zoo square fire course | `DEbuWrFE73BuAP8G6fiz7Udk5zFkD49JAA` |

### Prefix search: starts with coin prefix + `a` (e.g. `'bc1qa*'`, `'3a*'`, `'0xa*'`)

| Coin | Type | Seed phrase | Address |
|------|------|-------------|---------|
| BTC | BIP84 segwit | illegal curve swap report gallery alley shrimp youth receive begin attract fly | `bc1qaz2dn9ttfskhwfqwg8385auslc3unf5wwcze4k` |
| BTC | BIP49 p2sh | speak travel neglect pear cabbage pink vast ignore congress wagon scale boss | `3AGKSo1RanLUjSVwXWAnhqiXSNBYEdaRB4` |
| BTC | BIP44 legacy | practice wreck wall pelican alarm cake stadium ship length short lunar sniff | `1AyUf7PxrVhSzc7Uh5zdLKnn7aSNZCMsNn` |
| LTC | BIP84 segwit | cash arrest rare calm same adjust stomach area twenty mass absorb rifle | `ltc1qacdqddaxzl0yuacqrgpu6hnh2zhac2xlny3zdk` |
| LTC | BIP49 p2sh | spray square drill chuckle prevent impact walk page small allow happy senior | `MAbeaDCqWFHV2DG8JWkWbKHW8BepPXkJNQ` |
| LTC | BIP44 legacy | insect shoe drama sentence close evoke gaze trial false solution exercise jungle | `La74UqiBPyquzf1xmXvhV8nxzuAELx8dmz` |
| EVM | BIP44 | another shallow east there canoe much matrix sense proof logic perfect depth | `0xaaaa6fff901f29e59b904df0d9a2b1c2b70ade30` |
| DOGE | BIP44 | true festival champion dolphin organ rather scheme vocal clip feel razor hand | `DAAhozUb7VVtJmvt3MY4dPuMsZbLe3fABL` |

## Notes

- One seed phrase, one address. Import the phrase into a wallet and you own it.
- EVM address is the same on all EVM chains (Ethereum, BSC, Polygon, etc.).
- `OsRng` for entropy.
- `-s "<phrase>"` derives an address from an existing phrase without searching.
