use bip39_vanity_rs::{search, wallet};

fn usage(name: &str) {
    eprintln!("Usage: {} [options] <pattern> [pattern...]", name);
    eprintln!();
    eprintln!("Generates BIP39 seed phrases (12 words) and searches for vanity addresses.");
    eprintln!("  BTC/LTC: segwit (BIP84), p2sh (BIP49), legacy (BIP44)");
    eprintln!("  EVM: 0x-hex address  |  DOGE: base58");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -c <coin>    Coin: btc, ltc, evm/eth, doge  (default: btc)");
    eprintln!("  -a <type>    Addr type for BTC/LTC: segwit, p2sh, legacy  (default: segwit)");
    eprintln!("  -n <num>     Stop after N matches  (default: 1)");
    eprintln!("  -t <num>     Thread count  (default: auto)");
    eprintln!("  -s <phrase>  Derive address from seed phrase (no search)");
    eprintln!("  --hrp <str>  Custom bech32 HRP (for -a segwit)  (default: bc/ltc)");
    eprintln!("  -h           Show this help");
    eprintln!();
    eprintln!("Patterns:");
    eprintln!("  <str>        Address contains <str> (substring match)");
    eprintln!("  <str>*       Address starts with <str>");
    eprintln!("  *<str>       Address ends with <str>");
    eprintln!("  *<str>*      Address contains <str>");
    eprintln!("  <a>*<b>      Address starts with <a> AND ends with <b>");
    eprintln!("  <a>*<b>*<c>  Segments <a>, <b>, <c> appear in order in address");
    eprintln!();
    eprintln!("  Multiple patterns: any match triggers a hit (at least 1 pattern required)");
    eprintln!();
    eprintln!("  Address prefixes (must be included in prefix patterns):");
    eprintln!("    BTC segwit  'bc1q...'  |  BTC p2sh    '3...'");
    eprintln!("    BTC legacy  '1...'     |  LTC segwit  'ltc1q...'");
    eprintln!("    LTC p2sh    'M...'     |  LTC legacy  'L...'");
    eprintln!("    EVM         '0x...'    |  DOGE        'D...'");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("bip39_vanity");

    if args.len() == 1 {
        usage(prog);
        return;
    }

    let mut patterns: Vec<String> = Vec::new();
    let mut coin_name = "btc".to_string();
    let mut addr_type = "segwit".to_string();
    let mut count_target: Option<usize> = None;
    let mut num_threads: Option<usize> = None;
    let mut seed_phrase: Option<String> = None;
    let mut hrp: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { usage(prog); return; }
            "-c" | "--coin" => { i += 1; if i < args.len() { coin_name = args[i].clone(); } }
            "-a" | "--addr-type" => { i += 1; if i < args.len() { addr_type = args[i].clone(); } }
            "-n" | "--count" => { i += 1; if i < args.len() { count_target = args[i].parse().ok(); } }
            "-t" | "--threads" => { i += 1; if i < args.len() { num_threads = args[i].parse().ok(); } }
            "-s" | "--seed" => { i += 1; if i < args.len() { seed_phrase = Some(args[i].clone()); } }
            "--hrp" => { i += 1; if i < args.len() { hrp = Some(args[i].clone()); } }
            a if a.starts_with('-') => { eprintln!("Unknown option: {}", a); usage(prog); std::process::exit(1); }
            _ => { patterns.push(args[i].clone()); }
        }
        i += 1;
    }

    let Some(wallet) = wallet::by_name(&coin_name, &addr_type, hrp.as_deref()) else {
        eprintln!("Unknown coin or address type: {} {}", coin_name, addr_type);
        std::process::exit(1);
    };

    if let Some(ref phrase) = seed_phrase {
        let Some(address) = wallet.derive_from_phrase(phrase) else {
            eprintln!("Invalid seed phrase: {}", phrase);
            std::process::exit(1);
        };
        println!("Coin:     {}", wallet.name());
        println!("Address:  {}", address);
        if wallet.verify_address(&address) {
            println!("Status:   ✓ Address format valid");
        } else {
            println!("Status:   ✗ Address format invalid");
        }
        return;
    }

    if patterns.is_empty() {
        usage(prog);
        std::process::exit(1);
    }
    let patterns_lower: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();

    for p in &patterns_lower {
        let stripped: String = p.chars().filter(|c| *c != '*').collect();
        if let Err(bad) = wallet.validate_pattern(&stripped) {
            eprintln!("Error: pattern \"{p}\" contains characters that can never appear in {} address: {:?}",
                wallet.name(), bad.iter().collect::<String>());
            std::process::exit(1);
        }
    }

    let addr_prefix = wallet.address_prefix();
    for p in &patterns_lower {
        if let Some(first) = p.split('*').next() {
            if !first.is_empty() && !p.starts_with('*') && !first.starts_with(addr_prefix) {
                eprintln!("Error: pattern \"{p}\" can never match — {} addresses always start with \"{}\"",
                    wallet.name(), addr_prefix);
                eprintln!("  Try: \"{}{}\"", addr_prefix, p);
                std::process::exit(1);
            }
        }
    }

    let count_target = count_target.unwrap_or(1);
    let num_threads = num_threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));

    eprintln!("Coin: {} | Patterns: {} | Target: {count_target} | Threads: {num_threads}",
        wallet.name(),
        patterns_lower.join(", "));

    search::run(wallet, &patterns_lower, count_target, num_threads);
}
