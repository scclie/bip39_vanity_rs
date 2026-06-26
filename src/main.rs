mod search;
mod wallet;

fn usage(name: &str) {
    eprintln!("Usage: {} [options] <pattern> [pattern...]", name);
    eprintln!();
    eprintln!("Generates BIP39 seed phrases (12 words) and searches for vanity addresses.");
    eprintln!("  BTC/LTC: BIP84 Native SegWit bech32  |  EVM: 0x-hex address  |  DOGE: base58");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -c <coin>    Coin: btc, ltc, evm/eth, doge  (default: btc)");
    eprintln!("  -m <mode>    Match mode: prefix, suffix, anywhere  (default: suffix)");
    eprintln!("  -n <num>     Stop after N matches  (default: 1)");
    eprintln!("  -t <num>     Thread count  (default: auto)");
    eprintln!("  -s <phrase>  Derive address from seed phrase (no search)");
    eprintln!("  -h           Show this help");
    eprintln!();
    eprintln!("  pattern      Search pattern(s) — any match triggers a hit (at least 1 required)");
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
    let mut mode = "suffix".to_string();
    let mut count_target: Option<usize> = None;
    let mut num_threads: Option<usize> = None;
    let mut seed_phrase: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { usage(prog); return; }
            "-c" | "--coin" => { i += 1; if i < args.len() { coin_name = args[i].clone(); } }
            "-m" | "--mode" => { i += 1; if i < args.len() { mode = args[i].clone(); } }
            "-n" | "--count" => { i += 1; if i < args.len() { count_target = args[i].parse().ok(); } }
            "-t" | "--threads" => { i += 1; if i < args.len() { num_threads = args[i].parse().ok(); } }
            "-s" | "--seed" => { i += 1; if i < args.len() { seed_phrase = Some(args[i].clone()); } }
            a if a.starts_with('-') => { eprintln!("Unknown option: {}", a); usage(prog); return; }
            _ => { patterns.push(args[i].clone()); }
        }
        i += 1;
    }

    let Some(wallet) = wallet::by_name(&coin_name) else {
        eprintln!("Unknown coin: {}", coin_name);
        return;
    };

    if let Some(ref phrase) = seed_phrase {
        let Some(address) = wallet.derive_from_phrase(phrase) else {
            eprintln!("Invalid seed phrase: {}", phrase);
            return;
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
        return;
    }
    let patterns_lower: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();

    for p in &patterns_lower {
        if let Err(bad) = wallet.validate_pattern(p) {
            eprintln!("Error: pattern \"{p}\" contains characters that can never appear in {} address: {:?}",
                wallet.name(), bad.iter().collect::<String>());
            return;
        }
    }

    let count_target = count_target.unwrap_or(1);
    let num_threads = num_threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));

    eprintln!("Coin: {} | Patterns: {} | Mode: {mode} | Target: {count_target} | Threads: {num_threads}",
        wallet.name(),
        patterns_lower.join(", "));

    search::run(wallet, &patterns_lower, &mode, count_target, num_threads);
}
