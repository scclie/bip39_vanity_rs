use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bip39::Mnemonic;
use rand::RngCore;

use crate::wallet::Wallet;

pub fn wildcard_match(addr: &str, pattern: &str) -> bool {
    let segments: Vec<&str> = pattern.split('*').collect();

    if segments.len() == 1 {
        return addr.contains(pattern);
    }

    let non_empty: Vec<&str> = segments.iter().filter(|s| !s.is_empty()).copied().collect();

    if non_empty.is_empty() {
        return true;
    }

    if !pattern.starts_with('*') && !addr.starts_with(non_empty[0]) {
        return false;
    }

    if !pattern.ends_with('*') && !addr.ends_with(non_empty[non_empty.len() - 1]) {
        return false;
    }

    let mut search_pos = 0;
    for &seg in &non_empty {
        match addr[search_pos..].find(seg) {
            Some(idx) => search_pos += idx + seg.len(),
            None => return false,
        }
    }

    true
}

pub fn run(
    wallet: Arc<dyn Wallet>,
    patterns: &[String],
    count_target: usize,
    num_threads: usize,
) {
    let found_count = Arc::new(AtomicU64::new(0));
    let total_keys = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let mut handles = vec![];

    for _ in 0..num_threads {
        let wallet = wallet.clone();
        let patterns = patterns.to_vec();
        let found_count = found_count.clone();
        let total_keys = total_keys.clone();

        handles.push(std::thread::spawn(move || {
            let mut entropy = [0u8; 16];

            loop {
                if found_count.load(Ordering::Relaxed) >= count_target as u64 {
                    break;
                }

                rand::rngs::OsRng.fill_bytes(&mut entropy);

                let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) else { continue; };
                let seed = mnemonic.to_seed_normalized("");

                let Some(addr) = wallet.derive_address(&seed) else { continue; };

                let prev = total_keys.fetch_add(1, Ordering::Relaxed);
                if prev % 500 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = (prev as f64) / elapsed;
                    eprint!("\r[{:.0} key/s][total {}]  ", rate, prev);
                }

                let addr_lower = addr.to_lowercase();
                for p in &patterns {
                    if wildcard_match(&addr_lower, p) {
                        let n = found_count.fetch_add(1, Ordering::Relaxed);
                        if n < count_target as u64 {
                            println!("\nMatch #{} found!", n + 1);
                            println!("Seed phrase: {}", mnemonic.words().collect::<Vec<_>>().join(" "));
                            println!("Address: {}", addr);
                        }
                        break;
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
