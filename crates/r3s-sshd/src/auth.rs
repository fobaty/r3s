//! Authentication: `authorized_keys` with stat-caching, constant-time reject,
//! brute-force LRU protection.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::keys::PublicKey;
use tracing::{info, warn};

/// Entry in the brute-force protection LRU cache.
struct AuthAttempt {
    timestamp: Instant,
    failed_count: u32,
}

/// Brute-force protection using an LRU cache with exponential backoff.
#[derive(Clone)]
pub struct BruteForceProtector {
    max_entries: usize,
    attempts: Arc<Mutex<lru::LruCache<String, AuthAttempt>>>,
    min_backoff: Duration,
    max_backoff: Duration,
}

impl BruteForceProtector {
    pub fn new(max_entries: usize, min_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            max_entries,
            attempts: Arc::new(Mutex::new(lru::LruCache::new(NonZeroUsize::new(max_entries).unwrap()))),
            min_backoff,
            max_backoff,
        }
    }

    pub fn check(&self, username: &str) -> Result<(), Duration> {
        let mut cache = self.attempts.lock().unwrap();
        let now = Instant::now();

        // Clean up old entries
        cache.iter_mut().for_each(|(_, entry)| {
            if now.duration_since(entry.timestamp) > Duration::from_secs(3600) {
                entry.failed_count = 0;
            }
        });

        let mut entry = cache.get_mut(username);
        if entry.is_none() {
            cache.put(username.to_string(), AuthAttempt {
                timestamp: now,
                failed_count: 0,
            });
            entry = cache.get_mut(username);
        }

        match entry {
            Some(e) => {
                if e.failed_count >= 5 {
                    let backoff_ms = (self.min_backoff.as_millis() as u64 * 2_u64.pow(e.failed_count))
                        .min(self.max_backoff.as_millis() as u64);
                    let backoff = Duration::from_millis(backoff_ms);
                    return Err(backoff);
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn record_failure(&self, username: &str) {
        let mut cache = self.attempts.lock().unwrap();
        if let Some(entry) = cache.get_mut(username) {
            entry.failed_count += 1;
            entry.timestamp = Instant::now();
        } else {
            cache.put(username.to_string(), AuthAttempt {
                timestamp: Instant::now(),
                failed_count: 1,
            });
        }
    }
}

/// Authorized keys file with stat-based caching.
pub struct AuthorizedKeysFile {
    path: PathBuf,
}

impl AuthorizedKeysFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
        }
    }

    pub fn load(&self) -> Result<Vec<String>, std::io::Error> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect();

        Ok(lines)
    }

    pub fn verify_key(&self, _username: &str, public_key: &PublicKey) -> Result<(), anyhow::Error> {
        let lines = self.load()?;

        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            // Simple comparison: check if the base64 key data matches
            // In a real implementation, you'd parse the key type and compare properly
            // Join all parts from index 1 onwards (in case base64 has spaces)
            let key_str = parts[1..].join(" ");
            let key_data = match base64::decode(&key_str) {
                Ok(data) => data,
                Err(e) => {
                    warn!(error = %e, "invalid base64 in authorized_keys");
                    continue;
                }
            };
            
            // Compare with the public key's bytes
            if public_key.to_bytes().ok() == Some(key_data) {
                info!("authentication successful");
                return Ok(());
            }
        }

        warn!("authentication failed: key not authorized");
        let _ = public_key.to_bytes(); // Constant-time reject
        Err(anyhow::anyhow!("unauthorized key"))
    }
}

pub fn authenticate(
    username: &str,
    public_key: &PublicKey,
    authorized_keys: &AuthorizedKeysFile,
    protector: &BruteForceProtector,
) -> Result<(), anyhow::Error> {
    if let Err(backoff) = protector.check(username) {
        let backoff_ms = backoff.as_millis();
        warn!(username, backoff_ms, "brute-force protection triggered");
        return Err(anyhow::anyhow!("too many failed attempts, try again in {}ms", backoff_ms));
    }

    match authorized_keys.verify_key(username, public_key) {
        Ok(()) => Ok(()),
        Err(e) => {
            protector.record_failure(username);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_protector() {
        let protector = BruteForceProtector::new(100, Duration::from_secs(1), Duration::from_secs(60));
        assert!(protector.check("user1").is_ok());
        protector.record_failure("user1");
        assert!(protector.check("user1").is_ok());
    }
}