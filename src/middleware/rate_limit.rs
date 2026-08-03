//! Token-bucket rate limiting — port of strix `src/middleware/rate-limit.ts`.
//!
//! A per-`(ip, category)` token bucket: `login` 5/min, `register` 3/min,
//! `default` 60/min. Over-limit requests get `429 M_LIMIT_EXCEEDED` with
//! `retry_after_ms`. Disabled entirely by `DISABLE_RATE_LIMIT=1`. Idle buckets
//! are pruned periodically.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::json;

use crate::errors::MatrixError;
use crate::server::now_ms;

struct TokenBucket {
    tokens: f64,
    last_refill: i64,
}

#[derive(Clone, Copy)]
struct RateLimitConfig {
    max_tokens: f64,
    /// tokens per millisecond
    refill_rate: f64,
}

/// Category config (strix `RATE_CONFIGS`).
fn config_for(category: &str) -> RateLimitConfig {
    match category {
        "login" => RateLimitConfig {
            max_tokens: 5.0,
            refill_rate: 5.0 / 60_000.0,
        },
        "register" => RateLimitConfig {
            max_tokens: 3.0,
            refill_rate: 3.0 / 60_000.0,
        },
        _ => RateLimitConfig {
            max_tokens: 60.0,
            refill_rate: 60.0 / 60_000.0,
        },
    }
}

const CLEANUP_INTERVAL: i64 = 5 * 60_000;
const STALE_THRESHOLD: i64 = 10 * 60_000;

struct RateLimiterState {
    buckets: HashMap<String, TokenBucket>,
    last_cleanup: i64,
}

fn state() -> &'static Mutex<RateLimiterState> {
    static STATE: OnceLock<Mutex<RateLimiterState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(RateLimiterState {
            buckets: HashMap::new(),
            last_cleanup: now_ms(),
        })
    })
}

fn disabled() -> bool {
    std::env::var("DISABLE_RATE_LIMIT").as_deref() == Ok("1")
}

/// Consume one token for `(ip, category)`, or return a `429 M_LIMIT_EXCEEDED`
/// error carrying `retry_after_ms`. No-op when rate limiting is disabled.
pub fn check_rate_limit(ip: &str, category: &str) -> Result<(), MatrixError> {
    if disabled() {
        return Ok(());
    }
    let config = config_for(category);
    let key = format!("{ip}:{category}");
    let now = now_ms();

    let mut st = state().lock().unwrap();

    if now - st.last_cleanup >= CLEANUP_INTERVAL {
        st.last_cleanup = now;
        st.buckets
            .retain(|_, b| now - b.last_refill <= STALE_THRESHOLD);
    }

    let bucket = st.buckets.entry(key).or_insert(TokenBucket {
        tokens: config.max_tokens,
        last_refill: now,
    });

    let elapsed = (now - bucket.last_refill) as f64;
    bucket.tokens = (bucket.tokens + elapsed * config.refill_rate).min(config.max_tokens);
    bucket.last_refill = now;

    if bucket.tokens < 1.0 {
        let wait_ms = ((1.0 - bucket.tokens) / config.refill_rate).ceil() as i64;
        let mut extra = serde_json::Map::new();
        extra.insert("retry_after_ms".to_string(), json!(wait_ms));
        return Err(MatrixError::new("M_LIMIT_EXCEEDED", "Too many requests", 429).with_extra(extra));
    }

    bucket.tokens -= 1.0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both cases live in one test: they mutate the process-global
    // `DISABLE_RATE_LIMIT` env var, so running them as separate parallel tests
    // races. Keeping them sequential here avoids the interference.
    #[test]
    fn token_bucket_and_disable_flag() {
        // Enabled: register allows 3/min, then 429s.
        std::env::remove_var("DISABLE_RATE_LIMIT");
        let ip = "10.0.0.99";
        for _ in 0..3 {
            assert!(check_rate_limit(ip, "register").is_ok());
        }
        let err = check_rate_limit(ip, "register").unwrap_err();
        assert_eq!(err.errcode, "M_LIMIT_EXCEEDED");
        assert_eq!(err.status_code, 429);

        // Disabled: never blocks.
        std::env::set_var("DISABLE_RATE_LIMIT", "1");
        for _ in 0..100 {
            assert!(check_rate_limit("10.0.0.100", "register").is_ok());
        }
        std::env::remove_var("DISABLE_RATE_LIMIT");
    }
}
