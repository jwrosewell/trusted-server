//! In-process implementation of the core [`RateLimiter`] trait.
//!
//! The Fastly adapter uses Fastly's Edge Rate Limiting counters, which are
//! shared across every instance of the service
//! (`crates/trusted-server-adapter-fastly/src/rate_limiter.rs`). This adapter
//! has no such platform counter, so the window is counted in this process.
//!
//! That is the right scope for a single-instance appliance and the wrong scope
//! for more than one, since two processes would each allow the full budget.
//! The key-value store this adapter opens is single-process for the same
//! reason (`redb` takes an exclusive file lock), so an appliance that runs a
//! second instance already has to solve shared state, and this limiter is one
//! more thing that would need solving with it.
//!
//! The hourly budget is converted to a per-minute one exactly as the Fastly
//! adapter does, so a given `hourly_limit` allows the same number of requests
//! per minute on both.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use error_stack::Report;
use trusted_server_core::ec::rate_limiter::RateLimiter;
use trusted_server_core::error::TrustedServerError;

/// Length of the counting window.
const WINDOW: Duration = Duration::from_secs(60);

/// Converts an hourly budget into the per-minute budget actually enforced.
///
/// Copied from the Fastly adapter so the two agree on what a configured
/// `hourly_limit` permits: 65/hr becomes 2/min, and any positive limit below
/// 60/hr rounds up to 1/min.
fn hourly_limit_to_per_minute_limit(hourly_limit: u32) -> u32 {
    if hourly_limit == 0 {
        return 0;
    }

    let per_minute_limit = hourly_limit.saturating_add(59) / 60;
    per_minute_limit.max(1)
}

/// One key's count and the moment its window opened.
struct Window {
    started: Instant,
    count: u32,
}

/// In-process [`RateLimiter`] counting a fixed 60-second window per key.
pub struct InProcessRateLimiter {
    windows: Mutex<HashMap<String, Window>>,
}

impl InProcessRateLimiter {
    /// Creates an empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InProcessRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter for InProcessRateLimiter {
    fn exceeded(&self, key: &str, hourly_limit: u32) -> Result<bool, Report<TrustedServerError>> {
        let per_minute_limit = hourly_limit_to_per_minute_limit(hourly_limit);
        if per_minute_limit == 0 {
            return Ok(true);
        }

        // The map holds only counts, so a panic elsewhere while the lock was
        // held leaves no broken invariant and the poison is recovered from.
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);

        let now = Instant::now();
        // Drop windows that have expired, so a long-running appliance does not
        // accumulate an entry for every key it has ever seen.
        windows.retain(|_, window| now.duration_since(window.started) < WINDOW);

        let window = windows.entry(key.to_owned()).or_insert(Window {
            started: now,
            count: 0,
        });

        if window.count >= per_minute_limit {
            return Ok(true);
        }

        window.count = window.count.saturating_add(1);
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_hourly_limit_denies_everything() {
        let limiter = InProcessRateLimiter::new();

        assert!(
            limiter.exceeded("partner", 0).expect("should not error"),
            "a zero budget must deny the first request, not the second"
        );
    }

    #[test]
    fn requests_within_the_budget_are_allowed() {
        let limiter = InProcessRateLimiter::new();

        // 120/hr converts to 2/min.
        assert!(
            !limiter.exceeded("partner", 120).expect("should not error"),
            "the first request of two must be allowed"
        );
        assert!(
            !limiter.exceeded("partner", 120).expect("should not error"),
            "the second request of two must be allowed"
        );
    }

    #[test]
    fn the_request_past_the_budget_is_refused() {
        let limiter = InProcessRateLimiter::new();

        for _ in 0..2 {
            limiter.exceeded("partner", 120).expect("should not error");
        }

        assert!(
            limiter.exceeded("partner", 120).expect("should not error"),
            "the third request in a 2/min window must be refused"
        );
    }

    #[test]
    fn budgets_are_counted_per_key() {
        let limiter = InProcessRateLimiter::new();

        for _ in 0..2 {
            limiter
                .exceeded("partner-a", 120)
                .expect("should not error");
        }

        assert!(
            !limiter
                .exceeded("partner-b", 120)
                .expect("should not error"),
            "one partner exhausting its budget must not throttle another"
        );
    }

    #[test]
    fn hourly_budgets_convert_the_same_way_as_the_fastly_adapter() {
        assert_eq!(
            hourly_limit_to_per_minute_limit(0),
            0,
            "a zero budget stays a deny-all"
        );
        assert_eq!(
            hourly_limit_to_per_minute_limit(65),
            2,
            "65/hr rounds up to 2/min"
        );
        assert_eq!(
            hourly_limit_to_per_minute_limit(1),
            1,
            "any positive sub-60 budget rounds up to 1/min"
        );
    }
}
