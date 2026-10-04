//! How busy each line is right now, and how fast it has been seen to go.
//!
//! Every connection the group hands out counts its received bytes into its
//! line's [`LineLoad`]; a sampler turns the counters into a rate about once
//! a second and keeps the line's peak (fading over minutes). The group uses
//! them for new connections: the line with the most room left (peak − rate)
//! among those good enough, and for 速度最快: the line seen fastest.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// A peak this old counts half (lines get busier and quieter over a day).
const PEAK_HALF_LIFE: Duration = Duration::from_secs(10 * 60);

/// Received bytes of one line, as a rate.
#[derive(Default)]
pub struct LineLoad {
    bytes: AtomicU64,
    state: Mutex<Rate>,
}

#[derive(Default)]
struct Rate {
    at: Option<Instant>,
    seen: u64,
    /// Bytes per second over the last look(s).
    rate: f64,
    /// The fastest the line has gone (bytes per second), fading.
    peak: f64,
}

impl LineLoad {
    /// Counts `n` received bytes.
    pub fn add(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Turns the counter into a rate (call about once a second).
    pub fn sample(&self, now: Instant) {
        let total = self.bytes.load(Ordering::Relaxed);
        let mut s = self.state.lock();
        let Some(at) = s.at else {
            s.at = Some(now);
            s.seen = total;
            return;
        };
        let dt = now.duration_since(at).as_secs_f64();
        if dt < 0.5 {
            return;
        }
        let inst = (total - s.seen) as f64 / dt;
        // Smooth a little: one quiet second doesn't make a busy line idle.
        s.rate = if dt > 3.0 {
            inst
        } else {
            0.5 * s.rate + 0.5 * inst
        };
        let fade = 0.5f64.powf(dt / PEAK_HALF_LIFE.as_secs_f64());
        s.peak = (s.peak * fade).max(inst);
        s.at = Some(now);
        s.seen = total;
    }

    /// (bytes per second now, the fastest seen).
    pub fn get(&self) -> (f64, f64) {
        let s = self.state.lock();
        (s.rate, s.peak)
    }
}

/// The loads of a group's lines.
#[derive(Default)]
pub struct Loads {
    lines: Mutex<HashMap<String, Arc<LineLoad>>>,
}

impl Loads {
    pub fn of(&self, line: &str) -> Arc<LineLoad> {
        Arc::clone(self.lines.lock().entry(line.to_string()).or_default())
    }

    pub fn sample(&self, now: Instant) {
        let lines: Vec<Arc<LineLoad>> = self.lines.lock().values().cloned().collect();
        for l in lines {
            l.sample(now);
        }
    }

    /// line → (rate now, peak), for the lines seen so far.
    pub fn snapshot(&self) -> HashMap<String, (f64, f64)> {
        self.lines
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_and_fading_peak() {
        let l = LineLoad::default();
        let t0 = Instant::now();
        l.sample(t0);
        l.add(2_000_000);
        l.sample(t0 + Duration::from_secs(1));
        let (rate, peak) = l.get();
        assert!((rate - 1_000_000.0).abs() < 1.0, "smoothed from 0: {rate}");
        assert!((peak - 2_000_000.0).abs() < 1.0);
        // Quiet for a while: the rate drops at once, the peak fades slowly.
        l.sample(t0 + Duration::from_secs(5));
        let (rate, peak) = l.get();
        assert!(rate < 1.0);
        assert!(peak > 1_990_000.0 && peak < 2_000_000.0, "{peak}");
    }
}
