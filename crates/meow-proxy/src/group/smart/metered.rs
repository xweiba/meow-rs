//! What the user experienced on one connection: time from the first
//! request bytes to the first answer, bytes received, and whether anything
//! came back at all. Reported once, when the connection goes away (or as a
//! failure the moment it stalls).
//!
//! Long transfers are also watched while they run ([`Pace`]): how fast
//! data comes while it is flowing — pauses of the client (a player with a
//! full buffer) don't count — so a download that crawls on its line moves
//! the site's next connections elsewhere long before it ends.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use meow_common::ProxyConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use super::load::LineLoad;
use super::stats::{Outcome, BULK_BYTES};

/// Reads closer than this belong to one burst; a longer gap is the client
/// idling and doesn't count as time.
const BURST_GAP: Duration = Duration::from_millis(300);
/// Active time per speed window of a bulk transfer.
const WINDOW: Duration = Duration::from_secs(5);
/// A bulk transfer slower than this (bytes/s while flowing) is slow.
pub const SLOW_BULK_BPS: f64 = 200.0 * 1024.0;
/// Slow windows in a row before the line is called slow for the site.
const SLOW_WINDOWS: u32 = 2;
/// Active time between interim throughput samples of a long transfer.
const SAMPLE_EVERY: Duration = Duration::from_secs(30);
/// Asked, and not one byte back this long: the line is broken here.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// A bulk transfer with the client waiting and nothing back this long has
/// stalled.
pub const STALL: Duration = Duration::from_secs(10);

/// What a running connection tells the group.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Live {
    /// Throughput of a long transfer so far (since the last sample).
    Sample { bytes: u64, active_ms: f64 },
    /// Two windows in a row below [`SLOW_BULK_BPS`] (once per connection).
    Slow { rate: f64 },
    /// No first byte in time, or a bulk transfer stopped while the client
    /// waits. Already reported as a failure.
    Stalled,
}

/// The pace of one connection's received data.
#[derive(Default)]
pub struct Pace {
    received: u64,
    last_read: Option<Instant>,
    /// The client wrote after the last received byte: it waits for an
    /// answer since then.
    waiting_since: Option<Instant>,
    win_active: Duration,
    win_bytes: u64,
    slow_windows: u32,
    slow_sent: bool,
    /// The rate of the last full window (bytes/s).
    last_rate: Option<f64>,
    sample_active: Duration,
    sample_bytes: u64,
    /// Bytes already handed out in samples.
    sampled: u64,
}

impl Pace {
    pub fn on_write(&mut self, now: Instant) {
        if self.waiting_since.is_none() {
            self.waiting_since = Some(now);
        }
    }

    /// `n` bytes came in at `now`.
    pub fn on_read(&mut self, now: Instant, n: u64, emit: &mut impl FnMut(Live)) {
        let bulk = self.received >= BULK_BYTES;
        self.received += n;
        self.waiting_since = None;
        let gap = self.last_read.map(|t| now.saturating_duration_since(t));
        self.last_read = Some(now);
        if !bulk {
            return;
        }
        // Time counts only inside a burst: the first read after a pause
        // brings bytes, not time (errs towards fast, never falsely slow).
        let dt = gap.filter(|g| *g < BURST_GAP).unwrap_or_default();
        self.win_active += dt;
        self.win_bytes += n;
        self.sample_active += dt;
        self.sample_bytes += n;
        if self.win_active >= WINDOW {
            let rate = self.win_bytes as f64 / self.win_active.as_secs_f64();
            self.last_rate = Some(rate);
            self.win_active = Duration::ZERO;
            self.win_bytes = 0;
            if rate < SLOW_BULK_BPS {
                self.slow_windows += 1;
            } else {
                self.slow_windows = 0;
            }
            if self.slow_windows >= SLOW_WINDOWS && !self.slow_sent {
                self.slow_sent = true;
                emit(Live::Slow { rate });
            }
        }
        if self.sample_active >= SAMPLE_EVERY {
            emit(Live::Sample {
                bytes: self.sample_bytes,
                active_ms: self.sample_active.as_secs_f64() * 1000.0,
            });
            self.sampled += self.sample_bytes;
            self.sample_active = Duration::ZERO;
            self.sample_bytes = 0;
        }
    }

    /// When the connection counts as stalled if nothing comes before:
    /// asked and never answered, or a bulk transfer waiting on the line.
    pub fn deadline(&self) -> Option<Instant> {
        let since = self.waiting_since?;
        if self.received == 0 {
            Some(since + FIRST_BYTE_TIMEOUT)
        } else if self.received >= BULK_BYTES {
            Some(since + STALL)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn last_rate(&self) -> Option<f64> {
        self.last_rate
    }
}

pub struct MeteredConn {
    inner: Box<dyn ProxyConn>,
    connect: Duration,
    opened: Instant,
    wrote_at: Option<Instant>,
    first: Option<Duration>,
    received: u64,
    sent: u64,
    report: Option<Box<dyn FnOnce(Outcome) + Send + Sync>>,
    /// The line's load counter (received bytes as they come).
    load: Option<std::sync::Arc<LineLoad>>,
    pace: Pace,
    /// When the last interim sample was cut (the close report covers the
    /// rest only).
    sampled_at: Option<Instant>,
    live: Option<Box<dyn Fn(Live) + Send + Sync>>,
    stall: Option<Pin<Box<Sleep>>>,
}

impl MeteredConn {
    pub fn new(
        inner: Box<dyn ProxyConn>,
        connect: Duration,
        report: impl FnOnce(Outcome) + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            connect,
            opened: Instant::now(),
            wrote_at: None,
            first: None,
            received: 0,
            sent: 0,
            report: Some(Box::new(report)),
            load: None,
            pace: Pace::default(),
            sampled_at: None,
            live: None,
            stall: None,
        }
    }

    /// Also counts received bytes into the line's load.
    pub fn counting(mut self, load: std::sync::Arc<LineLoad>) -> Self {
        self.load = Some(load);
        self
    }

    /// Also tells `live` how the transfer goes while it runs.
    pub fn watching(mut self, live: impl Fn(Live) + Send + Sync + 'static) -> Self {
        self.live = Some(Box::new(live));
        self
    }

    fn emit(&mut self, ev: Live) {
        if let Live::Sample { .. } = ev {
            self.sampled_at = Some(Instant::now());
        }
        if let Some(live) = &self.live {
            live(ev);
        }
    }

    /// Nothing came in time: a failure now (the line is broken for this
    /// site), and nothing more at close.
    fn stalled(&mut self) {
        if let Some(report) = self.report.take() {
            report(Outcome {
                failed: true,
                connect_ms: ms(self.connect),
                ..Outcome::default()
            });
            self.emit(Live::Stalled);
        }
    }

    /// Arms the stall timer while the client waits; true once it fired.
    fn poll_stall(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(at) = self.pace.deadline().filter(|_| self.report.is_some()) else {
            self.stall = None;
            return false;
        };
        match &mut self.stall {
            Some(s) if s.deadline() == at => {}
            Some(s) => s.as_mut().reset(at),
            None => self.stall = Some(Box::pin(tokio::time::sleep_until(at))),
        }
        let fired = self
            .stall
            .as_mut()
            .is_some_and(|s| s.as_mut().poll(cx).is_ready());
        if fired {
            self.stall = None;
        }
        fired
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

impl Drop for MeteredConn {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            // Asked but never answered: the line broke after connecting
            // (reset by the server, blocked handshake). Counts as a failure.
            let failed = self.received == 0 && self.sent > 0;
            // Interim samples already carried the bytes up to the last cut.
            let since = self.sampled_at.unwrap_or(self.opened);
            report(Outcome {
                failed,
                connect_ms: ms(self.connect),
                first_ms: self.first.map_or(0.0, ms),
                bytes: self.received - self.pace.sampled,
                duration_ms: ms(since.elapsed()),
            });
        }
    }
}

impl AsyncRead for MeteredConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            if self.received == 0 {
                self.first = self.wrote_at.map(|w| w.elapsed());
            }
            self.received += n;
            if let Some(l) = &self.load {
                l.add(n);
            }
            let mut events = Vec::new();
            self.pace
                .on_read(Instant::now(), n, &mut |e| events.push(e));
            for e in events {
                self.emit(e);
            }
        }
        if res.is_pending() && self.poll_stall(cx) {
            self.stalled();
        }
        res
    }
}

impl AsyncWrite for MeteredConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !buf.is_empty() && self.wrote_at.is_none() {
            self.wrote_at = Some(Instant::now());
        }
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.sent += *n as u64;
            if *n > 0 {
                self.pace.on_write(Instant::now());
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl ProxyConn for MeteredConn {
    fn remote_destination(&self) -> String {
        self.inner.remote_destination()
    }
}

#[cfg(test)]
#[path = "metered_tests.rs"]
mod tests;
