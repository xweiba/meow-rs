//! What the user experienced on one connection: time from the first
//! request bytes to the first answer, bytes received, and whether anything
//! came back at all. Reported once, when the connection goes away.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use meow_common::ProxyConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::load::LineLoad;
use super::stats::Outcome;

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
        }
    }

    /// Also counts received bytes into the line's load.
    pub fn counting(mut self, load: std::sync::Arc<LineLoad>) -> Self {
        self.load = Some(load);
        self
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
            report(Outcome {
                failed,
                connect_ms: ms(self.connect),
                first_ms: self.first.map_or(0.0, ms),
                bytes: self.received,
                duration_ms: ms(self.opened.elapsed()),
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
