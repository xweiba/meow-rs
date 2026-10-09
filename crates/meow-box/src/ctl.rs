//! A minimal client for the core's REST API on 127.0.0.1: config reloads
//! (`PUT /configs`), traffic totals, the current line.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context as _};
use base64::Engine as _;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(20);

/// The core's API.
#[derive(Clone)]
pub struct Api {
    pub addr: SocketAddr,
    secret: String,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// Percent-encodes a path segment (group names have spaces, `~`, CJK).
pub fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The status code and body of a raw HTTP/1.x response.
pub fn parse_response(raw: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("no end of headers")?;
    let head = std::str::from_utf8(&raw[..end]).context("headers not UTF-8")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("no status")?;
    let body = &raw[end + 4..];
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let nl = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("bad chunk")?;
        let size_text = std::str::from_utf8(&rest[..nl])?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .context("bad chunk size")?;
        rest = &rest[nl + 2..];
        if size == 0 {
            break;
        }
        out.extend_from_slice(rest.get(..size).context("short chunk")?);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    Ok((status, out))
}

impl Api {
    /// The API at `addr` with `secret`.
    pub fn new(addr: SocketAddr, secret: String) -> Self {
        Self { addr, secret }
    }

    /// One request; (status, body).
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        tokio::time::timeout(TIMEOUT, async {
            let mut s = TcpStream::connect(self.addr).await?;
            let mut req = format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
                self.addr, self.secret
            );
            if let Some(b) = body {
                req.push_str("Content-Type: application/json\r\n");
                let _ = write!(req, "Content-Length: {}\r\n", b.len());
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes()).await?;
            if let Some(b) = body {
                s.write_all(b).await?;
            }
            let mut raw = Vec::new();
            s.read_to_end(&mut raw).await?;
            parse_response(&raw)
        })
        .await
        .context("core API timed out")?
    }

    /// GET a JSON document.
    pub async fn get_json(&self, path: &str) -> anyhow::Result<Value> {
        let (status, body) = self.request("GET", path, None).await?;
        if status != 200 {
            bail!("core API {path}: HTTP {status}");
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Hot-reloads the running core with `yaml`.
    pub async fn reload(&self, yaml: &str) -> anyhow::Result<()> {
        let payload = base64::engine::general_purpose::STANDARD.encode(yaml);
        let body = serde_json::to_vec(&json!({ "payload": payload }))?;
        let (status, resp) = self
            .request("PUT", "/configs?force=true", Some(&body))
            .await?;
        if !(200..300).contains(&status) {
            bail!(
                "reload refused (HTTP {status}): {}",
                String::from_utf8_lossy(&resp)
                    .chars()
                    .take(200)
                    .collect::<String>()
            );
        }
        Ok(())
    }

    /// (upload, download) byte totals.
    pub async fn totals(&self) -> anyhow::Result<(u64, u64)> {
        let v = self.get_json("/connections").await?;
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Ok((n("uploadTotal"), n("downloadTotal")))
    }

    /// The line traffic takes now: from the `proxy` group down through the
    /// groups' picks to a line.
    pub async fn current_line(&self) -> anyhow::Result<Option<String>> {
        let mut name = "proxy".to_owned();
        for _ in 0..6 {
            let v = self
                .get_json(&format!("/proxies/{}", path_segment(&name)))
                .await?;
            match v.get("now").and_then(Value::as_str) {
                Some(next) if !next.is_empty() => name = next.to_owned(),
                _ => return Ok(Some(name)),
            }
        }
        Ok(Some(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_plain_and_chunked() {
        let (s, b) = parse_response(b"HTTP/1.1 204 No Content\r\nX: y\r\n\r\n").unwrap();
        assert_eq!((s, b.len()), (204, 0));
        let (s, b) = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((s, b.as_slice()), (200, &b"{}"[..]));
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().1, b"abcde");
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn segments_are_encoded() {
        assert_eq!(path_segment("auto~smart"), "auto~smart");
        assert_eq!(path_segment("region:HK"), "region%3AHK");
        assert_eq!(path_segment("香港 01"), "%E9%A6%99%E6%B8%AF%2001");
    }

    #[test]
    fn requests_carry_the_secret_and_follow_picks() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (mut s, _) = l.accept().await.unwrap();
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let body = if req.contains("Authorization: Bearer k\r\n") {
                        let path = req.split_whitespace().nth(1).unwrap().to_owned();
                        let json = match path.as_str() {
                            "/proxies/proxy" => r#"{"now":"auto"}"#,
                            "/proxies/auto" => r#"{"now":"%E9%A6%99"}"#,
                            "/connections" => r#"{"uploadTotal":5,"downloadTotal":7}"#,
                            _ => r#"{"type":"Shadowsocks"}"#,
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{json}",
                            json.len()
                        )
                    } else {
                        "HTTP/1.1 401 x\r\n\r\n".to_owned()
                    };
                    s.write_all(body.as_bytes()).await.unwrap();
                }
            });
            let api = Api::new(addr, "k".into());
            assert_eq!(api.totals().await.unwrap(), (5, 7));
            assert_eq!(api.current_line().await.unwrap().unwrap(), "%E9%A6%99");
            let bad = Api::new(addr, "wrong".into());
            assert!(bad.totals().await.is_err());
        });
    }
}
