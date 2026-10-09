//! The config page (axum, on 127.0.0.1; the box's TCP 80 is bridged to
//! it): one embedded page and a small JSON API behind Basic auth (user
//! `admin`).

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::App;

/// The page (Chinese, no external assets).
const PAGE: &str = include_str!("admin.html");

/// The page and its API.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/status", get(status))
        .route("/api/subscriptions", post(add_subscription))
        .route("/api/subscriptions/{id}", delete(remove_subscription))
        .route("/api/refresh", post(refresh))
        .route("/api/mode", post(set_mode))
        .route("/api/password", post(set_password))
        .route("/api/dns", post(set_dns))
        .layer(middleware::from_fn_with_state(Arc::clone(&app), auth))
        .with_state(app)
}

/// `Authorization: Basic …` → (user, password).
pub fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, b64) = v.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_owned(), p.to_owned()))
}

async fn auth(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let ok = basic_credentials(req.headers()).is_some_and(|(u, p)| app.check_login(&u, &p));
    if ok {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"PaoPao\", charset=\"UTF-8\"",
        )],
        "请输入账号 admin 和启动时显示的密码",
    )
        .into_response()
}

async fn page() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        PAGE,
    )
        .into_response()
}

fn done(r: anyhow::Result<()>) -> Response {
    match r {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("{e:#}") })),
        )
            .into_response(),
    }
}

async fn status(State(app): State<Arc<App>>) -> Json<Value> {
    Json(app.status().await)
}

#[derive(Deserialize)]
struct UrlBody {
    url: String,
}

async fn add_subscription(State(app): State<Arc<App>>, Json(b): Json<UrlBody>) -> Response {
    done(app.add_subscription(&b.url).await)
}

async fn remove_subscription(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    done(app.remove_subscription(&id).await)
}

async fn refresh(State(app): State<Arc<App>>) -> Response {
    // Downloads take a while: answer now, the page polls the status.
    tokio::spawn(async move {
        if let Err(e) = app.refresh_subscriptions().await {
            tracing::warn!("subscription refresh: {e:#}");
        }
    });
    done(Ok(()))
}

#[derive(Deserialize)]
struct ModeBody {
    mode: String,
}

async fn set_mode(State(app): State<Arc<App>>, Json(b): Json<ModeBody>) -> Response {
    done(app.set_mode(&b.mode).await)
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

async fn set_password(State(app): State<Arc<App>>, Json(b): Json<PasswordBody>) -> Response {
    done(app.set_password(&b.password))
}

#[derive(Deserialize)]
struct DnsBody {
    upstreams: Vec<String>,
}

async fn set_dns(State(app): State<Arc<App>>, Json(b): Json<DnsBody>) -> Response {
    done(app.set_dns_upstreams(&b.upstreams))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn basic_auth_header() {
        let mut h = HeaderMap::new();
        assert!(basic_credentials(&h).is_none());
        let v = base64::engine::general_purpose::STANDARD.encode("admin:p:w");
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {v}")).unwrap(),
        );
        assert_eq!(
            basic_credentials(&h),
            Some(("admin".into(), "p:w".into())),
            "the password may hold a colon"
        );
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert!(basic_credentials(&h).is_none());
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!"));
        assert!(basic_credentials(&h).is_none());
    }

    #[test]
    fn page_is_small_and_chinese() {
        assert!(PAGE.len() < 32 * 1024);
        assert!(PAGE.contains("旁路由"));
        assert!(
            !PAGE.contains("http://") && !PAGE.contains("https://"),
            "no external assets"
        );
    }
}
