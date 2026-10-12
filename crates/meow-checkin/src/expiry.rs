//! 登录失效: does this answer mean the login is gone?
//!
//! Signs, any one is enough:
//!
//! 1. status 401 or 403, unless the request already answered so when it
//!    was recorded;
//! 2. a redirect (followed or not) to an address that looks like a login
//!    page, while the request itself is not to one;
//! 3. the request answered JSON when it was recorded and answers an HTML
//!    page with a password field or a login-looking address now;
//! 4. a short or JSON answer holding one of the "not logged in" texts.
//!
//! The login-page path fragments and the texts are [`Markers`]: built-in
//! lists plus what `checkin.json` adds under `settings`.

use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Markers {
    /// Lower-case path fragments.
    pub login_paths: Vec<String>,
    /// Lower-case texts.
    pub logged_out_texts: Vec<String>,
}

impl Default for Markers {
    fn default() -> Self {
        let own = |list: &[&str]| list.iter().map(|s| (*s).to_string()).collect();
        Self {
            login_paths: own(&[
                "/login",
                "/signin",
                "/sign-in",
                "/sign_in",
                "/logon",
                "/auth/",
                "/passport",
                "/sso",
                "/oauth",
                "/account/login",
                "/user/login",
            ]),
            logged_out_texts: own(&[
                "未登录",
                "未登入",
                "请先登录",
                "请登录",
                "请重新登录",
                "登录已过期",
                "登录失效",
                "登录超时",
                "登录状态已失效",
                "not logged in",
                "not login",
                "login required",
                "please log in",
                "please login",
                "unauthenticated",
                "unauthorized",
                "token expired",
                "session expired",
                "invalid token",
            ]),
        }
    }
}

impl Markers {
    /// The built-in markers plus `login_paths` and `texts`.
    pub fn with_extra(login_paths: &[String], texts: &[String]) -> Self {
        let mut m = Self::default();
        let clean = |s: &String| {
            let s = s.trim().to_lowercase();
            (!s.is_empty() && s.len() <= 200).then_some(s)
        };
        for p in login_paths.iter().filter_map(clean).take(50) {
            if !m.login_paths.contains(&p) {
                m.login_paths.push(p);
            }
        }
        for t in texts.iter().filter_map(clean).take(50) {
            if !m.logged_out_texts.contains(&t) {
                m.logged_out_texts.push(t);
            }
        }
        m
    }

    /// Does the address look like a login page?
    pub fn is_login_url(&self, url: &Url) -> bool {
        let path = url.path().to_ascii_lowercase();
        // The fragment as a whole path segment prefix: `/login`,
        // `/login.php`, `/auth/login`, not `/loginhistory`.
        self.login_paths.iter().any(|frag| {
            path.match_indices(frag.as_str()).any(|(at, _)| {
                frag.ends_with('/')
                    || path[at + frag.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_ascii_alphanumeric())
            })
        })
    }
}

/// What a replayed request came back with.
#[derive(Clone, Copy, Debug)]
pub struct Observation<'a> {
    pub status: u16,
    /// The address the request was sent to first.
    pub request_url: &'a Url,
    /// Where a redirect pointed, whether or not it was followed.
    pub redirected_to: Option<&'a Url>,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
    pub recorded_status: Option<u16>,
    pub recorded_content_type: Option<&'a str>,
}

fn mime(content_type: Option<&str>) -> String {
    content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

pub fn is_json(content_type: Option<&str>) -> bool {
    let m = mime(content_type);
    m == "application/json" || m.ends_with("+json") || m == "text/json"
}

pub fn is_html(content_type: Option<&str>) -> bool {
    let m = mime(content_type);
    m == "text/html" || m == "application/xhtml+xml"
}

fn has_password_field(body_lower: &str) -> bool {
    body_lower.contains("type=\"password\"")
        || body_lower.contains("type='password'")
        || body_lower.contains("type=password")
}

/// Texts are looked for in this much of the answer.
const SCAN_BYTES: usize = 8 * 1024;
/// A non-JSON answer longer than this is a page, not a message: its texts
/// say nothing ("请登录" is in every page's header).
const SHORT_ANSWER: usize = 2 * 1024;

pub fn looks_logged_out(o: &Observation<'_>, markers: &Markers) -> bool {
    if matches!(o.status, 401 | 403) && o.recorded_status != Some(o.status) {
        return true;
    }
    let to_login = o.redirected_to.is_some_and(|u| markers.is_login_url(u));
    if to_login && !markers.is_login_url(o.request_url) {
        return true;
    }
    let scan = &o.body[..o.body.len().min(SCAN_BYTES)];
    let text = String::from_utf8_lossy(scan).to_lowercase();
    // A page asking for a password where the recording got data, or
    // anything but a page.
    let was_not_a_page = is_json(o.recorded_content_type)
        || o.recorded_content_type.is_some_and(|c| !is_html(Some(c)));
    if is_html(o.content_type) && has_password_field(&text) && was_not_a_page {
        return true;
    }
    let is_message = is_json(o.content_type) || o.body.len() <= SHORT_ANSWER;
    if is_message
        && markers
            .logged_out_texts
            .iter()
            .any(|t| text.contains(t.as_str()))
    {
        return true;
    }
    false
}

/// A click step's page ended on a login-looking address other than the
/// step's own page.
pub fn click_ended_on_login(final_url: Option<&str>, page: &str, markers: &Markers) -> bool {
    let Some(end) = final_url.and_then(|u| Url::parse(u).ok()) else {
        return false;
    };
    let same =
        Url::parse(page).is_ok_and(|p| p.host_str() == end.host_str() && p.path() == end.path());
    !same && markers.is_login_url(&end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn obs<'a>(status: u16, request: &'a Url, body: &'a [u8]) -> Observation<'a> {
        Observation {
            status,
            request_url: request,
            redirected_to: None,
            content_type: Some("application/json"),
            body,
            recorded_status: Some(200),
            recorded_content_type: Some("application/json"),
        }
    }

    #[test]
    fn login_addresses() {
        let m = Markers::default();
        for u in [
            "https://a.example/login",
            "https://a.example/auth/login?next=/user",
            "https://a.example/user/login.php",
            "https://a.example/Signin",
            "https://a.example/passport/index",
            "https://a.example/auth/",
        ] {
            assert!(m.is_login_url(&url(u)), "{u}");
        }
        for u in [
            "https://a.example/user",
            "https://a.example/loginhistory",
            "https://a.example/user/checkin",
            "https://a.example/?next=/login",
        ] {
            assert!(!m.is_login_url(&url(u)), "{u}");
        }
    }

    #[test]
    fn status_401_and_403() {
        let m = Markers::default();
        let u = url("https://a.example/user/checkin");
        assert!(looks_logged_out(&obs(401, &u, b"{}"), &m));
        assert!(looks_logged_out(&obs(403, &u, b"{}"), &m));
        assert!(!looks_logged_out(&obs(200, &u, b"{}"), &m));
        assert!(!looks_logged_out(&obs(500, &u, b"{}"), &m));
        // It answered 403 when recorded too: not a sign.
        let mut o = obs(403, &u, b"{}");
        o.recorded_status = Some(403);
        assert!(!looks_logged_out(&o, &m));
    }

    #[test]
    fn redirect_to_a_login_page() {
        let m = Markers::default();
        let u = url("https://a.example/user/checkin");
        let login = url("https://a.example/auth/login");
        let other = url("https://a.example/user/done");
        let mut o = obs(302, &u, b"");
        o.redirected_to = Some(&login);
        assert!(looks_logged_out(&o, &m));
        o.redirected_to = Some(&other);
        assert!(!looks_logged_out(&o, &m));
        // The step is the login request itself.
        let own = url("https://a.example/auth/login");
        let mut o = obs(302, &own, b"");
        o.redirected_to = Some(&login);
        assert!(!looks_logged_out(&o, &m));
    }

    #[test]
    fn was_json_is_a_login_page_now() {
        let m = Markers::default();
        let u = url("https://a.example/user/checkin");
        let page = b"<html><form><input type=\"password\" name=p></form></html>";
        let mut o = obs(200, &u, page);
        o.content_type = Some("text/html; charset=utf-8");
        assert!(looks_logged_out(&o, &m));
        // It was a page when recorded: a password field proves nothing.
        o.recorded_content_type = Some("text/html");
        assert!(!looks_logged_out(&o, &m));
        // A page without a password field (a challenge page) is a failure,
        // not a lost login.
        let mut o = obs(200, &u, b"<html>checking your browser</html>");
        o.content_type = Some("text/html");
        assert!(!looks_logged_out(&o, &m));
    }

    #[test]
    fn texts_in_short_or_json_answers() {
        let m = Markers::default();
        let u = url("https://a.example/user/checkin");
        assert!(looks_logged_out(
            &obs(200, &u, r#"{"ret":0,"msg":"请先登录"}"#.as_bytes()),
            &m
        ));
        assert!(looks_logged_out(
            &obs(200, &u, br#"{"error":"Unauthenticated."}"#),
            &m
        ));
        assert!(!looks_logged_out(
            &obs(
                200,
                &u,
                r#"{"ret":1,"msg":"获得了 312 MB 流量"}"#.as_bytes()
            ),
            &m
        ));
        // A long page mentioning 请登录 somewhere is not a sign.
        let mut long = "<html>".repeat(600);
        long.push_str("请登录");
        let mut o = obs(200, &u, long.as_bytes());
        o.content_type = Some("text/html");
        o.recorded_content_type = Some("text/html");
        assert!(!looks_logged_out(&o, &m));
    }

    #[test]
    fn markers_can_be_added() {
        let m = Markers::with_extra(&["/Member/Enter".into()], &["SESSION_GONE".into()]);
        assert!(m.is_login_url(&url("https://a.example/member/enter")));
        let u = url("https://a.example/api");
        assert!(looks_logged_out(
            &obs(200, &u, b"{\"e\":\"session_gone\"}"),
            &m
        ));
        assert!(!looks_logged_out(
            &obs(200, &u, b"{\"e\":\"session_gone\"}"),
            &Markers::default()
        ));
    }

    #[test]
    fn click_reports() {
        let m = Markers::default();
        let page = "https://a.example/user";
        assert!(click_ended_on_login(
            Some("https://a.example/auth/login"),
            page,
            &m
        ));
        assert!(!click_ended_on_login(
            Some("https://a.example/user"),
            page,
            &m
        ));
        assert!(!click_ended_on_login(None, page, &m));
        // The step's own page is a login-looking address: no sign.
        assert!(!click_ended_on_login(
            Some("https://a.example/login"),
            "https://a.example/login",
            &m
        ));
    }
}
