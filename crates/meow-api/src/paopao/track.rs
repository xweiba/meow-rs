//! 虚拟定位's moving point (Dart `ProxyController.startTrack`, `TrackPlan`
//! in `virtual_location.dart`), kept in the core so a trip goes on with the
//! app closed, and the config the location script reads.
//!
//! The location script (run by the core's MITM) reads its config from the
//! scripts' store first (`<home>/modules/store.json`, key
//! [`CACHE_KEY`]: `{url, ts, data}`), from the route API's
//! `/v1/location.json` when that is old. A trip (`PUT
//! /paopao/location/track`: `{points: [{lat, lon, acc?}], speed (m/s),
//! loop, step_ms?, config_url, started?}`, kept in `track.json` with its
//! start: now, or `started` for one under way)
//! moves the point there every step, straight between the points, until
//! it arrives (or for good with `loop`); `DELETE` ends it. One task asleep
//! between steps, holding the trip's few numbers.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::service::{now_ms, Service};
use super::store::{write_atomic, Store};

/// Where the location script caches its remote config.
pub const CACHE_KEY: &str = "location_spoofer_remote_cfg";
/// The scripts' store under the core's home.
pub const STORE_PATH: &str = "modules/store.json";
/// The built-in 虚拟定位 module.
pub const LOCATION_MODULE: &str = "builtin:location-spoofer";
/// Steps unless told (Dart `startTrack`'s `step`).
const STEP_MS: u64 = 2000;

/// A place in WGS-84 (Dart `VirtualPoint`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub lat: f64,
    pub lon: f64,
    #[serde(default = "default_acc")]
    pub acc: i64,
}

fn default_acc() -> i64 {
    25
}

impl Point {
    /// Meters to `o` (great circle).
    pub fn distance_to(&self, o: &Self) -> f64 {
        const R: f64 = 6_371_000.0;
        let (d_lat, d_lon) = (
            (o.lat - self.lat).to_radians(),
            (o.lon - self.lon).to_radians(),
        );
        let a = (d_lat / 2.0).sin().powi(2)
            + self.lat.to_radians().cos() * o.lat.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
        2.0 * R * a.sqrt().min(1.0).asin()
    }

    /// The script's config (Dart `VirtualPoint.toConfig`).
    pub fn to_config(&self, enabled: bool) -> Value {
        json!({
            "enabled": enabled,
            "mode": "response",
            "latitude": self.lat,
            "longitude": self.lon,
            "horizontalAccuracy": self.acc,
            "failOpen": true,
            "debug": false,
        })
    }
}

/// A trip (`track.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Track {
    pub points: Vec<Point>,
    /// Meters a second.
    pub speed: f64,
    #[serde(default)]
    pub r#loop: bool,
    #[serde(default = "default_step")]
    pub step_ms: u64,
    /// The URL the script's cached config names (the route API's).
    pub config_url: String,
    /// When it set off, Unix ms.
    #[serde(default)]
    pub started: i64,
}

fn default_step() -> u64 {
    STEP_MS
}

impl Track {
    pub fn read(store: &Store) -> Option<Self> {
        std::fs::read(store.track())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    /// Meters along the whole route (back to the start too when looping).
    pub fn length(&self) -> f64 {
        let mut d: f64 = self
            .points
            .windows(2)
            .map(|w| w[0].distance_to(&w[1]))
            .sum();
        if self.r#loop && self.points.len() > 2 {
            d += self.points[self.points.len() - 1].distance_to(&self.points[0]);
        }
        d
    }

    /// Where it is `elapsed_ms` after setting off, and whether it arrived
    /// (Dart `TrackPlan.at`).
    pub fn at(&self, elapsed_ms: i64) -> Option<(Point, bool)> {
        let first = *self.points.first()?;
        if self.points.len() == 1 {
            return Some((first, true));
        }
        let last = self.points[self.points.len() - 1];
        let total = self.length();
        #[allow(clippy::cast_precision_loss)]
        let mut travelled = self.speed * elapsed_ms as f64 / 1000.0;
        if !self.r#loop && travelled >= total {
            return Some((last, true));
        }
        if total > 0.0 {
            travelled %= total;
        }
        let mut legs: Vec<(Point, Point)> = self.points.windows(2).map(|w| (w[0], w[1])).collect();
        if self.r#loop && self.points.len() > 2 {
            legs.push((last, first));
        }
        for (a, b) in legs {
            let d = a.distance_to(&b);
            if travelled <= d || d == 0.0 {
                let f = if d == 0.0 { 0.0 } else { travelled / d };
                let p = Point {
                    lat: a.lat + (b.lat - a.lat) * f,
                    lon: a.lon + (b.lon - a.lon) * f,
                    acc: a.acc,
                };
                return Some((p, false));
            }
            travelled -= d;
        }
        Some((last, !self.r#loop))
    }
}

/// The scripts' store as JSON.
fn read_store(home: &std::path::Path) -> Map<String, Value> {
    std::fs::read(home.join(STORE_PATH))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Puts `p` where the script looks first (Dart `ModuleStore.savePoint`):
/// used on its very next answer.
pub fn save_point(
    home: &std::path::Path,
    p: &Point,
    config_url: &str,
    enabled: bool,
) -> std::io::Result<()> {
    let mut all = read_store(home);
    let cached = json!({ "url": config_url, "ts": now_ms(), "data": p.to_config(enabled) });
    all.insert(CACHE_KEY.into(), cached.to_string().into());
    let bytes = serde_json::to_vec_pretty(&all).map_err(std::io::Error::other)?;
    write_atomic(&home.join(STORE_PATH), &bytes, false)
}

/// The script's config as the route API serves it (Dart
/// `_locationConfig`): the point the store holds, `enabled` as the
/// module is; None without a point.
pub async fn location_config(svc: &Service) -> Option<Value> {
    let home = svc.store().home().to_owned();
    let cached = tokio::task::spawn_blocking(move || read_store(&home))
        .await
        .ok()?
        .get(CACHE_KEY)?
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())?;
    let mut data = cached.get("data")?.as_object()?.clone();
    if let Some(on) = svc.location_module_on().await {
        data.insert("enabled".into(), on.into());
    }
    Some(Value::Object(data))
}

impl Service {
    /// Sets off on `t` now (replacing a trip under way).
    pub async fn start_track(&self, mut t: Track) -> Result<(), String> {
        if t.points.is_empty() {
            return Err("no points".into());
        }
        if !(t.speed.is_finite() && t.speed > 0.0) {
            return Err("speed must be above 0".into());
        }
        // Handed over under way (the app's trip): as far along as it is.
        let now = now_ms();
        if t.started <= 0 || t.started > now {
            t.started = now;
        }
        t.step_ms = t.step_ms.clamp(200, 60_000);
        let store = self.store().clone();
        let bytes = serde_json::to_vec(&t).map_err(|e| e.to_string())?;
        tokio::task::spawn_blocking(move || write_atomic(&store.track(), &bytes, false))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("cannot keep the trip: {e}"))?;
        self.wake_track();
        Ok(())
    }

    pub async fn stop_track(&self) {
        let _ = tokio::fs::remove_file(self.store().track()).await;
        self.wake_track();
    }

    /// `GET /paopao/location/track`: the trip and where it is now.
    pub fn track_answer(&self) -> Value {
        let Some(t) = Track::read(self.store()) else {
            return json!({ "track": null });
        };
        let at = t.at(now_ms() - t.started);
        json!({
            "track": t,
            "point": at.map(|(p, _)| p),
            "done": at.is_none_or(|(_, done)| done),
        })
    }
}

/// Moves the point along the trip while there is one. Runs for good:
/// spawn it.
pub async fn run_track(svc: Arc<Service>) {
    loop {
        let step = match Track::read(svc.store()) {
            None => None,
            Some(t) => {
                let home = svc.store().home().to_owned();
                match t.at(now_ms() - t.started) {
                    Some((p, done)) => {
                        let url = t.config_url.clone();
                        let _ =
                            tokio::task::spawn_blocking(move || save_point(&home, &p, &url, true))
                                .await;
                        if done {
                            let _ = tokio::fs::remove_file(svc.store().track()).await;
                            None
                        } else {
                            Some(Duration::from_millis(t.step_ms))
                        }
                    }
                    None => None,
                }
            }
        };
        match step {
            Some(d) => {
                tokio::select! {
                    () = tokio::time::sleep(d) => {}
                    () = svc.track_woken() => {}
                }
            }
            None => svc.track_woken().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(lat: f64, lon: f64) -> Point {
        Point { lat, lon, acc: 25 }
    }

    #[test]
    fn a_trip_moves_and_arrives() {
        let t = Track {
            points: vec![p(0.0, 0.0), p(0.0, 0.001), p(0.001, 0.001)],
            speed: 10.0,
            r#loop: false,
            step_ms: 2000,
            config_url: "u".into(),
            started: 0,
        };
        let leg = p(0.0, 0.0).distance_to(&p(0.0, 0.001));
        assert!((leg - 111.19).abs() < 0.1, "{leg}");
        let (at, done) = t.at(5000).unwrap();
        assert!(!done && at.lat == 0.0 && (at.lon - 0.05 / leg * 0.001 * 1000.0).abs() < 1e-9);
        assert_eq!(t.at(1_000_000).unwrap(), (p(0.001, 0.001), true));
        let looping = Track {
            r#loop: true,
            ..t.clone()
        };
        assert!(!looping.at(1_000_000).unwrap().1);
        assert!(looping.length() > t.length());
        let one = Track {
            points: vec![p(1.0, 2.0)],
            ..t
        };
        assert_eq!(one.at(0).unwrap(), (p(1.0, 2.0), true));
    }

    #[test]
    fn the_point_goes_where_the_script_looks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("modules")).unwrap();
        std::fs::write(dir.path().join(STORE_PATH), r#"{"other": "kept"}"#).unwrap();
        save_point(
            dir.path(),
            &p(31.2, 121.5),
            "http://127.0.0.1:17899/v1/location.json?key=k",
            true,
        )
        .unwrap();
        let all = read_store(dir.path());
        assert_eq!(all["other"], "kept");
        let cached: Value = serde_json::from_str(all[CACHE_KEY].as_str().unwrap()).unwrap();
        assert_eq!(
            cached["url"],
            "http://127.0.0.1:17899/v1/location.json?key=k"
        );
        assert_eq!(
            cached["data"],
            json!({"enabled": true, "mode": "response", "latitude": 31.2, "longitude": 121.5,
                   "horizontalAccuracy": 25, "failOpen": true, "debug": false})
        );
    }
}
