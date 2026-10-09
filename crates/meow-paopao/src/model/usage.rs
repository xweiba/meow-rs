//! Traffic left on a subscription (Dart: `Usage` in `pool.dart`).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::dart::{int_try_parse, Dv};

/// Milliseconds Dart's `DateTime` can hold (±100,000,000 days).
const MAX_DATE_MS: i64 = 8_640_000_000_000_000;

/// The account's traffic, from the `subscription-userinfo` header or the
/// provider's info rows.
///
/// JSON: `{"upload", "download", "total", "expire"?}`, bytes and Unix
/// milliseconds (UTC).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Bytes uploaded this period.
    pub upload: i64,
    /// Bytes downloaded this period.
    pub download: i64,
    /// Bytes the plan allows; 0 = unknown.
    pub total: i64,
    /// When the plan ends, Unix milliseconds (UTC); None = never / unknown.
    pub expire: Option<i64>,
}

impl Usage {
    /// Bytes used (upload + download).
    pub fn used(&self) -> i64 {
        self.upload.wrapping_add(self.download)
    }

    /// Reads a `subscription-userinfo` header
    /// (`upload=1; download=2; total=3; expire=1798732800`).
    ///
    /// Parts are `key=value` with exactly one `=`; a value that is not an int
    /// counts as 0. None when no part is well-formed. `expire` is in seconds;
    /// 0 means none. An expiry beyond Dart's `DateTime` range makes Dart throw;
    /// here the header is then treated as unusable (None).
    pub fn parse(header: &str) -> Option<Self> {
        // Dart map: a repeated key keeps its first position, takes the last value.
        let mut v: Vec<(&str, i64)> = Vec::new();
        for part in header.split(';') {
            let kv: Vec<&str> = crate::dart::trim(part).split('=').collect();
            if let [k, val] = kv[..] {
                let key = crate::dart::trim(k);
                let n = int_try_parse(val).unwrap_or(0);
                match v.iter_mut().find(|(k2, _)| *k2 == key) {
                    Some(e) => e.1 = n,
                    None => v.push((key, n)),
                }
            }
        }
        if v.is_empty() {
            return None;
        }
        let get = |k: &str| v.iter().find(|(k2, _)| *k2 == k).map(|(_, n)| *n);
        let expire = match get("expire") {
            None | Some(0) => None,
            Some(secs) => {
                let ms = secs.wrapping_mul(1000);
                if !(-MAX_DATE_MS..=MAX_DATE_MS).contains(&ms) {
                    return None;
                }
                Some(ms)
            }
        };
        Some(Self {
            upload: get("upload").unwrap_or(0),
            download: get("download").unwrap_or(0),
            total: get("total").unwrap_or(0),
            expire,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("upload".into(), self.upload.into());
        m.insert("download".into(), self.download.into());
        m.insert("total".into(), self.total.into());
        if let Some(e) = self.expire {
            m.insert("expire".into(), e.into());
        }
        Value::Object(m)
    }

    /// Dart `Usage.fromJson`: None when not an object; numbers are truncated
    /// to ints, anything else reads as 0 / no expiry.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let int = |k: &str| {
            o.get(k)
                .and_then(|x| Dv::from_json(x).as_int_opt().ok().flatten())
        };
        Some(Self {
            upload: int("upload").unwrap_or(0),
            download: int("download").unwrap_or(0),
            total: int("total").unwrap_or(0),
            expire: int("expire"),
        })
    }
}

impl Serialize for Usage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Usage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Self::from_json(&v).ok_or_else(|| serde::de::Error::custom("usage is not an object"))
    }
}
