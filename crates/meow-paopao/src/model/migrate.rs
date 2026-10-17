//! Settings an older app wrote, brought to the current format (Dart:
//! `RustConfigBuilder.migrate` on load; the builder on every input, as a
//! core keeps the input an older app gave it).
//!
//! Only what never comes back is rewritten here: renamed keys, the old
//! spellings of a pick (a group's own automatic children before they were
//! modes, a group's copy of a member, `direct` / `block` where the Clash
//! names are read), the per-entry network conditions, 🚀 节点选择 on 直连.
//! What depends on the lines of the moment (a region with one line now in
//! 其他地区, AI / Google without 节点选择) stays as saved and is read by the
//! builder ([`crate::plan::legacy`]), so it comes back when the lines do.
//!
//! [`migrate_settings`] is idempotent: settings of the current format come
//! out unchanged, so it runs on anything without looking at a version.
//! What it cannot place is left as it is (the app keeps it, unread).

use serde_json::{Map, Value};

use crate::model::network::NetworkCondition;
use crate::model::outbound_tags as tags;
use crate::model::policies::{policy_by_tag, POLICIES};
use crate::model::settings::{dart_str, COPY_MARK, CUSTOM_GROUP_PREFIX};

/// The settings file format this version writes (Dart
/// `settingsFileVersion`, the `version` of proxy.json — change both
/// together). Files without one are version 0: anything before.
pub const SETTINGS_VERSION: i64 = 1;

/// The result of [`migrate_settings`].
#[derive(Debug, Clone, PartialEq)]
pub struct Migrated {
    /// The settings in the current format.
    pub settings: Value,
    /// What was changed, one line each (English, for logs and the check
    /// tool); empty when nothing was.
    pub changes: Vec<String>,
}

/// `settings` (the `settings` object of proxy.json, or of a build input)
/// in the current format; see the module docs. Anything but an object is
/// returned as it is.
pub fn migrate_settings(settings: &Value) -> Migrated {
    let Some(o) = settings.as_object() else {
        return Migrated {
            settings: settings.clone(),
            changes: Vec::new(),
        };
    };
    let mut m = Migration {
        s: o.clone(),
        changes: Vec::new(),
    };
    m.core();
    m.mixed_port();
    m.policy_use();
    m.group_use_inner();
    m.networks();
    m.custom_groups();
    m.group_edits();
    m.removed_policies();
    m.picks();
    m.direct_selected();
    Migrated {
        settings: Value::Object(m.s),
        changes: m.changes,
    }
}

/// `{"settings": {...}}` → `{"settings", "changes", "version"}`: the JSON
/// entry point (`paopao_migrate`). `version` is [`SETTINGS_VERSION`].
pub fn migrate_json(input: &str) -> Value {
    match serde_json::from_str::<Value>(input) {
        Ok(v) if v.is_object() => {
            let m = migrate_settings(v.get("settings").unwrap_or(&Value::Null));
            serde_json::json!({
                "settings": m.settings,
                "changes": m.changes,
                "version": SETTINGS_VERSION,
            })
        }
        Ok(_) => serde_json::json!({ "error": "input is not a JSON object" }),
        Err(e) => serde_json::json!({ "error": format!("input is not JSON: {e}") }),
    }
}

struct Migration {
    s: Map<String, Value>,
    changes: Vec<String>,
}

/// A mode suffix of a group's automatic child, as `group_use` names it.
fn mode_use(suffix: &str) -> Option<&'static str> {
    match suffix {
        "~auto" | "~smart" => Some("smart"),
        "~balance" => Some("balance"),
        "~fastest" => Some("fastest"),
        _ => None,
    }
}

/// A pick `value` saved for group `user`, as what it stands for now:
/// (member, the mode `user` uses it in, 固定节点). None when it is current.
///
/// - `<user>@<member>[~mode][~sticky]` (the group's own copy) → member;
/// - `<policy>~auto|~smart|~balance|~fastest` (a policy's own automatic
///   children, before 94d7024) → ♻️ 自动选择 in that mode;
/// - `auto~smart|~balance|~fastest` picked in another group (♻️ 自动选择's
///   children were members everywhere before) → ♻️ 自动选择 in that mode;
/// - `fastest` (the top-level 速度最快 before 5c54dfb) → ♻️ 自动选择 in
///   速度最快.
fn old_pick(user: &str, value: &str) -> Option<(String, Option<&'static str>, bool)> {
    if let Some(rest) = value
        .strip_prefix(user)
        .and_then(|r| r.strip_prefix(COPY_MARK))
    {
        let (rest, sticky) = match rest.strip_suffix("~sticky") {
            Some(r) => (r, true),
            None => (rest, false),
        };
        // `auto~fastest` as the origin (a copy of a child, before 94d7024).
        let (origin, mode) = match rest.rfind('~') {
            Some(i) => match mode_use(&rest[i..]) {
                Some(m) => (&rest[..i], Some(m)),
                None => (rest, None),
            },
            None => (rest, None),
        };
        if origin.is_empty() {
            return None;
        }
        return Some((origin.to_owned(), mode, sticky));
    }
    if user != tags::AUTO {
        // The top-level 速度最快 (before ♻️ 自动选择 had modes).
        if value == "fastest" {
            return Some((tags::AUTO.to_owned(), Some("fastest"), false));
        }
        if let Some(mode) = value.strip_prefix(tags::AUTO).and_then(mode_use) {
            return Some((tags::AUTO.to_owned(), Some(mode), false));
        }
    }
    if policy_by_tag(user).is_some() || user.starts_with(CUSTOM_GROUP_PREFIX) {
        if let Some(mode) = value.strip_prefix(user).and_then(mode_use) {
            return Some((tags::AUTO.to_owned(), Some(mode), false));
        }
    }
    None
}

impl Migration {
    fn note(&mut self, what: impl Into<String>) {
        self.changes.push(what.into());
    }

    fn object_mut(&mut self, key: &str) -> &mut Map<String, Value> {
        let v = self
            .s
            .entry(key)
            .or_insert_with(|| Value::Object(Map::new()));
        if !v.is_object() {
            *v = Value::Object(Map::new());
        }
        v.as_object_mut().expect("an object")
    }

    /// `core` (`singbox`: the Go core, removed; meow is the only one).
    fn core(&mut self) {
        if let Some(c) = self.s.remove("core") {
            self.note(format!("core {c}: removed (meow is the only core)"));
        }
    }

    /// 17890 was the default local port before 7890.
    fn mixed_port(&mut self) {
        if self.s.get("mixed_port").and_then(Value::as_i64) == Some(17890) {
            self.s.insert("mixed_port".into(), 7890.into());
            self.note("mixed_port 17890 -> 7890 (the old default)");
        }
    }

    /// `policy_use` (ce1cf46 … 24c3e42) is `group_use`; an entry already
    /// in `group_use` wins.
    fn policy_use(&mut self) {
        let Some(old) = self.s.remove("policy_use") else {
            return;
        };
        let Value::Object(old) = old else {
            self.s.insert("policy_use".into(), old);
            return;
        };
        let uses = self.object_mut("group_use");
        let mut moved = Vec::new();
        for (k, v) in old {
            if !uses.contains_key(&k) {
                uses.insert(k.clone(), v);
                moved.push(k);
            }
        }
        if uses.is_empty() {
            self.s.remove("group_use");
        }
        self.note(format!("policy_use -> group_use ({})", moved.join(", ")));
    }

    /// A use's `groups` (before 24c3e42) is `members`; a use `auto` is
    /// 智能选择.
    fn group_use_inner(&mut self) {
        let Some(Value::Object(uses)) = self.s.get_mut("group_use") else {
            return;
        };
        let mut notes = Vec::new();
        for (tag, u) in uses.iter_mut() {
            let Some(u) = u.as_object_mut() else { continue };
            if let Some(groups) = u.remove("groups") {
                if u.contains_key("members") {
                    u.insert("groups".into(), groups);
                } else {
                    u.insert("members".into(), groups);
                    notes.push(format!("group_use {tag}: groups -> members"));
                }
            }
            if let Some(Value::Object(members)) = u.get_mut("members") {
                for (g, m) in members.iter_mut() {
                    if let Some(m) = m.as_object_mut() {
                        if m.get("use").and_then(Value::as_str) == Some("auto") {
                            m.insert("use".into(), "smart".into());
                            notes.push(format!("group_use {tag} {g}: auto -> smart"));
                        }
                    }
                }
            }
        }
        self.changes.extend(notes);
    }

    /// Entries saved before networks were named carried their condition
    /// (`on`, earlier `ssid`): each distinct one becomes a named network
    /// (after its Wi-Fi name, else its subnet) the entry points at; the same
    /// condition shares one (Dart `_LegacyNetworks`, kept in step).
    fn networks(&mut self) {
        let mut networks: Vec<Value> = self
            .s
            .get("networks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let before = networks.len();
        let mut moved = 0;
        for key in ["hosts", "rules", "wifi"] {
            let Some(Value::Array(entries)) = self.s.get_mut(key) else {
                continue;
            };
            for e in entries.iter_mut() {
                let Some(o) = e.as_object_mut() else { continue };
                if o.get("network").is_some_and(Value::is_string) {
                    continue;
                }
                let Some(old) = o.get("on").or_else(|| o.get("ssid")).cloned() else {
                    continue;
                };
                if old.is_null() {
                    continue;
                }
                let id = NetworkCondition::from_json(&old).map(|c| id_for(&mut networks, &c));
                o.remove("on");
                o.remove("ssid");
                o.insert("network".into(), id.map_or(Value::Null, Value::from));
                moved += 1;
            }
        }
        if moved > 0 {
            if networks.len() > before || self.s.contains_key("networks") {
                self.s
                    .insert("networks".into(), Value::Array(networks.clone()));
            }
            self.note(format!(
                "{moved} entries with their own network condition -> {} named networks",
                networks.len() - before
            ));
        }
    }

    /// A user group's hand-picked `members` (before policies were
    /// generated): its outlets are its `extras`; lines and groups are its
    /// members anyway now. A pick `direct` / `block` is DIRECT / REJECT.
    fn custom_groups(&mut self) {
        let Some(Value::Array(groups)) = self.s.get_mut("custom_groups") else {
            return;
        };
        let mut notes = Vec::new();
        for g in groups.iter_mut() {
            let Some(o) = g.as_object_mut() else { continue };
            let id = o.get("id").map(dart_str).unwrap_or_default();
            if !o.contains_key("extras") {
                if let Some(members) = o.get("members").and_then(Value::as_array) {
                    let outlets: Vec<Value> = members
                        .iter()
                        .filter(|m| m.as_str().is_some_and(is_outlet))
                        .cloned()
                        .collect();
                    if !outlets.is_empty() {
                        o.insert("extras".into(), Value::Array(outlets));
                    }
                    o.remove("members");
                    notes.push(format!("custom group {id}: members -> extras (outlets)"));
                }
            }
            // Name keywords picked its lines before its members were all
            // lines (35f1d97): nothing reads them.
            if o.remove("keywords").is_some() {
                notes.push(format!(
                    "custom group {id}: keywords removed (no longer used)"
                ));
            }
            if let Some(p) = o.get("pick").and_then(Value::as_str).map(str::to_owned) {
                let clash = match p.as_str() {
                    "direct" => Some("DIRECT"),
                    "block" => Some("REJECT"),
                    _ => None,
                };
                if let Some(c) = clash {
                    o.insert("pick".into(), c.into());
                    notes.push(format!("custom group {id}: pick {p} -> {c}"));
                }
            }
        }
        self.changes.extend(notes);
    }

    /// A built-in group's edit `add` (before outlets only) is `extras`.
    fn group_edits(&mut self) {
        let Some(Value::Object(edits)) = self.s.get_mut("group_edits") else {
            return;
        };
        let mut notes = Vec::new();
        for (tag, e) in edits.iter_mut() {
            let Some(o) = e.as_object_mut() else { continue };
            if o.contains_key("extras") {
                continue;
            }
            if let Some(add) = o.remove("add") {
                let outlets: Vec<Value> = add
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|m| m.as_str().is_some_and(is_outlet))
                    .cloned()
                    .collect();
                if !outlets.is_empty() {
                    o.insert("extras".into(), Value::Array(outlets));
                }
                notes.push(format!("group edit {tag}: add -> extras (outlets)"));
            }
            // Members taken out (before 35f1d97): a group lists every
            // region now; sites are what is left out (`exclude`).
            if o.remove("remove").is_some() {
                notes.push(format!("group edit {tag}: remove dropped (no longer used)"));
            }
        }
        self.changes.extend(notes);
    }

    /// 🎮 Steam (until 76f9634) is 游戏平台 now: its pick, edits and use
    /// carry over unless 游戏平台 has its own.
    fn removed_policies(&mut self) {
        const RENAMED: [(&str, &str); 1] = [("policy:steam", "policy:games")];
        for key in ["policies", "group_edits", "group_use"] {
            let Some(Value::Object(m)) = self.s.get_mut(key) else {
                continue;
            };
            let mut notes = Vec::new();
            for (old, new) in RENAMED {
                if m.contains_key(new) {
                    continue;
                }
                if let Some(v) = m.shift_remove(old) {
                    m.insert(new.to_owned(), v);
                    notes.push(format!("{key} {old} -> {new}"));
                }
            }
            self.changes.extend(notes);
        }
    }

    /// The picks (`selected`, `policies`, `group_pick`, a user group's
    /// `pick`) in an old spelling ([`old_pick`]): the member, and the mode
    /// the group uses it in / its 固定节点 in `group_use` (unless one is
    /// saved there already).
    fn picks(&mut self) {
        let mut found: Vec<(&'static str, String, String)> = Vec::new();
        if let Some(v) = self.s.get("selected").and_then(Value::as_str) {
            found.push(("selected", tags::PROXY.to_owned(), v.to_owned()));
        }
        for key in ["policies", "group_pick"] {
            if let Some(Value::Object(m)) = self.s.get(key) {
                for (k, v) in m {
                    if let Some(v) = v.as_str() {
                        found.push((key, k.clone(), v.to_owned()));
                    }
                }
            }
        }
        if let Some(Value::Array(groups)) = self.s.get("custom_groups") {
            for g in groups {
                if let (Some(id), Some(p)) = (
                    g.get("id").and_then(Value::as_str),
                    g.get("pick").and_then(Value::as_str),
                ) {
                    found.push((
                        "custom_groups",
                        format!("{CUSTOM_GROUP_PREFIX}{id}"),
                        p.to_owned(),
                    ));
                }
            }
        }
        for (key, user, value) in found {
            let Some((member, mode, sticky)) = old_pick(&user, &value) else {
                continue;
            };
            // ♻️ 自动选择's own pick may be its mode; never itself.
            if user == tags::AUTO && member == tags::AUTO {
                continue;
            }
            match key {
                "selected" => {
                    self.s.insert("selected".into(), member.clone().into());
                }
                "custom_groups" => {
                    let id = &user[CUSTOM_GROUP_PREFIX.len()..];
                    if let Some(Value::Array(groups)) = self.s.get_mut("custom_groups") {
                        for g in groups.iter_mut() {
                            if g.get("id").and_then(Value::as_str) == Some(id) {
                                g["pick"] = member.clone().into();
                            }
                        }
                    }
                }
                _ => {
                    self.object_mut(key)
                        .insert(user.clone(), member.clone().into());
                }
            }
            let entry = self.object_mut("group_use");
            let use_ = entry
                .entry(user.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if !use_.is_object() {
                *use_ = Value::Object(Map::new());
            }
            let u = use_.as_object_mut().expect("an object");
            let is_policy = policy_by_tag(&user).is_some() || user.starts_with(CUSTOM_GROUP_PREFIX);
            if sticky && is_policy && !u.contains_key("sticky") {
                u.insert("sticky".into(), true.into());
            }
            if let Some(mode) = mode {
                let members = u
                    .entry("members")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(members) = members.as_object_mut() {
                    members
                        .entry(member.clone())
                        .or_insert_with(|| serde_json::json!({ "use": mode }));
                }
            }
            if u.is_empty() {
                self.object_mut("group_use").shift_remove(&user);
            }
            if self
                .s
                .get("group_use")
                .and_then(Value::as_object)
                .is_some_and(Map::is_empty)
            {
                self.s.remove("group_use");
            }
            let how = match (mode, sticky) {
                (Some(m), true) => format!(" ({m}, 固定节点)"),
                (Some(m), false) => format!(" ({m})"),
                (None, true) => " (固定节点)".into(),
                (None, false) => String::new(),
            };
            self.note(format!("{key} {user}: {value} -> {member}{how}"));
        }
    }

    /// 🚀 节点选择 on 直连 (before 94d7024 it offered 直连; now 直连 is a
    /// policy's): what followed 节点选择 goes 直连 by its own pick instead —
    /// the built-in policies whose default is 节点选择 and that have no pick
    /// of their own, the user's groups on 节点选择, rules to 代理 — and
    /// 节点选择 itself is 自动选择. In 全局 everything went 直连: 直连 mode.
    fn direct_selected(&mut self) {
        let selected = self.s.get("selected").and_then(Value::as_str);
        if !matches!(selected, Some("DIRECT" | "direct")) {
            return;
        }
        let was = selected.unwrap_or_default().to_owned();
        self.s.insert("selected".into(), tags::AUTO.into());
        if self.s.get("mode").and_then(Value::as_str) == Some("global") {
            self.s.insert("mode".into(), "direct".into());
            self.note(format!("selected {was} in global mode -> direct mode"));
            return;
        }
        let defaults = self.s.get("group_defaults").cloned();
        let mut moved = Vec::new();
        for p in &POLICIES {
            let tag = p.tag();
            let follows = p.fallback == tags::PROXY
                && !p.blockable
                && p.prefer_pick.is_none()
                && p.prefer_region.is_none()
                && !p.sticky_exit
                && p.avoid_regions.is_empty();
            let saved = self
                .s
                .get("policies")
                .and_then(|m| m.get(&tag))
                .and_then(Value::as_str);
            let default = defaults
                .as_ref()
                .and_then(|d| d.get(&tag))
                .and_then(Value::as_str);
            let on_select = match saved {
                Some(v) => v == tags::PROXY,
                None => match default {
                    Some(d) => d == "select",
                    None => follows,
                },
            };
            if on_select {
                self.object_mut("policies")
                    .insert(tag.clone(), tags::DIRECT.into());
                moved.push(tag);
            }
        }
        let picks = self.s.get("group_pick").cloned();
        if let Some(Value::Array(groups)) = self.s.get_mut("custom_groups") {
            for g in groups.iter_mut() {
                let Some(id) = g.get("id").and_then(Value::as_str).map(str::to_owned) else {
                    continue;
                };
                let tag = format!("{CUSTOM_GROUP_PREFIX}{id}");
                let pick = picks
                    .as_ref()
                    .and_then(|p| p.get(&tag))
                    .and_then(Value::as_str)
                    .or_else(|| g.get("pick").and_then(Value::as_str))
                    .unwrap_or(tags::PROXY);
                if pick == tags::PROXY {
                    g["pick"] = "DIRECT".into();
                    moved.push(tag);
                }
            }
        }
        if let Some(Value::Object(picks)) = self.s.get_mut("group_pick") {
            for (k, v) in picks.iter_mut() {
                if k.starts_with(CUSTOM_GROUP_PREFIX) && v.as_str() == Some(tags::PROXY) {
                    *v = "DIRECT".into();
                }
            }
        }
        let mut rules = 0;
        if let Some(Value::Array(list)) = self.s.get_mut("rules") {
            for r in list.iter_mut() {
                let Some(o) = r.as_object_mut() else { continue };
                let to_proxy = match o.get("target") {
                    None | Some(Value::Null) => true,
                    Some(t) => t.as_str() == Some("proxy"),
                };
                if to_proxy {
                    o.insert("target".into(), "direct".into());
                    rules += 1;
                }
            }
        }
        self.note(format!(
            "selected {was} (节点选择 on 直连) -> auto; on 直连 by their own pick: {}; {rules} rules to 代理 -> 直连",
            moved.join(", ")
        ));
    }
}

/// An interface or SSH chain ([`crate::model::settings::is_extra_outlet`]).
fn is_outlet(m: &str) -> bool {
    crate::model::settings::is_extra_outlet(m)
}

/// The id of the network holding condition `c`, added when none does:
/// `net-<n>`, the first free n; named after the Wi-Fi name, else the
/// subnet, else `网络 <n>`, made unique with ` 2`, ` 3` …
fn id_for(networks: &mut Vec<Value>, c: &NetworkCondition) -> String {
    for n in networks.iter() {
        let same = n
            .get("on")
            .and_then(NetworkCondition::from_json)
            .is_some_and(|x| x == *c);
        if same {
            if let Some(id) = n.get("id").and_then(Value::as_str) {
                return id.to_owned();
            }
        }
    }
    let ids: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.get("id").and_then(Value::as_str))
        .collect();
    let mut i = 1;
    while ids.contains(&format!("net-{i}").as_str()) {
        i += 1;
    }
    let base = [c.name.as_deref(), c.subnet.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|t| !t.is_empty())
        .map_or_else(|| format!("网络 {i}"), str::to_owned);
    let names: Vec<&str> = networks
        .iter()
        .filter_map(|n| n.get("name").and_then(Value::as_str))
        .collect();
    let mut name = base.clone();
    let mut k = 2;
    while names.contains(&name.as_str()) {
        name = format!("{base} {k}");
        k += 1;
    }
    let id = format!("net-{i}");
    let mut on = Map::new();
    if let Some(n) = &c.name {
        on.insert("name".into(), n.clone().into());
    }
    if let Some(s) = &c.subnet {
        on.insert("subnet".into(), s.clone().into());
    }
    let mut n = Map::new();
    n.insert("id".into(), id.clone().into());
    n.insert("name".into(), name.into());
    n.insert("on".into(), Value::Object(on));
    networks.push(Value::Object(n));
    id
}
