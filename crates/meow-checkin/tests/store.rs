//! The engine's files: what is in which, who can read them, and how
//! loading copes with what it finds.

mod support;

use meow_checkin::store::Store;
use meow_checkin::{Engine, EngineConfig, SystemClock, SystemConnector};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

fn open(dir: &Path) -> Arc<Engine> {
    Engine::open(
        dir,
        Arc::new(SystemConnector),
        Arc::new(SystemClock),
        EngineConfig::default(),
    )
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

const SECRET_COOKIE: &str = "sid=TOPSECRETCOOKIE; uid=7";
const SECRET_MANUAL: &str = "MANUALSECRET10293";

fn populated(dir: &Path) -> (Arc<Engine>, String) {
    let engine = open(dir);
    let id = engine
        .create_task(
            &json!({"name": "主力机场", "home": "https://main.example.com/user",
                    "access": "proxy", "minute_of_day": 510, "enabled": true,
                    "subscription_id": "sub1"}),
            false,
        )
        .unwrap()
        .id;
    engine
        .save_variable(
            &id,
            "cookie",
            &json!({"name": "cookie", "source": "auto", "from": "cookie_header",
                    "url": "https://main.example.com/"}),
            false,
        )
        .unwrap();
    engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual", "value": SECRET_MANUAL}),
            false,
        )
        .unwrap();
    engine
        .push_variables(
            &id,
            &json!({"task_id": id, "values": {"cookie": SECRET_COOKIE},
                    "user_agent": "Mozilla/5.0 Test"}),
        )
        .unwrap();
    engine
        .save_steps(
            &id,
            &json!({"steps": [
                support::api_step("签到", "https://main.example.com/user/checkin?u={uid}",
                                  "https://main.example.com/user"),
                support::click_step("领取流量包", "https://main.example.com/user"),
            ]}),
            false,
        )
        .unwrap();
    (engine, id)
}

#[test]
fn everything_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, id) = populated(dir.path());
    let before = serde_json::to_value(engine.snapshot(true)).unwrap();
    drop(engine);

    let after = serde_json::to_value(open(dir.path()).snapshot(true)).unwrap();
    assert_eq!(before, after);
    let task = &after["tasks"][0];
    assert_eq!(task["id"], id.as_str());
    assert_eq!(task["access"], "proxy");
    assert_eq!(task["subscription_id"], "sub1");
    assert_eq!(task["steps"].as_array().unwrap().len(), 2);
    assert_eq!(task["variables"][0]["has_value"], true);
    assert_eq!(task["variables"][1]["value"], SECRET_MANUAL);
}

#[test]
fn values_live_in_their_own_file_and_nowhere_else() {
    let dir = tempfile::tempdir().unwrap();
    let (_engine, id) = populated(dir.path());
    let tasks = read(dir.path(), "checkin.json");
    assert!(!tasks.contains("TOPSECRETCOOKIE"));
    assert!(!tasks.contains(SECRET_MANUAL));
    assert!(!tasks.contains("Mozilla/5.0 Test"));
    // The reference is there; the value is not.
    assert!(tasks.contains("{cookie}"));

    let secrets: Value = serde_json::from_str(&read(dir.path(), "checkin-secrets.json")).unwrap();
    assert_eq!(secrets["version"], 1);
    assert_eq!(
        secrets["tasks"][&id]["values"]["cookie"]["value"],
        SECRET_COOKIE
    );
    assert_eq!(
        secrets["tasks"][&id]["values"]["uid"]["value"],
        SECRET_MANUAL
    );
    assert_eq!(secrets["tasks"][&id]["user_agent"], "Mozilla/5.0 Test");
}

#[cfg(unix)]
#[test]
fn files_are_for_the_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("checkin");
    let (_engine, _) = populated(&dir);
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["checkin.json", "checkin-secrets.json"] {
        let mode = std::fs::metadata(dir.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn writes_leave_no_scratch_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (_engine, _) = populated(dir.path());
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
}

#[test]
fn nothing_is_created_until_something_is_saved() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("checkin");
    let engine = open(&dir);
    assert!(engine.snapshot(false).tasks.is_empty());
    assert!(!dir.exists());
}

#[test]
fn a_file_that_is_not_json_is_set_aside_not_lost() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("checkin.json"), b"{ this is not json").unwrap();
    let engine = open(dir.path());
    assert!(engine.snapshot(false).tasks.is_empty());
    assert_eq!(
        read(dir.path(), "checkin.json.corrupt"),
        "{ this is not json"
    );
    // And the engine works on.
    engine
        .create_task(&json!({"home": "https://a.example/"}), false)
        .unwrap();
    assert_eq!(open(dir.path()).snapshot(false).tasks.len(), 1);
}

#[test]
fn a_file_from_a_newer_version_is_set_aside() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("checkin.json"),
        br#"{"version": 9, "tasks": [{"future": true}]}"#,
    )
    .unwrap();
    assert!(open(dir.path()).snapshot(false).tasks.is_empty());
    assert!(dir.path().join("checkin.json.v9.bak").exists());
}

#[test]
fn unreadable_entries_are_left_out_and_the_rest_loads() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("checkin.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "some_future_field": {"x": 1},
            "tasks": [
                {"id": "t1", "name": "好的", "home": "https://a.example/", "access": "direct",
                 "minute_of_day": 60, "enabled": true, "extra": 1,
                 "steps": [
                    {"kind": "click", "id": "s1", "name": "点", "page": "https://a.example/",
                     "locators": []},
                    {"kind": "hologram", "id": "s2"},
                    "not a step"
                 ],
                 "variables": [{"name": "cookie", "source": "auto", "from": "cookie_header"}]},
                {"id": "t2", "name": "缺字段"},
                {"id": "t1", "name": "重复", "home": "https://b.example/", "minute_of_day": 1},
                42
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    // Values and runs of tasks that are not there are dropped.
    std::fs::write(
        dir.path().join("checkin-secrets.json"),
        serde_json::to_vec(&json!({"version": 1, "tasks": {
            "t1": {"values": {"cookie": {"value": "a=1", "updated_at": "2026-10-12T00:00:00Z"}}},
            "gone": {"values": {"x": {"value": "y", "updated_at": "2026-10-12T00:00:00Z"}}}
        }}))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("checkin-runs.json"), b"[]").unwrap();

    let loaded = Store::new(dir.path()).load();
    assert_eq!(loaded.tasks.len(), 1);
    assert_eq!(loaded.tasks[0].name, "好的");
    assert_eq!(loaded.tasks[0].steps.len(), 1);
    assert_eq!(loaded.secrets.len(), 1);
    assert!(loaded.secrets.contains_key("t1"));
    assert!(loaded.runs.is_empty());
    // Values never show in debug output.
    assert!(!format!("{:?}", loaded.secrets).contains("a=1"));
}

#[test]
fn deleting_a_task_deletes_its_values() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, id) = populated(dir.path());
    engine.delete_task(&id).unwrap();
    let secrets = read(dir.path(), "checkin-secrets.json");
    assert!(!secrets.contains("TOPSECRETCOOKIE"));
    assert!(!secrets.contains(SECRET_MANUAL));
}

#[test]
fn values_of_tasks_that_cannot_be_read_are_set_aside_with_them() {
    for (content, suffix) in [
        (&b"{ this is not json"[..], "corrupt"),
        (&br#"{"version": 9, "tasks": []}"#[..], "v9.bak"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (_engine, _) = populated(dir.path());
        let secrets_before = read(dir.path(), "checkin-secrets.json");
        std::fs::write(dir.path().join("checkin.json"), content).unwrap();
        let engine = open(dir.path());
        assert!(engine.snapshot(false).tasks.is_empty());
        // The values went aside untouched instead of being wiped by the
        // first write of an engine that knows no task.
        assert_eq!(
            read(dir.path(), &format!("checkin-secrets.json.{suffix}")),
            secrets_before
        );
        assert!(!dir.path().join("checkin-secrets.json").exists());
        let id = engine
            .create_task(&json!({"home": "https://a.example/"}), false)
            .unwrap()
            .id;
        engine
            .save_variable(
                &id,
                "uid",
                &json!({"name": "uid", "source": "manual", "value": "new"}),
                false,
            )
            .unwrap();
        assert_eq!(
            read(dir.path(), &format!("checkin-secrets.json.{suffix}")),
            secrets_before
        );
    }
}

#[cfg(unix)]
#[test]
fn loading_tightens_modes_and_clears_scratch_files() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("checkin");
    let (engine, _) = populated(&dir);
    drop(engine);
    // Restored from a backup, or touched by hand: readable by everybody.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["checkin.json", "checkin-secrets.json"] {
        std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    // A core that died between writing and renaming.
    std::fs::write(dir.join("checkin-secrets.json.4242.7.tmp"), SECRET_COOKIE).unwrap();
    std::fs::write(dir.join("unrelated.tmp"), "kept").unwrap();

    let engine = open(&dir);
    assert_eq!(engine.snapshot(false).tasks.len(), 1);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("checkin.json")), 0o600);
    assert_eq!(mode(&dir.join("checkin-secrets.json")), 0o600);
    assert!(!dir.join("checkin-secrets.json.4242.7.tmp").exists());
    assert!(dir.join("unrelated.tmp").exists());
}

#[test]
fn a_later_state_is_never_overwritten_by_an_earlier_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path());
    let mut done = meow_checkin::store::Done::new();
    let runs = std::collections::HashMap::new();
    meow_checkin::store::mark_done(&mut done, "t1", "2026-10-12");
    let earlier = store.stage_runs(&runs, &done).unwrap();
    meow_checkin::store::mark_done(&mut done, "t1", "2026-10-13");
    let later = store.stage_runs(&runs, &done).unwrap();
    // Written in the other order, as two threads may.
    store.commit(later).unwrap();
    store.commit(earlier).unwrap();
    let file: Value = serde_json::from_str(&read(dir.path(), "checkin-runs.json")).unwrap();
    assert_eq!(file["done"]["t1"], json!(["2026-10-12", "2026-10-13"]));
}

#[test]
fn the_days_a_task_ran_on_read_in_both_shapes_and_stay_few() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, id) = populated(dir.path());
    drop(engine);
    std::fs::write(
        dir.path().join("checkin-runs.json"),
        serde_json::to_vec(&json!({"version": 1, "runs": [], "done": {
            &id: "2026-10-12", "gone": ["2026-10-12"]
        }}))
        .unwrap(),
    )
    .unwrap();
    let mut loaded = Store::new(dir.path()).load();
    assert_eq!(loaded.done.len(), 1);
    assert!(meow_checkin::store::is_done(
        &loaded.done,
        &id,
        "2026-10-12"
    ));
    assert!(!meow_checkin::store::is_done(
        &loaded.done,
        &id,
        "2026-10-13"
    ));
    for day in 13..=20 {
        meow_checkin::store::mark_done(&mut loaded.done, &id, &format!("2026-10-{day}"));
    }
    assert_eq!(loaded.done[&id].len(), meow_checkin::store::DONE_DAYS_MAX);
    assert!(meow_checkin::store::is_done(
        &loaded.done,
        &id,
        "2026-10-20"
    ));
    assert!(!meow_checkin::store::is_done(
        &loaded.done,
        &id,
        "2026-10-12"
    ));
}

#[test]
fn a_file_holding_too_much_is_cut_to_the_limits() {
    let dir = tempfile::tempdir().unwrap();
    let step = json!({"kind": "click", "id": "s", "name": "点", "page": "https://a.example/"});
    let tasks: Vec<Value> = (0..150)
        .map(|i| {
            json!({"id": format!("t{i}"), "name": "x", "home": "https://a.example/",
                   "minute_of_day": 1, "steps": vec![step.clone(); 80]})
        })
        .collect();
    std::fs::write(
        dir.path().join("checkin.json"),
        serde_json::to_vec(&json!({"version": 1, "tasks": tasks})).unwrap(),
    )
    .unwrap();
    let loaded = Store::new(dir.path()).load();
    assert_eq!(loaded.tasks.len(), meow_checkin::store::TASKS_MAX);
    assert!(loaded.tasks.iter().all(|t| t.steps.len() == 50));
}
