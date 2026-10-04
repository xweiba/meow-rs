//! Runs an http-response script over a body, for trying scripts out:
//!
//! `run <script.js> <url> [--arg A] [--binary] [--store FILE] < body > out`
//!
//! Writes the (possibly rewritten) body to stdout, the status to stderr.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use meow_script::{run, Message, Options, Store};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(script), Some(url)) = (args.next(), args.next()) else {
        eprintln!("usage: run <script.js> <url> [--arg A] [--binary] [--store FILE] < body");
        std::process::exit(2);
    };
    let (mut argument, mut binary, mut store) = (String::new(), false, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--arg" => argument = args.next().unwrap_or_default(),
            "--binary" => binary = true,
            "--store" => store = args.next().map(Into::into),
            other => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            }
        }
    }
    let source = std::fs::read_to_string(&script).expect("script");
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body).expect("stdin");
    let request = Message {
        url,
        method: "POST".into(),
        ..Message::default()
    };
    let response = Message {
        status: 200,
        body: Some(body.clone()),
        ..Message::default()
    };
    let opts = Options {
        name: "run".into(),
        argument,
        binary_body: binary,
        timeout: Duration::from_secs(10),
        store: Arc::new(Store::new(store)),
    };
    match run(&source, &request, Some(&response), &opts) {
        Ok(out) => {
            eprintln!("status {}", out.status.unwrap_or(200));
            let changed = out.body.is_some();
            std::io::stdout()
                .write_all(&out.body.unwrap_or(body))
                .expect("stdout");
            eprintln!("{}", if changed { "changed" } else { "unchanged" });
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
