//! lp1-node command line. Every command reads public fixtures only; nothing signs, sends or
//! connects outward. Exit status 0 means the command's own checks passed.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process;

use lp1_node::{fixtures, http, rpc, verify, window};

const USAGE: &str = "lp1-node <command> [options]

commands:
  verify-fixtures   provenance, profile/genesis binding, chain, window cases, ASERT oracle, hash oracle
  profile           print the genesis identity binding of profile.json
  window            run the RP window cases [--case ID] [--no-cache]
  hash              K1-K3, hash-oracle digests and derivations from fixture headers
  asert-batch       differential ASERT rows as JSON lines [--in FILE] [--out FILE]
  serve             read-only JSON-RPC on 127.0.0.1 [--bind 127.0.0.1] [--port N] [--empty-chain]
                    [--max-requests N] [--max-runtime-ms N] [--conn-timeout-ms N]

common options:
  --fixtures DIR    fixture directory (default: <crate root>/fixtures)";

struct Args {
    cmd: String,
    opts: Vec<(String, Option<String>)>,
}

const FLAGS: [&str; 2] = ["--no-cache", "--empty-chain"];
const VALUED: [&str; 9] = ["--fixtures", "--case", "--in", "--out", "--bind", "--port", "--max-requests", "--max-runtime-ms", "--conn-timeout-ms"];

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or_else(|| USAGE.to_string())?;
    let mut opts = Vec::new();
    while let Some(a) = it.next() {
        if FLAGS.contains(&a.as_str()) {
            opts.push((a, None));
        } else if VALUED.contains(&a.as_str()) {
            let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
            opts.push((a, Some(v)));
        } else {
            return Err(format!("unknown option {a}\n{USAGE}"));
        }
    }
    Ok(Args { cmd, opts })
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.opts.iter().rev().find(|(n, _)| n == k).and_then(|(_, v)| v.as_deref())
    }
    fn flag(&self, k: &str) -> bool {
        self.opts.iter().any(|(n, _)| n == k)
    }
    fn num(&self, k: &str) -> Result<Option<u64>, String> {
        match self.get(k) {
            None => Ok(None),
            Some(s) => s.parse::<u64>().map(Some).map_err(|_| format!("{k}: not a non-negative integer")),
        }
    }
    fn dir(&self) -> PathBuf {
        match self.get("--fixtures") {
            Some(d) => PathBuf::from(d),
            None => fixtures::default_dir(),
        }
    }
}

fn run() -> Result<bool, String> {
    let a = parse_args()?;
    let dir = a.dir();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match a.cmd.as_str() {
        "verify-fixtures" => verify::verify_all(&dir, &mut out),
        "profile" => {
            let node = verify::load_node(&dir, true)?;
            writeln!(out, "{}", verify::profile_json(&node.profile)).map_err(|e| e.to_string())?;
            Ok(true)
        }
        "window" => {
            let node = verify::load_node(&dir, true)?;
            let cases = fixtures::read_json(&dir, "window-cases.json")?;
            let cache = !a.flag("--no-cache");
            let reports = verify::run_window_cases(&node.cfg, &cases, cache, a.get("--case"))?;
            if reports.is_empty() {
                return Err("no matching case".into());
            }
            for r in &reports {
                writeln!(out, "{}", r.to_json()).map_err(|e| e.to_string())?;
            }
            let pass = reports.iter().filter(|r| r.pass()).count();
            writeln!(out, "{{\"check\":\"window\",\"cache\":{cache},\"cases\":{},\"pass\":{pass},\"itemsNotEvaluated\":\"{}\"}}", reports.len(), window::ITEMS_NOT_EVALUATED).map_err(|e| e.to_string())?;
            Ok(pass == reports.len())
        }
        "hash" => {
            let rep = verify::run_hash_checks(&fixtures::read_json(&dir, "hash-oracle.json")?, &fixtures::read_json(&dir, "window-cases.json")?)?;
            writeln!(out, "{}", rep.to_json()).map_err(|e| e.to_string())?;
            Ok(rep.pass())
        }
        "asert-batch" => {
            let oracle = match a.get("--in") {
                Some(p) => {
                    let b = std::fs::read(p).map_err(|e| format!("read {p}: {e}"))?;
                    serde_json::from_slice(&b).map_err(|e| format!("{p}: {e}"))?
                }
                None => fixtures::read_json(&dir, "asert-oracle.json")?,
            };
            let (rows, matched) = match a.get("--out") {
                Some(p) => {
                    let f = File::create(p).map_err(|e| format!("create {p}: {e}"))?;
                    let mut w = BufWriter::new(f);
                    let r = verify::run_asert_rows(&oracle, &mut w)?;
                    w.flush().map_err(|e| e.to_string())?;
                    r
                }
                None => verify::run_asert_rows(&oracle, &mut out)?,
            };
            Ok(rows == matched)
        }
        "serve" => serve(&a, &dir, &mut out),
        "help" | "--help" | "-h" => {
            writeln!(out, "{USAGE}").map_err(|e| e.to_string())?;
            Ok(true)
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

fn serve(a: &Args, dir: &std::path::Path, out: &mut dyn Write) -> Result<bool, String> {
    http::check_bind(a.get("--bind").unwrap_or("127.0.0.1"))?;
    let port = match a.num("--port")? {
        None => 0u16,
        Some(p) if p <= u16::MAX as u64 => p as u16,
        Some(_) => return Err("--port out of range".into()),
    };
    let cfg = http::HttpConfig {
        port,
        max_requests: a.num("--max-requests")?,
        max_runtime_ms: a.num("--max-runtime-ms")?,
        conn_timeout_ms: a.num("--conn-timeout-ms")?.unwrap_or(5000),
    };
    // The chain is validated completely before the listener exists.
    let node = verify::load_node(dir, a.flag("--empty-chain"))?;
    let router = rpc::Router::new(node.profile.chain_id, &node.chain);
    let listener = http::bind(&cfg).map_err(|e| format!("bind: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    if !local.ip().is_loopback() {
        return Err("listener is not on loopback".into());
    }
    let opt = |v: Option<u64>| v.map(|x| x.to_string()).unwrap_or_else(|| "null".into());
    writeln!(
        out,
        "{{\"event\":\"ready\",\"transport\":\"lp1-loopback-http-serial\",\"addr\":\"127.0.0.1\",\"port\":{},\"head\":{},\"chainId\":\"{}\",\"maxRequests\":{},\"maxRuntimeMs\":{},\"connTimeoutMs\":{},\"m7\":false}}",
        local.port(),
        router.head(),
        rpc::qty(node.profile.chain_id),
        opt(cfg.max_requests),
        opt(cfg.max_runtime_ms),
        cfg.conn_timeout_ms
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    let stderr = io::stderr();
    let mut log = stderr.lock();
    let (served, why) = http::serve(&router, &listener, &cfg, &mut log).map_err(|e| e.to_string())?;
    writeln!(out, "{{\"event\":\"shutdown\",\"served\":{served},\"reason\":\"{why}\"}}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(true)
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => process::exit(1),
        Err(e) => {
            eprintln!("{{\"error\":{}}}", lp1_node::json::quote(&e));
            process::exit(2);
        }
    }
}
