//! scandiaca binary entrypoint — port of strix `src/index.ts`.
//!
//! Reads config from the environment, builds the signing key and storage
//! backend, and serves the Matrix API. The sqlite/postgres backends arrive in a
//! later phase; for now `STORAGE=memory` is the only backend (the default).

use std::env;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use scandiaca::server::{run, AppState};
use scandiaca::signing::{generate_signing_key, import_signing_key, SigningKey};
use scandiaca::storage::{create_memory_storage, create_sqlite_storage, Storage};

fn main() {
    // Size the tokio runtime to the *actual* CPU quota. In a CPU-limited
    // container `available_parallelism()` still reports every host core, so the
    // default runtime oversubscribes (e.g. 10 worker threads fighting for a
    // 2-CPU quota) — adding scheduler churn and tail latency. Matching workers to
    // the cgroup quota removes that.
    let workers = worker_thread_count();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(serve());
}

/// Worker-thread count: explicit `TOKIO_WORKER_THREADS` wins, else the cgroup CPU
/// quota, else the host's available parallelism.
fn worker_thread_count() -> usize {
    if let Ok(v) = env::var("TOKIO_WORKER_THREADS") {
        if let Ok(n) = v.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
    }
    cgroup_cpu_quota()
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

/// Read the CPU quota (rounded up to whole cores) from the cgroup, v2 then v1.
/// Returns `None` when unlimited or unreadable (bare-metal / no limit).
fn cgroup_cpu_quota() -> Option<usize> {
    // cgroup v2: "<quota> <period>" (or "max <period>" when unlimited).
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let mut it = s.split_whitespace();
        if let (Some(q), Some(p)) = (it.next(), it.next()) {
            if q != "max" {
                if let (Ok(q), Ok(p)) = (q.parse::<f64>(), p.parse::<f64>()) {
                    if p > 0.0 {
                        return Some(((q / p).ceil() as usize).max(1));
                    }
                }
            }
        }
    }
    // cgroup v1.
    let q: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").ok()?.trim().parse().ok()?;
    let p: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us").ok()?.trim().parse().ok()?;
    if q > 0 && p > 0 {
        Some(((q as f64 / p as f64).ceil() as usize).max(1))
    } else {
        None
    }
}

async fn serve() {
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8008);
    let server_name = env::var("SERVER_NAME").unwrap_or_else(|_| "localhost".to_string());

    let signing_key = load_signing_key();

    // Storage backend: `memory` (default) or `sqlite`. Postgres/MySQL are future.
    let storage_kind = env::var("STORAGE").unwrap_or_else(|_| "memory".to_string());
    let storage: Arc<dyn Storage> = match storage_kind.as_str() {
        "sqlite" => {
            let path = env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/matrix.db".to_string());
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            println!("Using SQLite storage at {path}");
            Arc::new(create_sqlite_storage(&path))
        }
        other => {
            if other != "memory" {
                eprintln!("STORAGE={other} not implemented; using in-memory storage");
            }
            println!("Using in-memory storage");
            Arc::new(create_memory_storage())
        }
    };

    let signing_key = Arc::new(signing_key);
    let federation_client = Some(Arc::new(scandiaca::federation::FederationClient::new(
        server_name.clone(),
        Arc::clone(&signing_key),
    )));

    // Appservice registrations: prefer the JSON env var, else parse a directory
    // of Complement-style registration YAMLs (`APPSERVICE_REGISTRATION_DIR`).
    let registrations = match env::var("APPSERVICE_REGISTRATIONS").ok() {
        Some(json) if !json.is_empty() => {
            scandiaca::appservice::registration::parse_registrations(Some(&json))
        }
        _ => match env::var("APPSERVICE_REGISTRATION_DIR").ok() {
            Some(dir) if !dir.is_empty() => {
                scandiaca::appservice::registration::parse_registration_dir(&dir)
            }
            _ => Vec::new(),
        },
    };
    if !registrations.is_empty() {
        println!("loaded {} appservice registration(s)", registrations.len());
    }

    let state = AppState {
        storage,
        server_name: Arc::from(server_name.as_str()),
        signing_key,
        federation_client,
        registrations: Arc::new(registrations),
    };

    // Optional TLS federation listener (Complement / real federation): serve
    // federation over HTTPS on FED_PORT when TLS_CERT and TLS_KEY are both set.
    let tls = match (env::var("TLS_CERT"), env::var("TLS_KEY")) {
        (Ok(cert_path), Ok(key_path)) => {
            // rustls 0.23 needs a process-wide default crypto provider.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let fed_port: u16 = env::var("FED_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8448);
            Some(scandiaca::server::TlsConfig { fed_port, cert_path, key_path })
        }
        _ => None,
    };

    // Periodic federation EDU replay sweep (startup + every 5s) so durable EDUs
    // (device-list/to-device) queued while a peer was down are delivered once it
    // recovers (strix's flushAllPendingEdus timer).
    if let Some(fed) = state.federation_client.clone() {
        let storage = Arc::clone(&state.storage);
        let origin = Arc::clone(&state.server_name);
        tokio::spawn(async move {
            loop {
                scandiaca::federation::outbound::flush_all_pending_edus(&*storage, &fed, &origin).await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    println!("scandiaca listening on :{port} (server_name: {server_name})");
    if let Err(e) = run(state, port, tls).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

/// Load the ed25519 signing key from `SIGNING_KEY_SEED`, or generate a fresh one
/// (printing the seed so it can be persisted).
fn load_signing_key() -> SigningKey {
    match env::var("SIGNING_KEY_SEED") {
        Ok(seed_b64) => {
            let seed_bytes = STANDARD
                .decode(seed_b64.trim())
                .expect("SIGNING_KEY_SEED must be valid base64");
            let seed: [u8; 32] = seed_bytes
                .try_into()
                .expect("SIGNING_KEY_SEED must decode to 32 bytes");
            let key_id = env::var("SIGNING_KEY_ID").unwrap_or_else(|_| "ed25519:auto".to_string());
            import_signing_key(key_id, seed)
        }
        Err(_) => {
            let key = generate_signing_key();
            println!("Generated signing key {}", key.key_id);
            println!(
                "Seed (set SIGNING_KEY_SEED to persist): {}",
                STANDARD.encode(key.seed)
            );
            key
        }
    }
}
