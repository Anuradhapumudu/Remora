//! `remora-host serve`: Phase 3 command-line host on loopback.
//!
//! Prints (one per line, stable prefixes - the end-to-end tests read them):
//! `device:`, `identity:`, `listening:`, then `code:` and `password:` for
//! the next connection. Each accept prompt shows the viewer's name, device
//! code and the safety code; the user answers `accept <id>` or `deny <id>`.
//! While a session is active the host prints `SESSION ACTIVE <id>` (INV11)
//! and `session ended <id>` when it ends.
//!
//! Remote input is NOT echoed: a keystroke could be someone typing a
//! password; Phase 3 has no injector, so the CLI only counts events.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use remora_app::cli::{
    format_sas, identity_hex, offer_code, parse_identity, short_code_of, unix_now,
};
use remora_app::keystore::{self, Role};
use remora_crypto::sas::Sas;
use remora_net::{HostEvent, HostServer};
use remora_session::{HostConfig, Identity, SessionId};

/// How long each printed connection code is valid (protocol.md §2: ≤ 5 min).
const CODE_TTL: Duration = Duration::from_secs(300);

/// `remora-host serve` options.
#[derive(clap::Args, Debug)]
pub(crate) struct ServeArgs {
    /// Address to listen on (Phase 3: a specific local address).
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    /// Key file (default: the per-user config directory).
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Name shown to viewers (untrusted text, ≤ 64 bytes).
    #[arg(long, default_value = "Remora host")]
    name: String,
    /// A viewer identity key (64 hex digits) allowed to connect without a
    /// password (trusted mode). May be repeated.
    #[arg(long = "trust", value_name = "KEY")]
    trusted: Vec<String>,
}

pub(crate) fn run(args: ServeArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    rt.block_on(serve(args))
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    if args.bind.ip().is_unspecified() {
        bail!(
            "Phase 3 listens on a specific address (e.g. 127.0.0.1:0), not {}",
            args.bind
        );
    }
    let trusted = args
        .trusted
        .iter()
        .map(|k| parse_identity(k).with_context(|| format!("--trust {k}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let path = match args.identity_file {
        Some(p) => p,
        None => keystore::default_path(Role::Host)?,
    };
    let (keys, created) = keystore::load_or_create(&path)?;
    if created {
        println!("note: created a new device identity in {}", path.display());
    }
    let cert = keys
        .cert(&args.name, unix_now())
        .context("--name is at most 64 bytes")?;
    let public = keys.identity.public();
    let config = HostConfig {
        identity: Arc::new(Identity {
            noise: keys.noise,
            cert,
        }),
        password_enabled: true,
        trusted,
    };
    let (server, mut events) = HostServer::bind(args.bind, config).await?;
    let addr = server.local_addr()?;
    println!("device: {}", short_code_of(&public));
    println!("identity: {}", identity_hex(&public));
    println!("listening: {addr}");
    print_next_code(&server, addr, &public);

    let mut stdin = stdin_lines();
    let mut pending: HashMap<SessionId, Sas> = HashMap::new();
    let mut inputs: HashMap<SessionId, u64> = HashMap::new();
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                handle_event(ev, &server, addr, &public, &mut pending, &mut inputs);
            }
            line = stdin.recv() => {
                let Some(line) = line else { break };
                if !handle_command(line.trim(), &server, &mut pending) {
                    break;
                }
            }
        }
    }
    server.shutdown();
    Ok(())
}

fn print_next_code(
    server: &HostServer,
    addr: SocketAddr,
    public: &remora_crypto::identity::IdentityPublic,
) {
    let nonce = server.issue_nonce(CODE_TTL);
    println!(
        "code: {}",
        offer_code(addr, public, nonce, unix_now(), CODE_TTL.as_secs())
    );
    println!("password: {}", server.otp().reveal());
}

fn handle_event(
    ev: HostEvent,
    server: &HostServer,
    addr: SocketAddr,
    public: &remora_crypto::identity::IdentityPublic,
    pending: &mut HashMap<SessionId, Sas>,
    inputs: &mut HashMap<SessionId, u64>,
) {
    match ev {
        HostEvent::Prompt {
            id,
            sas,
            viewer_name,
            viewer_key,
        } => {
            pending.insert(id, sas);
            println!(
                "prompt {}: {:?} (device {}) safety code {} - check it matches the viewer's screen, then type 'accept {}' or 'deny {}'",
                id.0,
                viewer_name,
                short_code_of(&viewer_key),
                format_sas(sas),
                id.0,
                id.0
            );
            // The code and password just used are spent (A06, INV15).
            print_next_code(server, addr, public);
        }
        HostEvent::PromptClosed { id } => {
            if pending.remove(&id).is_some() {
                println!("prompt withdrawn {}", id.0);
            }
        }
        HostEvent::Active { id } => {
            pending.remove(&id);
            println!(
                "SESSION ACTIVE {}: a viewer is connected (type 'disconnect {}' to end it)",
                id.0, id.0
            );
        }
        HostEvent::Deliver { id, .. } => {
            let n = inputs.entry(id).or_default();
            *n += 1;
            if *n == 1 {
                println!("input {}: receiving input events (not shown)", id.0);
            }
        }
        HostEvent::Failed { id, reason, .. } => {
            println!("failed {}: {reason}", id.0);
            print_next_code(server, addr, public);
        }
        HostEvent::OtpRotated => println!("note: 3 failed attempts - the password was replaced"),
        HostEvent::OtpUsed { .. } => {}
        HostEvent::Closed { id, code } => {
            pending.remove(&id);
            inputs.remove(&id);
            println!("session ended {} ({code:?})", id.0);
        }
    }
}

/// Applies one typed command; `false` to quit.
fn handle_command(line: &str, server: &HostServer, pending: &mut HashMap<SessionId, Sas>) -> bool {
    let mut words = line.split_whitespace();
    let (cmd, arg) = (words.next().unwrap_or(""), words.next());
    let id = arg.and_then(|a| a.parse::<u64>().ok()).map(SessionId);
    match (cmd, id) {
        ("", _) => {}
        ("quit", _) => return false,
        ("accept", Some(id)) => match pending.get(&id) {
            // Approval is bound to the session AND the code on its prompt (A22).
            Some(&sas) => {
                if let Err(e) = server.approve(id, sas) {
                    println!("cannot accept {}: {e}", id.0);
                }
            }
            None => println!("no pending session {}", id.0),
        },
        ("deny", Some(id)) => {
            if pending.remove(&id).is_some() {
                server.deny(id);
            } else {
                println!("no pending session {}", id.0);
            }
        }
        ("disconnect", Some(id)) => server.disconnect(id),
        _ => {
            println!("unknown command: {line:?} (accept <id> | deny <id> | disconnect <id> | quit)")
        }
    }
    true
}

/// Lines typed on stdin, read on a plain thread (stdin is blocking).
fn stdin_lines() -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// `remora-host identity`: print (creating if needed) this host's identity.
pub(crate) fn identity(file: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match file {
        Some(p) => p,
        None => keystore::default_path(Role::Host)?,
    };
    let (keys, _) = keystore::load_or_create(&path)?;
    let public = keys.identity.public();
    println!("identity: {}", identity_hex(&public));
    println!("device: {}", short_code_of(&public));
    Ok(())
}
