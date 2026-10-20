//! `remora-host serve`: Phase 3 command-line host on loopback.
//!
//! Prints (one per line, stable prefixes - the end-to-end tests read them):
//! `device:`, `identity:`, `listening:`, then `code:` and `password:` for
//! the next connection. Each accept prompt shows the viewer's name, device
//! code and the safety code under a short **prompt number** (1, 2, 3, …,
//! never reused in a run); the user answers `accept <n>` or `deny <n>`.
//! While a session is active the host prints `SESSION ACTIVE <n>` (INV11)
//! and `session ended <n>` when it ends. Every run warns on stderr that the
//! key file is unencrypted (F-UX2); a new code/password pair comes with a
//! `note:` line saying why (F-UX3).
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
    PasswordChange, format_sas, identity_hex, key_file_warning, offer_code, parse_identity,
    short_code_of, unix_now,
};
use remora_app::keystore::{self, Role};
use remora_app::prompts::{HostCommand, SessionBook, no_such_prompt, parse_host_command};
use remora_crypto::identity::IdentityPublic;
use remora_crypto::sas::Sas;
use remora_crypto::secret::Otp;
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
    // F-UX2: on EVERY run, not only when the file is created.
    eprintln!("{}", key_file_warning(&path));
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
    let mut ui = Ui {
        shown_password: server.otp(),
        server,
        addr,
        public,
        book: SessionBook::new(),
        inputs: HashMap::new(),
        rotated: false,
    };
    ui.print_code(false);

    let mut stdin = stdin_lines();
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                ui.handle_event(ev);
            }
            line = stdin.recv() => {
                let Some(line) = line else { break };
                if !ui.handle_command(&line) {
                    break;
                }
            }
        }
    }
    ui.server.shutdown();
    Ok(())
}

/// One session as the person sees it: a prompt number (F-UX1) for the
/// protocol's random 64-bit session ID.
struct Entry {
    id: SessionId,
    /// The safety code on its prompt while it waits for accept/deny
    /// (approval is bound to it, A22); `None` once active.
    pending: Option<Sas>,
}

/// The host CLI's state.
struct Ui {
    server: HostServer,
    addr: SocketAddr,
    public: IdentityPublic,
    book: SessionBook<Entry>,
    inputs: HashMap<SessionId, u64>,
    /// The password last printed, to explain a change (F-UX3).
    shown_password: Otp,
    /// The host replaced the password after failed attempts since it was
    /// last printed.
    rotated: bool,
}

impl Ui {
    /// Prints a fresh single-use code and the current password. With
    /// `explain`, first a line saying why a new pair appeared (F-UX3).
    fn print_code(&mut self, explain: bool) {
        let otp = self.server.otp();
        if explain {
            let change =
                PasswordChange::between(self.shown_password.reveal(), otp.reveal(), self.rotated);
            println!("{}", change.note());
        }
        let nonce = self.server.issue_nonce(CODE_TTL);
        println!(
            "code: {}",
            offer_code(
                self.addr,
                &self.public,
                nonce,
                unix_now(),
                CODE_TTL.as_secs()
            )
        );
        println!("password: {}", otp.reveal());
        self.shown_password = otp;
        self.rotated = false;
    }

    fn number_of(&self, id: SessionId) -> Option<u64> {
        self.book.find(|e| e.id == id)
    }

    fn waiting(&self) -> Vec<u64> {
        self.book.numbers_where(|e| e.pending.is_some())
    }

    fn handle_event(&mut self, ev: HostEvent) {
        match ev {
            HostEvent::Prompt {
                id,
                sas,
                viewer_name,
                viewer_key,
            } => {
                let n = self.book.insert(Entry {
                    id,
                    pending: Some(sas),
                });
                println!(
                    "prompt {n}: {viewer_name:?} (device {}) safety code {} - check it matches the viewer's screen, then type 'accept {n}' or 'deny {n}'",
                    short_code_of(&viewer_key),
                    format_sas(sas),
                );
                // The code and password just used are spent (A06, INV15).
                self.print_code(true);
            }
            HostEvent::PromptClosed { id } => {
                if let Some(n) = self.number_of(id)
                    && let Some(e) = self.book.get_mut(n)
                    && e.pending.take().is_some()
                {
                    println!("prompt withdrawn {n}");
                }
            }
            HostEvent::Active { id } => {
                let n = match self.number_of(id) {
                    Some(n) => n,
                    // Trusted mode has no prompt: number it now.
                    None => self.book.insert(Entry { id, pending: None }),
                };
                if let Some(e) = self.book.get_mut(n) {
                    e.pending = None;
                }
                println!(
                    "SESSION ACTIVE {n}: a viewer is connected (type 'disconnect {n}' to end it)"
                );
            }
            HostEvent::Deliver { id, .. } => {
                let count = self.inputs.entry(id).or_default();
                *count += 1;
                if *count == 1 {
                    match self.number_of(id) {
                        Some(n) => println!("input {n}: receiving input events (not shown)"),
                        None => println!("input: receiving input events (not shown)"),
                    }
                }
            }
            HostEvent::Failed { id, reason, .. } => {
                match self.number_of(id) {
                    Some(n) => println!("failed {n}: {reason}"),
                    None => println!("failed: {reason}"),
                }
                self.print_code(true);
            }
            HostEvent::OtpRotated => {
                self.rotated = true;
                println!("note: 3 failed attempts - the password was replaced");
            }
            HostEvent::OtpUsed { .. } => {}
            HostEvent::Closed { id, code } => {
                self.inputs.remove(&id);
                if let Some(n) = self.number_of(id) {
                    self.book.remove(n);
                    println!("session ended {n} ({code:?})");
                }
            }
        }
    }

    /// Applies one typed line; `false` to quit. Every mistake gets an
    /// explicit answer (F-UX1).
    fn handle_command(&mut self, line: &str) -> bool {
        let cmd = match parse_host_command(line) {
            Ok(cmd) => cmd,
            Err(e) => {
                println!("{e}");
                return true;
            }
        };
        match cmd {
            HostCommand::Nothing => {}
            HostCommand::Quit => return false,
            HostCommand::Accept(n) => match self.book.get(n) {
                // Approval is bound to the session AND the code on its prompt (A22).
                Some(Entry {
                    id,
                    pending: Some(sas),
                }) => {
                    if let Err(e) = self.server.approve(*id, *sas) {
                        println!("cannot accept {n}: {e}");
                    }
                }
                Some(Entry { pending: None, .. }) => {
                    println!("session {n} is already active - nothing to accept")
                }
                None => println!("{}", no_such_prompt(n, &self.waiting())),
            },
            HostCommand::Deny(n) => match self.book.get_mut(n) {
                Some(e) if e.pending.is_some() => {
                    e.pending = None;
                    self.server.deny(e.id);
                }
                Some(_) => println!("session {n} is already active - use 'disconnect {n}'"),
                None => println!("{}", no_such_prompt(n, &self.waiting())),
            },
            HostCommand::Disconnect(n) => match self.book.get(n) {
                Some(e) => self.server.disconnect(e.id),
                None => println!("no session {n}"),
            },
        }
        true
    }
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
    eprintln!("{}", key_file_warning(&path));
    let public = keys.identity.public();
    println!("identity: {}", identity_hex(&public));
    println!("device: {}", short_code_of(&public));
    Ok(())
}
