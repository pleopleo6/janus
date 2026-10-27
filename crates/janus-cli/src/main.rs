#![forbid(unsafe_code)]
//! `janus`: demo client / server for the Janus hybrid post-quantum channel.
//!
//! ```text
//! janus keygen --out server.id
//! janus keygen --out client.id
//! janus serve   --id server.id --trust <client fingerprint> [--echo | --forward HOST:PORT]
//! janus connect 127.0.0.1:7878 --id client.id --trust <server fingerprint>
//! janus tunnel  --listen 127.0.0.1:15432 --to server:7878 --id client.id --trust <server fp>
//! ```
//!
//! **Educational project, not production-ready.**

mod identity;
mod net;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use janus_channel::ChannelConfig;
use janus_core::handshake::{Config, TrustStore};
use janus_core::sig::IdentityKeypair;
use janus_tokio::{JanusStream, Options};
use rand_core::{TryRng as _, UnwrapErr};
use tokio::net::{TcpListener, TcpStream};

use crate::net::Ending;

#[derive(Parser)]
#[command(
    name = "janus",
    version,
    about = "Hybrid post-quantum secure channel (demo)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new identity file and print its fingerprint.
    Keygen {
        /// Where to write the (unencrypted!) secret identity.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the fingerprint of an identity file.
    Fingerprint {
        /// Identity file.
        #[arg(long)]
        id: PathBuf,
    },
    /// Accept connections.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:7878")]
        listen: String,
        /// Echo messages back instead of chatting on stdin (serves clients
        /// concurrently).
        #[arg(long, conflicts_with = "forward")]
        echo: bool,
        /// Forward every authenticated connection to this plain TCP service
        /// (serves clients concurrently). Pair with `janus tunnel`.
        #[arg(long, value_name = "HOST:PORT")]
        forward: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Connect to a server and chat over stdin / stdout.
    Connect {
        /// Server address.
        addr: String,
        #[command(flatten)]
        common: Common,
    },
    /// Accept plain TCP connections locally and carry each one over Janus
    /// to a `janus serve --forward` server (a post-quantum "stunnel").
    Tunnel {
        /// Local address unmodified applications connect to.
        #[arg(long, default_value = "127.0.0.1:15000")]
        listen: String,
        /// Address of the Janus server.
        #[arg(long)]
        to: String,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(Args)]
struct Common {
    /// Our identity file.
    #[arg(long)]
    id: PathBuf,
    /// Fingerprint of a peer to accept (repeatable).
    #[arg(long = "trust", value_name = "FINGERPRINT")]
    trust: Vec<String>,
    /// File with one trusted fingerprint per line.
    #[arg(long)]
    trust_file: Option<PathBuf>,
    /// Records between two rekeys (must match the peer).
    #[arg(long, default_value_t = janus_channel::record::DEFAULT_REKEY_INTERVAL)]
    rekey_interval: u64,
}

impl Common {
    fn config(&self) -> Result<(Config, Options)> {
        let identity = identity::load(&self.id)?;
        let mut trust = TrustStore::new();
        for fp in &self.trust {
            trust.add(identity::parse_fingerprint(fp)?);
        }
        if let Some(path) = &self.trust_file {
            for fp in identity::load_trust_file(path)? {
                trust.add(fp);
            }
        }
        if trust.is_empty() {
            anyhow::bail!("no trusted peer: pass --trust <fingerprint> or --trust-file");
        }
        eprintln!(
            "[janus] our fingerprint: {}",
            identity.public().fingerprint()
        );
        Ok((
            Config { identity, trust },
            Options {
                channel: ChannelConfig {
                    rekey_interval: self.rekey_interval,
                },
                ..Options::default()
            },
        ))
    }
}

fn report<S>(stream: &JanusStream<S>) {
    let info = stream.handshake_info();
    eprintln!(
        "[janus] handshake ok in {:.1} ms ({} B sent, {} B received)",
        info.elapsed.as_secs_f64() * 1000.0,
        info.bytes_sent,
        info.bytes_received
    );
    eprintln!("[janus] peer: {}", stream.peer_fingerprint());
    // Shown so users can compare it out-of-band (like Signal's safety number):
    // equal values prove there is no man in the middle, even if a pinned key
    // was set up wrongly.
    eprintln!(
        "[janus] session id: {}",
        identity::grouped(stream.session_id().get(..16).unwrap_or_default())
    );
}

fn report_ending(ending: &Ending) {
    match ending {
        Ending::Clean => eprintln!("[janus] connection closed cleanly"),
        Ending::Truncated => eprintln!(
            "[janus] WARNING: stream ended without close_notify; data may have been truncated"
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Probe the OS RNG once so that a failure is an error, not a panic later.
    let mut probe = [0u8; 32];
    getrandom::SysRng
        .try_fill_bytes(&mut probe)
        .map_err(|e| anyhow::anyhow!("OS random number generator unavailable: {e}"))?;

    match cli.command {
        Command::Keygen { out } => {
            let id = IdentityKeypair::generate(&mut UnwrapErr(getrandom::SysRng));
            identity::save(&out, &id)?;
            eprintln!("[janus] wrote {} (keep it secret)", out.display());
            println!("{}", id.public().fingerprint());
        }
        Command::Fingerprint { id } => {
            println!("{}", identity::load(&id)?.public().fingerprint());
        }
        Command::Serve {
            listen,
            echo,
            forward,
            common,
        } => {
            let (config, opts) = common.config()?;
            let config = Arc::new(config);
            let listener = TcpListener::bind(&listen)
                .await
                .with_context(|| format!("cannot listen on {listen}"))?;
            match &forward {
                Some(target) => eprintln!("[janus] listening on {listen}, forwarding to {target}"),
                None => eprintln!("[janus] listening on {listen}"),
            }
            loop {
                let (tcp, peer) = listener.accept().await?;
                eprintln!("[janus] connection from {peer}");
                let config = Arc::clone(&config);
                let target = forward.clone();
                let concurrent = echo || forward.is_some();
                let job = async move {
                    let stream = janus_tokio::accept(tcp, &config, opts).await?;
                    report(&stream);
                    if let Some(target) = target {
                        let plain = TcpStream::connect(&target)
                            .await
                            .with_context(|| format!("cannot reach {target}"))?;
                        let (up, down) = net::forward(stream, plain).await?;
                        eprintln!("[janus] {peer}: tunnel closed ({up} B up, {down} B down)");
                        Ok(Ending::Clean)
                    } else if echo {
                        net::run_echo(stream).await
                    } else {
                        net::run_interactive(stream).await
                    }
                };
                if concurrent {
                    tokio::spawn(async move {
                        match job.await {
                            Ok(e) => report_ending(&e),
                            Err(e) => eprintln!("[janus] {peer}: {e:#}"),
                        }
                    });
                } else {
                    // Interactive mode owns stdin: one peer at a time.
                    match job.await {
                        Ok(e) => report_ending(&e),
                        Err(e) => eprintln!("[janus] {peer}: {e:#}"),
                    }
                }
            }
        }
        Command::Connect { addr, common } => {
            let (config, opts) = common.config()?;
            let tcp = TcpStream::connect(&addr)
                .await
                .with_context(|| format!("cannot connect to {addr}"))?;
            // `connect` returns only once the server confirmed it accepted us.
            let stream = janus_tokio::connect(tcp, &config, opts).await?;
            report(&stream);
            eprintln!("[janus] type messages, Ctrl-D to close");
            report_ending(&net::run_interactive(stream).await?);
        }
        Command::Tunnel { listen, to, common } => {
            let (config, opts) = common.config()?;
            let config = Arc::new(config);
            let listener = TcpListener::bind(&listen)
                .await
                .with_context(|| format!("cannot listen on {listen}"))?;
            eprintln!("[janus] tunnel {listen} -> janus://{to}");
            loop {
                let (plain, peer) = listener.accept().await?;
                let (config, to) = (Arc::clone(&config), to.clone());
                tokio::spawn(async move {
                    let job = async {
                        let tcp = TcpStream::connect(&to)
                            .await
                            .with_context(|| format!("cannot reach {to}"))?;
                        let stream = janus_tokio::connect(tcp, &config, opts).await?;
                        eprintln!(
                            "[janus] {peer}: secured, session {}",
                            identity::grouped(stream.session_id().get(..8).unwrap_or_default())
                        );
                        net::forward(stream, plain).await
                    };
                    match job.await {
                        Ok((up, down)) => {
                            eprintln!("[janus] {peer}: closed ({up} B up, {down} B down)");
                        }
                        Err(e) => eprintln!("[janus] {peer}: {e:#}"),
                    }
                });
            }
        }
    }
    Ok(())
}
