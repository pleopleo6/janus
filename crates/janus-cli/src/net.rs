//! Running the sans-IO handshake and channel over tokio TCP streams.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use janus_channel::{
    ChannelConfig, Deframer, Error as ChannelError, Frame, FrameType, Received, Receiver, Sender,
    channel,
};
use janus_core::handshake::{self, Config, Session};
use rand_core::UnwrapErr;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};

/// Upper bound on the whole handshake, so a silent peer cannot hold a slot.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The operating system RNG.
///
/// `UnwrapErr` turns an OS RNG failure into a panic. That failure is not
/// reachable from network input, and `main` probes the RNG once at startup so
/// that a broken RNG is reported as an error rather than a crash.
pub fn os_rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// Details of a completed handshake, for display.
#[derive(Debug)]
pub struct HandshakeInfo {
    /// Wire bytes sent / received during the handshake (frames included).
    pub bytes_sent: usize,
    /// Wire bytes received.
    pub bytes_received: usize,
    /// Wall-clock duration, including network round trips.
    pub elapsed: Duration,
}

/// Read the next frame, or `None` on a clean EOF at a frame boundary.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, d: &mut Deframer) -> Result<Option<Frame>> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if let Some(f) = d.next_frame()? {
            return Ok(Some(f));
        }
        let n = r.read(&mut buf).await?;
        if n == 0 {
            d.finish()?;
            return Ok(None);
        }
        d.push(buf.get(..n).ok_or_else(|| anyhow!("read overflow"))?);
    }
}

async fn read_handshake<R: AsyncRead + Unpin>(r: &mut R, d: &mut Deframer) -> Result<Vec<u8>> {
    match read_frame(r, d).await? {
        Some(Frame {
            ty: FrameType::Handshake,
            body,
        }) => Ok(body),
        Some(_) => bail!("unexpected record during handshake"),
        None => bail!("peer closed the connection during the handshake"),
    }
}

/// Run the initiator side. Returns the session and the deframer, which may
/// already hold records that arrived right after the handshake.
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &Config,
) -> Result<(Session, Deframer, HandshakeInfo)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let start = Instant::now();
        let mut rng = os_rng();
        let mut d = Deframer::new();
        let (state, hello) = handshake::client_start(config, &mut rng);
        let hello = Frame::handshake(&hello)?;
        stream.write_all(&hello).await?;
        let reply = read_handshake(stream, &mut d).await?;
        let (finish, session) = state
            .read_server_hello(&reply, &mut rng)
            .context("handshake failed")?;
        let finish = Frame::handshake(&finish)?;
        stream.write_all(&finish).await?;
        let info = HandshakeInfo {
            bytes_sent: hello.len().saturating_add(finish.len()),
            bytes_received: reply
                .len()
                .saturating_add(janus_channel::framing::FRAME_HEADER_LEN),
            elapsed: start.elapsed(),
        };
        Ok((session, d, info))
    })
    .await
    .context("handshake timed out")?
}

/// Run the responder side.
pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &Config,
) -> Result<(Session, Deframer, HandshakeInfo)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut d = Deframer::new();
        let hello = read_handshake(stream, &mut d).await?;
        let start = Instant::now();
        let mut rng = os_rng();
        let (state, reply) =
            handshake::server_accept(config, &hello, &mut rng).context("handshake failed")?;
        let reply = Frame::handshake(&reply)?;
        stream.write_all(&reply).await?;
        let finish = read_handshake(stream, &mut d).await?;
        let session = state
            .read_client_finish(&finish)
            .context("handshake failed")?;
        let header = janus_channel::framing::FRAME_HEADER_LEN;
        let info = HandshakeInfo {
            bytes_sent: reply.len(),
            bytes_received: hello
                .len()
                .saturating_add(finish.len())
                .saturating_add(2 * header),
            elapsed: start.elapsed(),
        };
        Ok((session, d, info))
    })
    .await
    .context("handshake timed out")?
}

/// Make peer-controlled text safe to print on a terminal: control characters
/// (including ESC, which starts terminal escape sequences) are escaped.
pub fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(|c| {
            if c.is_control() && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// How a session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    /// Both directions closed with authenticated `Close` records.
    Clean,
    /// The peer's stream ended without `Close`: possible truncation attack.
    Truncated,
}

fn eof_ending(rx: &janus_channel::Receiver) -> Result<Ending> {
    match rx.finish() {
        Ok(()) => Ok(Ending::Clean),
        Err(ChannelError::Truncated) => Ok(Ending::Truncated),
        Err(e) => Err(e.into()),
    }
}

/// An established, mutually confirmed channel over a stream.
#[derive(Debug)]
pub struct Link {
    tx: Sender,
    rx: Receiver,
    d: Deframer,
}

/// Server side: open the channel and send the acceptance receipt.
///
/// The handshake has no fourth message, so after `ClientFinish` the client
/// cannot know whether the server accepted it (as in TLS 1.3). The demo makes
/// acceptance explicit: the server's first record is an empty `Data` record.
/// It is encrypted under the server→client key, which only a server that
/// accepted the client has derived.
pub async fn server_open<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: Session,
    d: Deframer,
    cfg: ChannelConfig,
) -> Result<Link> {
    let (mut tx, rx) = channel(session, cfg)?;
    stream.write_all(&tx.seal(&[])?).await?;
    Ok(Link { tx, rx, d })
}

/// Client side: open the channel and wait for the server's acceptance
/// receipt before reporting the session as established.
pub async fn client_open<S: AsyncRead + Unpin>(
    stream: &mut S,
    session: Session,
    mut d: Deframer,
    cfg: ChannelConfig,
) -> Result<Link> {
    let (tx, mut rx) = channel(session, cfg)?;
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(stream, &mut d))
        .await
        .context("server did not confirm the session in time")?;
    match first {
        Ok(Some(frame)) => match rx.open(&frame)? {
            Received::Data(m) if m.is_empty() => Ok(Link { tx, rx, d }),
            _ => bail!("unexpected first record from the server"),
        },
        Ok(None) | Err(_) => {
            bail!("the server refused the session (our identity is probably not pinned there)")
        }
    }
}

/// Echo server loop: every message is sent back; a `Close` is answered with
/// a `Close`.
pub async fn run_echo<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    link: Link,
) -> Result<Ending> {
    let Link {
        mut tx,
        mut rx,
        mut d,
    } = link;
    loop {
        let Some(frame) = read_frame(&mut stream, &mut d).await? else {
            return eof_ending(&rx);
        };
        match rx.open(&frame)? {
            Received::Data(msg) => stream.write_all(&tx.seal(&msg)?).await?,
            Received::Close => {
                stream.write_all(&tx.close()?).await?;
                stream.shutdown().await?;
                return Ok(Ending::Clean);
            }
        }
    }
}

/// Interactive chat: stdin lines are sent, incoming messages printed.
/// Ends when either side closes.
pub async fn run_interactive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    link: Link,
) -> Result<Ending> {
    let Link {
        mut tx,
        mut rx,
        mut d,
    } = link;
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut sent_close = false;
    loop {
        tokio::select! {
            line = stdin.next_line(), if !sent_close => {
                match line? {
                    Some(line) => {
                        for chunk in line.as_bytes().chunks(janus_channel::MAX_PLAINTEXT_LEN) {
                            stream.write_all(&tx.seal(chunk)?).await?;
                        }
                    }
                    None => {
                        stream.write_all(&tx.close()?).await?;
                        sent_close = true;
                    }
                }
            }
            frame = read_frame(&mut stream, &mut d) => {
                let Some(frame) = frame? else {
                    return eof_ending(&rx);
                };
                match rx.open(&frame)? {
                    Received::Data(msg) => println!("< {}", sanitize(&msg)),
                    Received::Close => {
                        if !sent_close {
                            stream.write_all(&tx.close()?).await?;
                        }
                        stream.shutdown().await?;
                        return Ok(Ending::Clean);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use janus_core::sig::IdentityKeypair;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    const CFG: ChannelConfig = ChannelConfig { rekey_interval: 2 };

    async fn connect(addr: std::net::SocketAddr, client: &Config) -> (TcpStream, Link) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let (session, d, _) = client_handshake(&mut s, client).await.unwrap();
        let link = client_open(&mut s, session, d, CFG).await.unwrap();
        (s, link)
    }

    fn configs() -> (Config, Config) {
        let c = IdentityKeypair::from_seed(&[1; 64]);
        let s = IdentityKeypair::from_seed(&[2; 64]);
        let client = Config {
            trust: [s.public().fingerprint()].into_iter().collect(),
            identity: c,
        };
        let server = Config {
            trust: [client.identity.public().fingerprint()]
                .into_iter()
                .collect(),
            identity: s,
        };
        (client, server)
    }

    async fn spawn_echo(
        server: Config,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<Ending>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(server);
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let (session, d, _) = server_handshake(&mut s, &server).await?;
            let link = server_open(&mut s, session, d, CFG).await?;
            run_echo(s, link).await
        });
        (addr, task)
    }

    #[tokio::test]
    async fn echo_over_tcp_with_rekeys() {
        let (client, server) = configs();
        let (addr, task) = spawn_echo(server).await;
        let (
            mut s,
            Link {
                mut tx,
                mut rx,
                mut d,
            },
        ) = connect(addr, &client).await;
        for i in 0..7u8 {
            s.write_all(&tx.seal(&[i; 10]).unwrap()).await.unwrap();
            let f = read_frame(&mut s, &mut d).await.unwrap().unwrap();
            assert_eq!(rx.open(&f).unwrap(), Received::Data(vec![i; 10]));
        }
        s.write_all(&tx.close().unwrap()).await.unwrap();
        let f = read_frame(&mut s, &mut d).await.unwrap().unwrap();
        assert_eq!(rx.open(&f).unwrap(), Received::Close);
        assert_eq!(task.await.unwrap().unwrap(), Ending::Clean);
    }

    #[tokio::test]
    async fn server_detects_truncation() {
        let (client, server) = configs();
        let (addr, task) = spawn_echo(server).await;
        let (
            mut s,
            Link {
                mut tx,
                mut rx,
                mut d,
            },
        ) = connect(addr, &client).await;
        s.write_all(&tx.seal(b"hi").unwrap()).await.unwrap();
        let f = read_frame(&mut s, &mut d).await.unwrap().unwrap();
        rx.open(&f).unwrap();
        drop(s); // TCP FIN without a Close record
        assert_eq!(task.await.unwrap().unwrap(), Ending::Truncated);
    }

    #[tokio::test]
    async fn untrusted_client_is_refused_over_tcp() {
        let (_, server) = configs();
        let rogue = Config {
            identity: IdentityKeypair::from_seed(&[9; 64]),
            trust: [server.identity.public().fingerprint()]
                .into_iter()
                .collect(),
        };
        let (addr, task) = spawn_echo(server).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // The client completes its side (it trusts the server)…
        let (session, d, _) = client_handshake(&mut s, &rogue).await.unwrap();
        // …but the server refuses it, and the client learns it before
        // reporting a session: no acceptance receipt arrives.
        let err = task.await.unwrap().unwrap_err();
        assert!(format!("{err:#}").contains("untrusted"), "{err:#}");
        let err = client_open(&mut s, session, d, CFG).await.unwrap_err();
        assert!(format!("{err:#}").contains("refused"), "{err:#}");
    }

    #[tokio::test]
    async fn garbage_is_rejected_without_panic() {
        let (_, server) = configs();
        let (addr, task) = spawn_echo(server).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x16, 0x00, 0x05, 1, 2, 3, 4, 5])
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[test]
    fn sanitize_escapes_terminal_controls() {
        assert_eq!(sanitize(b"hi\x1b[2Jthere\n"), "hi\\u{1b}[2Jthere\\n");
        assert_eq!(sanitize("café\t!".as_bytes()), "café\t!");
    }
}
