#![forbid(unsafe_code)]
//! Async secure streams over the Janus hybrid post-quantum handshake.
//!
//! Wrap any `AsyncRead + AsyncWrite` transport (usually a `TcpStream`):
//!
//! ```no_run
//! # async fn demo(config: janus_core::handshake::Config) -> std::io::Result<()> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! let tcp = tokio::net::TcpStream::connect("server.example:7878").await?;
//! let mut stream = janus_tokio::connect(tcp, &config, janus_tokio::Options::default()).await?;
//! println!("talking to {}", stream.peer_fingerprint());
//! stream.write_all(b"hello").await?;
//! stream.shutdown().await?; // sends an authenticated Close record
//! # Ok(()) }
//! ```
//!
//! [`JanusStream`] implements `AsyncRead` and `AsyncWrite`, so it can be
//! handed to anything that speaks tokio I/O (`copy_bidirectional`, codecs,
//! HTTP clients, …).
//!
//! Semantics:
//! - [`connect`] returns only once the server has *accepted* the client:
//!   the server's first record is an empty acceptance receipt, encrypted
//!   under the server→client key (the handshake alone does not tell the
//!   client whether the server accepted it);
//! - writes are split into records of at most 16 KiB;
//! - reading returns EOF only after the peer's authenticated `Close`
//!   record. If the transport ends without one, reads fail with
//!   [`std::io::ErrorKind::UnexpectedEof`] (possible truncation attack);
//! - any authentication failure is fatal for the stream.
//!
//! **Educational project, not production-ready.**

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use janus_channel::{
    ChannelConfig, Deframer, Error as ChannelError, Frame, FrameType, MAX_PLAINTEXT_LEN, Received,
    Receiver, Sender, channel,
};
use janus_core::handshake::{self, Config, Session};
use janus_core::schedule::Hash;
use janus_core::sig::Fingerprint;
use rand_core::{TryRng as _, UnwrapErr};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

/// Connection options. Both peers must use the same `channel` settings.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Record-layer parameters (rekey interval).
    pub channel: ChannelConfig,
    /// Upper bound on the handshake, including the acceptance receipt.
    pub handshake_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            channel: ChannelConfig::default(),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// Facts about a completed handshake.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeInfo {
    /// Bytes written during the handshake (framing included).
    pub bytes_sent: usize,
    /// Bytes read during the handshake (framing included).
    pub bytes_received: usize,
    /// Wall-clock time, network round trips included.
    pub elapsed: Duration,
}

/// A mutually authenticated, encrypted stream.
pub struct JanusStream<S> {
    io: S,
    tx: Sender,
    rx: Receiver,
    deframer: Deframer,
    /// Decrypted bytes not yet returned to the reader.
    plain: Vec<u8>,
    plain_pos: usize,
    /// Encrypted bytes not yet written to the transport.
    out: Vec<u8>,
    out_pos: usize,
    peer_closed: bool,
    we_closed: bool,
    peer: Fingerprint,
    session_id: Hash,
    info: HandshakeInfo,
}

impl<S> fmt::Debug for JanusStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JanusStream")
            .field("peer", &self.peer)
            .field("tx", &self.tx)
            .field("rx", &self.rx)
            .finish_non_exhaustive()
    }
}

impl<S> JanusStream<S> {
    /// Fingerprint of the authenticated peer.
    pub fn peer_fingerprint(&self) -> Fingerprint {
        self.peer
    }

    /// Session identifier, equal on both sides (compare it out of band to
    /// rule out a man in the middle).
    pub fn session_id(&self) -> &Hash {
        &self.session_id
    }

    /// Handshake statistics.
    pub fn handshake_info(&self) -> HandshakeInfo {
        self.info
    }

    /// The underlying transport.
    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

fn io_err(e: ChannelError) -> io::Error {
    let kind = match e {
        ChannelError::Truncated => io::ErrorKind::UnexpectedEof,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

fn hs_err(e: janus_core::Error) -> io::Error {
    let kind = match e {
        janus_core::Error::UntrustedPeer | janus_core::Error::BadSignature => {
            io::ErrorKind::PermissionDenied
        }
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

/// The OS RNG, probed first so that its failure is an error, not a panic.
fn rng() -> io::Result<UnwrapErr<getrandom::SysRng>> {
    let mut probe = [0u8; 16];
    getrandom::SysRng
        .try_fill_bytes(&mut probe)
        .map_err(|e| io::Error::other(format!("OS RNG unavailable: {e}")))?;
    Ok(UnwrapErr(getrandom::SysRng))
}

async fn read_frame<S: AsyncRead + Unpin>(
    io: &mut S,
    d: &mut Deframer,
) -> io::Result<Option<Frame>> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if let Some(f) = d.next_frame().map_err(io_err)? {
            return Ok(Some(f));
        }
        let n = io.read(&mut buf).await?;
        if n == 0 {
            d.finish().map_err(io_err)?;
            return Ok(None);
        }
        d.push(buf.get(..n).unwrap_or_default());
    }
}

async fn read_handshake<S: AsyncRead + Unpin>(io: &mut S, d: &mut Deframer) -> io::Result<Vec<u8>> {
    match read_frame(io, d).await? {
        Some(Frame {
            ty: FrameType::Handshake,
            body,
        }) => Ok(body),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected record during the handshake",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed the connection during the handshake",
        )),
    }
}

fn frame(msg: &[u8]) -> io::Result<Vec<u8>> {
    Frame::handshake(msg).map_err(io_err)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "handshake timed out")
}

fn assemble<S>(
    io: S,
    session: Session,
    deframer: Deframer,
    opts: Options,
    info: HandshakeInfo,
) -> io::Result<JanusStream<S>> {
    let peer = session.peer().fingerprint();
    let session_id = *session.session_id();
    let (tx, rx) = channel(session, opts.channel).map_err(io_err)?;
    Ok(JanusStream {
        io,
        tx,
        rx,
        deframer,
        plain: Vec::new(),
        plain_pos: 0,
        out: Vec::new(),
        out_pos: 0,
        peer_closed: false,
        we_closed: false,
        peer,
        session_id,
        info,
    })
}

/// Run the handshake as the initiator and wait for the server's acceptance.
///
/// # Errors
/// I/O errors, handshake failures (`PermissionDenied` for an untrusted or
/// impersonated server), `TimedOut`, or a refusal by the server.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    config: &Config,
    opts: Options,
) -> io::Result<JanusStream<S>> {
    let start = Instant::now();
    let mut rng = rng()?;
    let fut = async {
        let mut d = Deframer::new();
        let (state, hello) = handshake::client_start(config, &mut rng);
        let hello = frame(&hello)?;
        io.write_all(&hello).await?;
        let reply = read_handshake(&mut io, &mut d).await?;
        let (finish, session) = state.read_server_hello(&reply, &mut rng).map_err(hs_err)?;
        let finish = frame(&finish)?;
        io.write_all(&finish).await?;
        io.flush().await?;
        let info = HandshakeInfo {
            bytes_sent: hello.len().saturating_add(finish.len()),
            bytes_received: reply
                .len()
                .saturating_add(janus_channel::framing::FRAME_HEADER_LEN),
            elapsed: Duration::ZERO,
        };
        // Wait for the acceptance receipt.
        let receipt = read_frame(&mut io, &mut d).await;
        Ok::<_, io::Error>((session, d, info, receipt))
    };
    let (session, d, mut info, receipt) = tokio::time::timeout(opts.handshake_timeout, fut)
        .await
        .map_err(|_| timed_out())??;
    let mut stream = assemble(io, session, d, opts, info)?;
    match receipt {
        Ok(Some(f)) => match stream.rx.open(&f).map_err(io_err)? {
            Received::Data(m) if m.is_empty() => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected first record from the server",
                ));
            }
        },
        Ok(None) | Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the server refused the session (is our identity pinned there?)",
            ));
        }
    }
    info.elapsed = start.elapsed();
    stream.info = info;
    Ok(stream)
}

/// Run the handshake as the responder and send the acceptance receipt.
///
/// # Errors
/// I/O errors, handshake failures (`PermissionDenied` for an untrusted or
/// impersonated client), `TimedOut`.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    config: &Config,
    opts: Options,
) -> io::Result<JanusStream<S>> {
    let mut rng = rng()?;
    let fut = async {
        let mut d = Deframer::new();
        let hello = read_handshake(&mut io, &mut d).await?;
        let start = Instant::now();
        let (state, reply) = handshake::server_accept(config, &hello, &mut rng).map_err(hs_err)?;
        let reply = frame(&reply)?;
        io.write_all(&reply).await?;
        io.flush().await?;
        let finish = read_handshake(&mut io, &mut d).await?;
        let session = state.read_client_finish(&finish).map_err(hs_err)?;
        let header = janus_channel::framing::FRAME_HEADER_LEN;
        let info = HandshakeInfo {
            bytes_sent: reply.len(),
            bytes_received: hello
                .len()
                .saturating_add(finish.len())
                .saturating_add(header.saturating_mul(2)),
            elapsed: start.elapsed(),
        };
        Ok::<_, io::Error>((session, d, info))
    };
    let (session, d, info) = tokio::time::timeout(opts.handshake_timeout, fut)
        .await
        .map_err(|_| timed_out())??;
    let mut stream = assemble(io, session, d, opts, info)?;
    stream.out = stream.tx.seal(&[]).map_err(io_err)?;
    stream.flush().await?;
    Ok(stream)
}

impl<S: AsyncWrite + Unpin> JanusStream<S> {
    /// Write out any buffered ciphertext.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(pending) = self.out.get(self.out_pos..).filter(|p| !p.is_empty()) {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos = self.out_pos.saturating_add(n);
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for JanusStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(avail) = this.plain.get(this.plain_pos..).filter(|a| !a.is_empty()) {
                let n = avail.len().min(buf.remaining());
                buf.put_slice(avail.get(..n).unwrap_or_default());
                this.plain_pos = this.plain_pos.saturating_add(n);
                return Poll::Ready(Ok(()));
            }
            if this.peer_closed {
                return Poll::Ready(Ok(())); // clean EOF
            }
            match this.deframer.next_frame().map_err(io_err)? {
                Some(frame) => match this.rx.open(&frame).map_err(io_err)? {
                    // Empty records carry no data (e.g. the acceptance
                    // receipt) and must not be mistaken for EOF.
                    Received::Data(pt) => {
                        this.plain = pt;
                        this.plain_pos = 0;
                    }
                    Received::Close => this.peer_closed = true,
                },
                None => {
                    let mut tmp = [0u8; 8 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        // Transport EOF without an authenticated Close.
                        this.deframer.finish().map_err(io_err)?;
                        return Poll::Ready(Err(io_err(
                            this.rx.finish().err().unwrap_or(ChannelError::Truncated),
                        )));
                    }
                    this.deframer.push(rb.filled());
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for JanusStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.we_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(MAX_PLAINTEXT_LEN);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        this.out = this
            .tx
            .seal(buf.get(..n).unwrap_or_default())
            .map_err(io_err)?;
        this.out_pos = 0;
        // The data is now committed; push it out opportunistically. Pending
        // bytes are written by the next write / flush / shutdown.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.we_closed {
            this.out = this.tx.close().map_err(io_err)?;
            this.out_pos = 0;
            this.we_closed = true;
            ready!(this.poll_drain(cx))?;
        }
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
