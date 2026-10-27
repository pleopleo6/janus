//! Session loops on top of [`janus_tokio::JanusStream`]: interactive chat,
//! echo, and TCP forwarding (tunnel).

use std::io;

use anyhow::{Context, Result};
use janus_tokio::JanusStream;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

/// How a session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    /// The peer closed with an authenticated `Close` record.
    Clean,
    /// The peer's stream ended without `Close`: possible truncation attack.
    Truncated,
}

/// Map the end of a read loop to an [`Ending`].
fn ending(res: io::Result<()>) -> Result<Ending> {
    match res {
        Ok(()) => Ok(Ending::Clean),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(Ending::Truncated),
        Err(e) => Err(e.into()),
    }
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

/// Echo every byte back until the peer closes, then close.
pub async fn run_echo<S: AsyncRead + AsyncWrite + Unpin>(stream: JanusStream<S>) -> Result<Ending> {
    let (mut r, mut w) = tokio::io::split(stream);
    let res = tokio::io::copy(&mut r, &mut w).await.map(|_| ());
    let end = ending(res)?;
    w.shutdown().await?;
    Ok(end)
}

/// Interactive chat: stdin lines are sent, incoming lines printed.
/// Ends when the peer closes (Ctrl-D closes our direction).
pub async fn run_interactive<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: JanusStream<S>,
) -> Result<Ending> {
    let (r, mut w) = tokio::io::split(stream);
    let mut printer = tokio::spawn(async move {
        let mut lines = BufReader::new(r).split(b'\n');
        while let Some(line) = lines.next_segment().await? {
            println!("< {}", sanitize(&line));
        }
        Ok::<(), io::Error>(())
    });
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut stdin_open = true;
    loop {
        tokio::select! {
            line = stdin.next_line(), if stdin_open => match line? {
                Some(line) => {
                    w.write_all(line.as_bytes()).await?;
                    w.write_all(b"\n").await?;
                    w.flush().await?;
                }
                None => {
                    w.shutdown().await?;
                    stdin_open = false;
                }
            },
            res = &mut printer => {
                let end = ending(res.context("reader task")?)?;
                if stdin_open {
                    w.shutdown().await?;
                }
                return Ok(end);
            }
        }
    }
}

/// Pipe a Janus stream and a plain TCP connection into each other until
/// both directions are closed. Returns the bytes moved each way.
pub async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    mut secure: JanusStream<S>,
    mut plain: TcpStream,
) -> Result<(u64, u64)> {
    tokio::io::copy_bidirectional(&mut secure, &mut plain)
        .await
        .context("forwarding stopped")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use janus_core::handshake::Config;
    use janus_core::sig::IdentityKeypair;
    use janus_tokio::{Options, accept, connect};
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

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

    #[tokio::test]
    async fn echo_over_tcp() {
        let (client, server) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            run_echo(accept(s, &server, Options::default()).await.unwrap()).await
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = connect(tcp, &client, Options::default()).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        c.shutdown().await.unwrap();
        let mut back = Vec::new();
        c.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"ping");
        assert_eq!(task.await.unwrap().unwrap(), Ending::Clean);
    }

    #[tokio::test]
    async fn echo_reports_truncation() {
        let (client, server) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            run_echo(accept(s, &server, Options::default()).await.unwrap()).await
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = connect(tcp, &client, Options::default()).await.unwrap();
        c.write_all(b"cut").await.unwrap();
        c.flush().await.unwrap();
        drop(c); // TCP FIN, no Close record
        assert_eq!(task.await.unwrap().unwrap(), Ending::Truncated);
    }

    /// Full tunnel over real sockets: plain app → tunnel entrance → Janus
    /// server → plain service.
    #[tokio::test]
    async fn tunnel_end_to_end() {
        let (client, server) = configs();
        // The protected service: uppercases what it receives.
        let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_addr = service.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = service.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            s.write_all(&buf.to_ascii_uppercase()).await.unwrap();
        });
        // Janus server forwarding to the service.
        let jserver = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jaddr = jserver.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = jserver.accept().await.unwrap();
            let secure = accept(s, &server, Options::default()).await.unwrap();
            let plain = TcpStream::connect(service_addr).await.unwrap();
            forward(secure, plain).await.unwrap();
        });
        // Tunnel entrance.
        let entrance = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let eaddr = entrance.local_addr().unwrap();
        tokio::spawn(async move {
            let (plain, _) = entrance.accept().await.unwrap();
            let tcp = TcpStream::connect(jaddr).await.unwrap();
            let secure = connect(tcp, &client, Options::default()).await.unwrap();
            forward(secure, plain).await.unwrap();
        });
        // An unmodified application talks to the entrance in clear.
        let mut app = TcpStream::connect(eaddr).await.unwrap();
        app.write_all(b"select * from secrets;").await.unwrap();
        app.shutdown().await.unwrap();
        let mut resp = Vec::new();
        app.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"SELECT * FROM SECRETS;");
    }

    #[test]
    fn sanitize_escapes_terminal_controls() {
        assert_eq!(sanitize(b"hi\x1b[2Jthere\n"), "hi\\u{1b}[2Jthere\\n");
        assert_eq!(sanitize("café\t!".as_bytes()), "café\t!");
    }
}
