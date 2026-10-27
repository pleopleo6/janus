#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::ErrorKind;
use std::time::Duration;

use janus_channel::ChannelConfig;
use janus_core::handshake::Config;
use janus_core::sig::IdentityKeypair;
use janus_tokio::{Options, accept, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

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

fn opts() -> Options {
    Options {
        channel: ChannelConfig { rekey_interval: 3 },
        handshake_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn bulk_transfer_both_ways_across_rekeys() {
    let (client, server) = configs();
    // A small pipe forces partial reads and writes everywhere.
    let (a, b) = duplex(1024);
    let srv = tokio::spawn(async move {
        let mut s = accept(b, &server, opts()).await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        s.write_all(&got).await.unwrap();
        s.shutdown().await.unwrap();
        got.len()
    });
    let mut c = connect(a, &client, opts()).await.unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    c.write_all(&data).await.unwrap();
    c.shutdown().await.unwrap();
    let mut back = Vec::new();
    c.read_to_end(&mut back).await.unwrap();
    assert_eq!(srv.await.unwrap(), data.len());
    assert_eq!(back, data);
}

#[tokio::test]
async fn both_sides_agree_on_session_and_peers() {
    let (client, server) = configs();
    let (cfp, sfp) = (
        client.identity.public().fingerprint(),
        server.identity.public().fingerprint(),
    );
    let (a, b) = duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        let s = accept(b, &server, opts()).await.unwrap();
        (*s.session_id(), s.peer_fingerprint())
    });
    let c = connect(a, &client, opts()).await.unwrap();
    let (sid, seen) = srv.await.unwrap();
    assert_eq!(c.session_id(), &sid);
    assert_eq!(c.peer_fingerprint(), sfp);
    assert_eq!(seen, cfp);
    let info = c.handshake_info();
    assert_eq!(info.bytes_sent, 1253 + 5410);
}

#[tokio::test]
async fn refused_client_learns_it_at_connect() {
    let (_, server) = configs();
    let rogue = Config {
        identity: IdentityKeypair::from_seed(&[9; 64]),
        trust: [server.identity.public().fingerprint()]
            .into_iter()
            .collect(),
    };
    let (a, b) = duplex(64 * 1024);
    let srv = tokio::spawn(async move { accept(b, &server, opts()).await.map(|_| ()) });
    let err = connect(a, &rogue, opts()).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "{err}");
    assert_eq!(
        srv.await.unwrap().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn untrusted_server_is_permission_denied() {
    let (client, _) = configs();
    let impostor = Config {
        identity: IdentityKeypair::from_seed(&[7; 64]),
        trust: [client.identity.public().fingerprint()]
            .into_iter()
            .collect(),
    };
    let (a, b) = duplex(64 * 1024);
    tokio::spawn(async move { accept(b, &impostor, opts()).await.map(|_| ()) });
    let err = connect(a, &client, opts()).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
}

#[tokio::test]
async fn transport_eof_without_close_is_unexpected_eof() {
    let (client, server) = configs();
    let (a, b) = duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        let mut s = accept(b, &server, opts()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.map(|_| buf)
    });
    let mut c = connect(a, &client, opts()).await.unwrap();
    c.write_all(b"partial").await.unwrap();
    c.flush().await.unwrap();
    drop(c); // drops the pipe without a Close record
    let err = srv.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn silent_server_times_out() {
    let (client, _) = configs();
    let (a, _b) = duplex(64 * 1024);
    let o = Options {
        handshake_timeout: Duration::from_millis(100),
        ..opts()
    };
    let err = connect(a, &client, o).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn copy_bidirectional_works_through_janus() {
    // The tunnel use case: plain bytes on one side, Janus on the other.
    let (client, server) = configs();
    let (a, b) = duplex(4096);
    let (mut app, app_side) = duplex(4096);
    tokio::spawn(async move {
        let mut s = accept(b, &server, opts()).await.unwrap();
        let mut plain = app_side;
        tokio::io::copy_bidirectional(&mut s, &mut plain)
            .await
            .unwrap();
    });
    let mut c = connect(a, &client, opts()).await.unwrap();
    c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    c.flush().await.unwrap();
    let mut req = [0u8; 18];
    app.read_exact(&mut req).await.unwrap();
    assert_eq!(&req, b"GET / HTTP/1.0\r\n\r\n");
    app.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();
    let mut resp = [0u8; 17];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"HTTP/1.0 200 OK\r\n");
}
