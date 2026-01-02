//! This is the simplest possible client using rustls that does something useful:
//! it accepts the default configuration, loads some root certs, and then connects
//! to rust-lang.org and issues a basic HTTP request.  The response is printed to stdout.
//!
//! It makes use of rustls::Stream to treat the underlying TLS connection as a basic
//! bi-directional stream -- the underlying IO is performed transparently.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::RootCertStore;

fn main() {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // ВАЖНО: Добавьте ALPN протоколы здесь
    // config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // config.no_alpn = true;
    // Установка отпечатка Chrome
    // config.fingerprint = Some(rustls::TlsFingerprint::Chrome);
    // Установка отпечатка Webkit
    config.fingerprint = Some(rustls::TlsFingerprint::Webkit);

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Run RUST_LOG=trace cargo run --bin simpleclient

    // let host = "example.com"; // Поддерживает SCT, ECH
    // let host = "cloudflare.com"; // Поддерживает ECH
    // let host = "vk.com";
    let host = "github.com";
    // let host = "speed.cloudflare.com"; // http/1.1, Поддерживает ECH
    // let host = "www.youtube.com"; //
    // let host = "rr14---sn-n8v7kn7l.googlevideo.com"; // пустой ALPN
    let server_name = host.try_into().unwrap();
    // Для *.googlevideo.com
    // let server_name = "xn--ngstr-lra8j.com"
    //     .try_into()
    //     .unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{host}:443")).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
    );

    if let Err(e) = tls.write_all(http_request.as_bytes()) {
        eprintln!("Error writing to TLS stream: {}", e);
    }

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap()
        .suite();
    let key_exchange_group = tls
        .conn
        .negotiated_key_exchange_group()
        .unwrap();
    let alpn_protocol = String::from_utf8_lossy(tls.conn.alpn_protocol().unwrap_or(&[]));

    writeln!(
        &mut std::io::stderr(),
        "{host} | {ciphersuite:?} | {key_exchange_group:?} | {alpn_protocol}",
    )
    .unwrap();

    let mut plaintext = Vec::new();
    if let Err(e) = tls.read_to_end(&mut plaintext) {
        eprintln!("Error reading from TLS stream: {}", e);
    }
    stdout().write_all(&plaintext).unwrap();
}
