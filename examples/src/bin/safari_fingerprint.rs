//! Пример использования Safari fingerprint с rustls.
//!
//! Этот пример демонстрирует, как эмулировать TLS-отпечаток Safari
//! при подключении к HTTPS-сайтам.
//!
//! Запуск:
//! ```bash
//! cargo run --bin safari_fingerprint -- <hostname>
//! ```

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, SafariFingerprint};

fn main() {
    let hostname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    let hostname: &'static str = Box::leak(hostname.into_boxed_str());

    eprintln!("Подключаемся к {}...", hostname);

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_fingerprint(Arc::new(SafariFingerprint))
        .with_no_client_auth();

    let server_name = hostname.try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{}:443", hostname)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    eprintln!("Отправляем HTTP запрос...");
    tls.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            hostname
        )
        .as_bytes(),
    )
    .unwrap();

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(n) => {
            eprintln!("Получено {} bytes", n);
        }
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            eprintln!(
                "Получено {} bytes (сервер закрыл соединение без TLS close_notify)",
                plaintext.len()
            );
        }
        Err(e) => {
            eprintln!("Ошибка: {}", e);
            std::process::exit(1);
        }
    }
    stdout().write_all(&plaintext).unwrap();
}
