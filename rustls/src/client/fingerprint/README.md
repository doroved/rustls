# Модуль Browser Fingerprint (эмуляция отпечатков браузера)

## Обзор

Этот модуль реализует **модульную эмуляцию отпечатков браузеров** для rustls. Он позволяет модифицировать `ClientHello`, чтобы он соответствовал TLS-отпечатку конкретного браузера (cipher suites, динамический порядок расширений, ECH GREASE, GREASE-значения и т.д.), при этом сохраняя стандартное поведение rustls, когда fingerprint не настроен.

Поддерживаемые отпечатки:
- **Chrome** (desktop на macOS / Linux / Windows)
- **WebKit** (Safari на macOS / WebKit на iOS)

**Ключевой принцип проектирования:** Fingerprinting — **opt-in** (подключается явно). Все fingerprint-специфичные модификации (cipher suites, порядок расширений, ECH GREASE, дополнительные kx groups, certificate compression) применяются **только** при вызове `.with_fingerprint()`. Без него rustls ведёт себя идентично upstream `v/0.23.40`.

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│  ConfigBuilder::with_fingerprint()                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Включить ECH GREASE (если fp.wants_ech_grease()) │   │
│  │ 2. Клонировать CryptoProvider & добавить SECP521R1 │   │
│  │ 3. Настроить cert_compressors / decompressors       │   │
│  │ 4. Сохранить fingerprint в state                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    client/hs.rs                              │
│  После того как rustls построил дефолтный ClientHelloPayload:│
│  1. fp.apply(&mut payload, is_retry)                        │
│  2. Обновить ALPN-трекинг в соответствии с fingerprint       │
│  3. Продолжить обычный handshake                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Основные компоненты

### 1. Трейт `ClientHelloFingerprinter`

```rust
pub trait ClientHelloFingerprinter: Send + Sync + 'static + core::fmt::Debug {
    /// Modify the given `ClientHelloPayload` in-place.
    fn apply(&self, payload: &mut ClientHelloPayload, is_retry: bool);

    /// Returns `true` if this browser fingerprint sends ECH GREASE by default.
    fn wants_ech_grease(&self) -> bool {
        false
    }
}
```

- Вызывается **после** того, как rustls сконструировал дефолтный `ClientHelloPayload`, но **до** его кодирования на wire.
- `wants_ech_grease()` позволяет билдеру `.with_fingerprint()` автоматически включить ECH GREASE, избавив пользователя от необходимости вручную вызывать `.with_ech(...)`.

### 2. Улучшение макроса `extension_struct!`

Макрос (в `msgs/macros.rs`) расширен опциональным блоком `unknown { }`:

```rust
extension_struct! {
    pub(crate) struct ClientExtensions<'a> {
        ExtensionType::ServerName => pub(crate) server_name: Option<ServerNamePayload<'a>>,
        // ... другие известные расширения
    } + {
        pub(crate) order_seed: u16,
        pub(crate) contiguous_extensions: Vec<ExtensionType>,
    } unknown {
        pub(crate) unknown_extensions,
    }
}
```

---

## Реализация Chrome Fingerprint

### Цель

Полное соответствие TLS Client Hello от **Google Chrome (desktop)**.

- **JA4**: `t13d1516h2_8daaf6152771_806a8c22fdea`
- **JA3**: `2b5f481644e2bffe78bd0ae32c85add3`

### Cipher Suites (всего 16)

Точный порядок наборов шифрования Google Chrome:

```rust
[
    GREASE,                          // случайное GREASE-значение (0x0A0A, 0x1A1A, ...)
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
]
```

### Динамическая перестановка расширений (Extension Permutation)

В настоящем Chrome (BoringSSL feature `SSL_set_permute_extensions`) порядок внутренних расширений между начальным GREASE и конечным GREASE **рандомизируется (перемешивается)** при каждом новом Client Hello пакете:

1. **GREASE extension 1** (пустой payload) — случайный тип из `GREASE_VALUES`
2. **16 внутренних расширений** в **случайном порядке** (Fisher-Yates shuffle на базе PRNG текущего сеанса):
   - `server_name` (SNI)
   - `supported_groups` (`[GREASE, X25519MLKEM768, X25519, secp256r1, secp384r1]`)
   - `supported_versions` (`[GREASE, TLS 1.3, TLS 1.2]`)
   - `psk_key_exchange_modes` (`psk_dhe: true`)
   - `extended_master_secret`
   - `signed_certificate_timestamp` (`0x0012`)
   - `application_settings` (ALPS: `h2`, `0x44cd`)
   - `application_layer_protocol_negotiation` (ALPN: `h2`, `http/1.1`)
   - `ec_point_formats` (uncompressed)
   - `renegotiation_info`
   - `key_share` (`[GREASE, X25519MLKEM768, X25519]`)
   - `encrypted_client_hello` (`0xfe0d` / `65037`)
   - `session_ticket` (request)
   - `signature_algorithms` (`mldsa44`, `mldsa65`, `mldsa87` + классические схемы)
   - `status_request` (OCSP)
   - `compress_certificate` (Brotli)
3. **Второе GREASE extension** (payload: `[0x00]`) — **отличный тип от первого GREASE**

### Динамический размер пакетов (Без 0x0015 Padding)

- В Chrome **отсутствует** Padding Extension (`0x0015`).
- Вместо этого Chrome динамически варьирует размер ECH GREASE полезной нагрузки (`outer.payload`) блоками по 32 байта (144..272+ байт).
- В результате итоговая длина пакетов Client Hello на wire меняется динамически от соединения к соединению (например, 405, 437, 469, 501 байт), в точности как в Wireshark-дампах Google Chrome.

---

## Реализация WebKit (Safari) Fingerprint

### Цель

Соответствие вызову **Safari / WebKit 26.0.1 на macOS Sequoia / iOS**.

- **JA4**: `t13d2014h2_a09f3c656075_e42f34c56612`

### Cipher Suites (всего 21)

Точная последовательность WebKit / Safari (включая 3DES суиты).

### Порядок расширений WebKit / Safari

Фиксированная последовательность расширений + выравнивание пакета до **512 байт** через Padding Extension (`0x0015`).

---

## GREASE-генератор случайных чисел

Используется встроенный быстрый xorshift64* PRNG, сидируемый из байтов `session_id` / `random`.
Включает зашиту от нулевого состояния (`if state == 0 { state = 0x9E3779B97F4A7C15 }`), предотвращающую зацикливание при пустом session ID.

---

## Пример использования

### Код Chrome Fingerprint:

```rust
use rustls::{ClientConfig, ChromeFingerprint, RootCertStore};
use std::sync::Arc;

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_fingerprint(Arc::new(ChromeFingerprint))
    .with_no_client_auth();
```

### Код WebKit (Safari) Fingerprint:

```rust
use rustls::{ClientConfig, WebKitFingerprint, RootCertStore};
use std::sync::Arc;

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_fingerprint(Arc::new(WebKitFingerprint))
    .with_no_client_auth();
```

---

## Команды запуска примеров

Для тестирования и проверки отпечатков в проекте предусмотрены бинарники примеров:

### 1. Запуск Chrome Fingerprint:
```bash
cargo run --bin chrome_fingerprint --package rustls-examples -- example.com
```

### 2. Запуск WebKit (Safari) Fingerprint:
```bash
cargo run --bin webkit_fingerprint --package rustls-examples -- example.com
```

### 3. Проверка на сервере анализа отпечатков (`tls.peet.ws`):
```bash
cargo run --bin chrome_fingerprint --package rustls-examples -- tls.peet.ws
```

---

## Изменённые файлы

| Файл | Описание изменений |
|------|-------------------|
| `rustls/Cargo.toml` | Добавлена `brotli` фича по умолчанию |
| `rustls/src/client/fingerprint/mod.rs` | Трейт `ClientHelloFingerprinter` + метод `wants_ech_grease()` |
| `rustls/src/client/fingerprint/chrome.rs` | Модуль эмуляции Chrome fingerprint + extension permutation + динамический ECH GREASE |
| `rustls/src/client/fingerprint/webkit.rs` | Модуль эмуляции WebKit (Safari) fingerprint |
| `rustls/src/client/fingerprint/grease.rs` | `GreaseRng` с защитой от нулевого состояния |
| `rustls/src/client/builder.rs` | `.with_fingerprint()` — авто-настройка ECH GREASE, Brotli/Zlib и SECP521R1 |
| `rustls/src/msgs/handshake.rs` | Фикс проверки дублирования `contiguous_extensions.contains()` |
| `examples/src/bin/chrome_fingerprint.rs` | Пример использования Chrome отпечатка |
| `examples/src/bin/webkit_fingerprint.rs` | Пример использования WebKit (Safari) отпечатка |
