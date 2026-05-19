# Модуль Browser Fingerprint (эмуляция отпечатков браузера)

## Обзор

Этот модуль реализует **модульную эмуляцию отпечатков браузера** для rustls. Он позволяет модифицировать `ClientHello`, чтобы он соответствовал TLS-отпечатку конкретного браузера (cipher suites, порядок расширений, GREASE-значения и т.д.), при этом сохраняя стандартное поведение rustls, когда fingerprint не настроен.

Основной use case — эмуляция **Safari на macOS / WebKit на iOS** для совпадения с JA4-отпечатками и прохождения TLS fingerprinting-проверок, которые используют некоторые серверы.

**Ключевой принцип проектирования:** Fingerprinting — **opt-in** (подключается явно). Все fingerprint-специфичные модификации (cipher suites, порядок расширений, GREASE, дополнительные kx groups, certificate compression) применяются **только** при вызове `.with_fingerprint()`. Без него rustls ведёт себя идентично upstream `v/0.23.40`.

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│  ConfigBuilder::with_fingerprint()                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Клонировать CryptoProvider                       │   │
│  │ 2. Добавить SECP521R1 в kx_groups                   │   │
│  │ 3. Установить cert_compressors = [ZLIB]             │   │
│  │ 4. Установить cert_decompressors = [ZLIB]           │   │
│  │ 5. Сохранить fingerprint в state                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    client/hs.rs (строка ~420)                │
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
    fn apply(&self, payload: &mut ClientHelloPayload, is_retry: bool);
}
```

- Вызывается **после** того, как rustls сконструировал дефолтный `ClientHelloPayload`, но **до** его кодирования
- Получает мутабельный доступ ко всему payload
- `is_retry` указывает, является ли это ClientHello, отправленным в ответ на HelloRetryRequest

### 2. Улучшение макроса `extension_struct!`

Макрос (в `msgs/macros.rs`) был расширен опциональным блоком `unknown { }`:

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

**Что изменилось:**
- Добавлено поле `unknown_extensions: Vec<UnknownExtension>`
- `read_extension_body()` теперь сохраняет нераспознанные расширения в `unknown_extensions` вместо возврата `false` (что вызывало бы ошибки парсинга)
- `encode_one()` проверяет `unknown_extensions` **до** проверки известных полей — это позволяет делать кастомное кодирование известных типов (например, `SupportedVersions` с TLS 1.1/1.0)
- `collect_used()` включает типы из `unknown_extensions`

### 3. Структура `UnknownExtension`

```rust
pub struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload<'static>,
}
```

- Определена в `msgs/handshake.rs`
- Видимость полей изменена на `pub(crate)` для использования в клиентских расширениях
- Хранит сырые байты для любого типа расширения
- Кодируется напрямую без валидации структуры

---

## Реализация Safari Fingerprint

### Цель

Соответствие захвату Wireshark от **Safari 26.0.1 на macOS Sequoia 15.7.1**.

JA4-отпечаток: `t13d2014h2_a09f3c656075_e42f34c56612`

### Cipher Suites (всего 21)

Точный порядок из захвата Safari:

```rust
[
    GREASE,                          // случайное GREASE-значение
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
]
```

### Порядок расширений (точная последовательность Safari)

Расширения помещаются в вектор `contiguous_extensions` для сохранения порядка:

1. **GREASE extension** (пустой payload) — случайный тип из `GREASE_VALUES`
2. **server_name** (SNI) — если присутствует
3. **extended_master_secret** (пустой)
4. **renegotiation_info** (пустой)
5. **supported_groups** — `[GREASE, X25519, secp256r1, secp384r1, secp521r1]` (P-521 добавляется динамически через `.with_fingerprint()`)
6. **ec_point_formats** (uncompressed)
7. **ALPN** — `[h2, http/1.1]` (только если пользователь не сконфигурировал ALPN)
8. **status_request** (OCSP)
9. **signature_algorithms** — включает дубликат `RSA_PSS_SHA384` (`0x0805`)
10. **signed_certificate_timestamp** (пустой, тип `0x0012`)
11. **key_share** — `[GREASE, X25519]` в CH1, группа, запрошенная сервером, в CH2
12. **psk_key_exchange_modes** (`psk_dhe: true`)
13. **supported_versions** — кастомное кодирование с TLS 1.3, 1.2, 1.1, 1.0 + GREASE
14. **compress_certificate** (только zlib) — добавляется только при `.with_fingerprint()`
15. **Второе GREASE extension** (payload: `[0x00]`) — **другой тип, чем у первого GREASE**
16. **padding** (переменная длина для достижения 512-байтового TLS-записи)

### GREASE-инъекция

Используется 5 случайных GREASE-значений на ClientHello:
- 1 для cipher suite
- 1 для supported_groups / key_share
- 1 для supported_versions
- 2 для extensions (должны быть **разными**)

**Критический фикс:** Два GREASE-значения для расширений **должны отличаться**. Если они равны, `collect_used()` выдаст тип дважды, но `encode_one()` найдёт первое совпадение `unknown_extension` и закодирует его дважды с тем же payload. Это вызывает `DecodeError` на сервере, потому что второе расширение имеет неправильную длину.

### Обработка Key Share

- **CH1 (начальный):** Оставляет только X25519 из сгенерированных rustls shares, добавляет GREASE key share с payload `[0x00]` в начало
- **CH2 (ответ на HRR):** Оставляет сгенерированный rustls share для запрошенной группы без изменений

### Обработка ALPN

Fingerprint Safari по умолчанию устанавливает `[h2, http/1.1]`, но **только если пользователь явно не сконфигурировал ALPN**:

```rust
if exts.protocols.is_none() {
    exts.protocols = Some(vec![
        ProtocolName::from(b"h2".to_vec()),
        ProtocolName::from(b"http/1.1".to_vec()),
    ]);
}
```

Это позволяет пользователю переопределить (например, example использует `[http/1.1]` для простых HTTP-запросов).

### Кастомные расширения

#### Supported Versions (тип 0x002b)
Вместо использования стандартной структуры `SupportedProtocolVersions` (которая кодирует только TLS 1.3/1.2), Safari отправляет:
```
0x0a                    // длина 10 байт
[GREASE]               // 2 байта
0x0304 (TLS 1.3)       // 2 байта
0x0303 (TLS 1.2)       // 2 байта
0x0302 (TLS 1.1)       // 2 байта
0x0301 (TLS 1.0)       // 2 байта
```

Реализовано путём очистки `exts.supported_versions = None` и инъекции сырых байтов как `UnknownExtension`.

#### Padding (тип 0x0015)
Только в начальном ClientHello. Закодированный payload — нулевые байты, чтобы TLS-запись была ровно 512 байт:
```rust
pad_data_len = 512 - current_body_len - 8
```

Где `current_body_len` измеряется кодированием payload без padding, а `8` — это handshake header (4 байта) + заголовок padding-расширения (4 байта).

---

## GREASE-генератор случайных чисел

### Почему не крейт `rand`?

`rand` не является зависимостью `rustls`. Добавлять целый крейт ради 5 случайных чисел — перебор. Используем простой xorshift64* PRNG.

### Реализация `GreaseRng`

```rust
pub(crate) struct GreaseRng {
    state: u64,
}
```

**Сидирование:** Берёт первые 8 байт `session_id` как `u64` seed. Это даёт:
- **Стабильность:** Одинаковый session ID → одинаковые GREASE-значения в CH1/CH2
- **Разнообразие:** Разные соединения → разные GREASE-значения
- **Детерминированность:** Воспроизводимо для отладки

**Алгоритм:** xorshift64* — 3 XOR/shift-операции + мультипликативный скремблер:
```rust
fn next_u32(&mut self) -> u32 {
    self.state ^= self.state >> 12;
    self.state ^= self.state << 25;
    self.state ^= self.state >> 27;
    ((self.state.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 32) as u32
}
```

**Выбор значения:**
```rust
pub(crate) fn get_grease_value(rng: &mut GreaseRng) -> u16 {
    GREASE_VALUES[rng.next_usize(GREASE_VALUES.len())]
}
```

---

## Точки интеграции

### 1. Builder API

В `ClientConfig`:

```rust
pub fn with_fingerprint(
    mut self,
    fingerprint: Arc<dyn crate::client::fingerprint::ClientHelloFingerprinter>,
) -> Self {
    self.state.fingerprint = Some(fingerprint);

    // Добавить SECP521R1 в kx_groups для fingerprinting
    let mut provider = (*self.provider).clone();
    provider
        .kx_groups
        .push(crate::crypto::aws_lc_rs::kx_group::SECP521R1);
    self.provider = Arc::new(provider);

    // Добавить zlib certificate compression
    self.state.cert_compressors = Some(vec![compress::ZLIB_COMPRESSOR]);
    self.state.cert_decompressors = Some(vec![compress::ZLIB_DECOMPRESSOR]);

    self
}
```

Использование:
```rust
let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_fingerprint(Arc::new(SafariFingerprint))
    .with_no_client_auth();
```

**Без `.with_fingerprint()`**:
- `kx_groups` = upstream default (без secp521r1)
- `cert_compressors/decompressors` = пустые (без compress_certificate в CH)
- Поведение идентично `v/0.23.40`

### 2. Применение в Handshake

В `client/hs.rs` (~строка 420), после того как rustls построил дефолтный `ClientHelloPayload`:

```rust
// Apply browser fingerprint if configured.
if let Some(fp) = &config.fingerprint {
    fp.apply(&mut chp_payload, retryreq.is_some());

    // Update ALPN tracking to match what fingerprint actually sent,
    // so ALPN validation against ServerHello uses the correct list.
    if let Some(protocols) = &chp_payload.extensions.protocols {
        input.hello.alpn_protocols = protocols.clone();
    }
}
```

**Фикс ALPN-трекинга:** Без этого rustls валидировал бы выбранный ALPN из ServerHello против изначально сконфигурированного ALPN, а не против модифицированного fingerprint, что приводило к ошибкам согласования.

### 3. Фикс Certificate Extensions (глобальный)

В `msgs/handshake.rs`, `CertificateExtensions::read()` был изменён для игнорирования неизвестных расширений:

```rust
fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
    // ...
    while sub.any_left() {
        out.read_one(&mut sub, |_unk| {
            // Ignore unknown certificate extensions (e.g., SCT)
            Ok(())
        })?;
    }
    Ok(out)
}
```

Это предотвращает ошибки `UnknownCertificateExtension`, когда серверы отправляют Signed Certificate Timestamps (SCT) или другие нестандартные расширения сертификатов.

**Примечание:** Это глобальный bug fix (RFC 8446 §4.2: *"Implementations MUST ignore unrecognized extensions"*), а не fingerprint-специфичное поведение. Работает независимо от `.with_fingerprint()`.

### 4. Сохранение trailing dots в SNI (глобальный)

В `msgs/handshake.rs` изменён `From<&DnsName>` для `ServerNamePayload`:

```rust
impl<'a> From<&DnsName<'a>> for ServerNamePayload<'static> {
    fn from(value: &DnsName<'a>) -> Self {
        // Self::SingleDnsName(trim_hostname_trailing_dot_for_sni(value))
        Self::SingleDnsName(value.to_owned()) // #PATCH: preserve trailing dots
    }
}
```

Стандартный rustls обрезает trailing dot в SNI (RFC6066). Этот патч сохраняет его, что позволяет использовать домены с двойной точкой в конце для обхода блокировок по SNI.

**Примечание:** Это глобальный патч, работает независимо от `.with_fingerprint()`.

---

## Поддержка SECP521R1 (P-521)

Safari's `supported_groups` включает `secp521r1` (тип `0x0019`). В стандартном rustls 0.23.40 P-521 не поддерживается как kx group (только как enum-значение).

**Файл:** `rustls/src/crypto/aws_lc_rs/kx_p521.rs`
```rust
pub static SECP521R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp521r1,
    agreement_algorithm: &agreement::ECDH_P521,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};
```

**Файл:** `rustls/src/crypto/ring/kx.rs`
- `KxGroup` и `uncompressed_point` сделаны `pub(crate)` для использования из aws-lc-rs

**Файл:** `rustls/src/crypto/aws_lc_rs/mod.rs`
- `SECP521R1` экспортирован в `kx_group`
- **Убран** из `DEFAULT_KX_GROUPS` и `ALL_KX_GROUPS` (upstream список без P-521)

**Добавление через `.with_fingerprint()`:**
```rust
let mut provider = (*self.provider).clone();
provider
    .kx_groups
    .push(crate::crypto::aws_lc_rs::kx_group::SECP521R1);
self.provider = Arc::new(provider);
```

Таким образом P-521 доступен **только** при использовании fingerprint, не влияя на стандартное поведение rustls.

---

## Важные детали реализации

### Очистка `session_ticket`

Safari не отправляет расширение session_ticket в своём отпечатке. Мы явно очищаем его:
```rust
exts.session_ticket = None;
```

### `order_seed = 0`

rustls обычно рандомизирует порядок расширений с помощью `order_seed`. Для Safari устанавливаем в 0 и используем `contiguous_extensions` для детерминированного порядка:
```rust
exts.order_seed = 0;
exts.contiguous_extensions.clear();
// ... затем push расширений в точном порядке Safari
```

### Certificate Compression (только с fingerprint)

Расширение `compress_certificate` добавляется в ClientHello **только** при `.with_fingerprint()`:

- `cert_compressors = [ZLIB_COMPRESSOR]`
- `cert_decompressors = [ZLIB_DECOMPRESSOR]`

Без fingerprint оба списка пустые, поэтому расширение не отправляется.

`zlib` остаётся в `default` features (`Cargo.toml`), но decompressor используется только при fingerprint. Это позволяет принимать `CompressedCertificate` от серверов (Facebook, Instagram), не изменяя CH без fingerprint.

### Поведение `collect_used()` vs `encode_one()`

Это **самый тонкий баг**, который мы исправили:

- `collect_used()` итерирует ВСЕ `unknown_extensions` и возвращает их типы
- `encode_one()` находит **первое** совпадение `unknown_extension` по типу и кодирует его

Если два GREASE-расширения имеют одинаковый тип:
1. `collect_used()` → `[..., 0x1A1A, ..., 0x1A1A, ...]` (тип появляется дважды)
2. `encode_one(0x1A1A)` → кодирует первый `UnknownExtension` с пустым payload
3. `encode_one(0x1A1A)` → кодирует ТОТ ЖЕ первый `UnknownExtension` снова (неправильный payload!)

**Фикс:** Гарантировать `grease_ext1 != grease_ext2` через rejection sampling.

---

## Пример использования

```rust
use rustls::{ClientConfig, SafariFingerprint};
use std::sync::Arc;

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_fingerprint(Arc::new(SafariFingerprint))
    .with_no_client_auth();
```

Смотрите `examples/src/bin/safari_fingerprint.rs` для полного рабочего примера.

---

## Тестирование

Проверено на следующих ранее падающих сайтах (все теперь работают стабильно):

| Сайт | Статус | Примечания |
|------|--------|------------|
| example.com | ✅ 10/10 | HTTP/1.1 ALPN |
| rust-lang.org | ✅ 5/5 | Возвращает 0 байт (HTTP/1.1) |
| google.com | ✅ 5/5 | `http2_handshake_failed` (ожидаемо с HTTP/1.1 ALPN) |
| officeci-mauservice.azurewebsites.net | ✅ 5/5 | Azure HRR-сайт |
| appservicelandingpage.trafficmanager.net | ✅ 5/5 | Azure HRR-сайт |

---

## Изменённые файлы

| Файл | Изменение |
|------|-----------|
| `rustls/Cargo.toml` | `zlib` в `default` features (как upstream) |
| `rustls/src/client/fingerprint/mod.rs` | Новое определение трейта `ClientHelloFingerprinter` |
| `rustls/src/client/fingerprint/safari.rs` | Реализация Safari fingerprint |
| `rustls/src/client/fingerprint/grease.rs` | GREASE RNG |
| `rustls/src/client/client_conn.rs` | Добавлено поле `fingerprint` в `ClientConfig` |
| `rustls/src/client/builder.rs` | `with_fingerprint()` — добавляет SECP521R1 + zlib компрессию |
| `rustls/src/client/hs.rs` | Применение fingerprint + фикс ALPN-трекинга |
| `rustls/src/msgs/macros.rs` | Поддержка `unknown_extensions` + проверка duplicate |
| `rustls/src/msgs/handshake.rs` | `UnknownExtension` visibility + `CertificateExtensions::read` ignore unknown + SNI trailing dots |
| `rustls/src/crypto/aws_lc_rs/kx_p521.rs` | Kx group SECP521R1 |
| `rustls/src/crypto/aws_lc_rs/mod.rs` | Экспорт SECP521R1, **убран** из `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` |
| `rustls/src/crypto/ring/kx.rs` | `KxGroup` и `uncompressed_point` сделаны `pub(crate)` |
| `rustls/src/lib.rs` | Экспорт fingerprint модулей |
| `examples/src/bin/safari_fingerprint.rs` | Пример-бинарник |
