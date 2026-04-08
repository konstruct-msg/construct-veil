# Roadmap — улучшения construct-ice

## 1. tonic/hyper интеграция

**Статус:** planned  
**Приоритет:** высокий

`Obfs4Stream` уже реализует `AsyncRead + AsyncWrite`, но нет готового `Connect` trait для tonic. Это позволит использовать obfs4 с gRPC "из коробки".

**Что нужно:**
- Реализовать `tonic::transport::Connect` для obfs4
- Добавить wrapper `Obfs4Channel` для удобного создания gRPC каналов
- Пример в `examples/` с полным gRPC клиентом и сервером
- Тесты: gRPC request/response через obfs4 транспорт

**Затронутые файлы:** новые `src/transport/tonic.rs`, `examples/grpc_*`

---

## 2. TLS wrapper (feature flag есть, код частично есть)

**Статус:** частично реализовано (в FFI)  
**Приоритет:** высокий

В `Cargo.toml` есть `tls` и `ffi-tls` фичи. В `ffi.rs` есть `ice_proxy_start_tls`, но нет публичного API для пользователей библиотеки (не-FFI).

**Что нужно:**
- Публичный `TlsObfs4Stream` или метод `Obfs4Stream::connect_tls()`
- Пример TLS-over-obfs4 в `examples/`
- Документация: когда использовать plain obfs4, когда TLS-over-obfs4

**Затронутые файлы:** `src/transport/mod.rs`, новые примеры

---

## 3. Метрики и логирование

**Статус:** не реализовано  
**Приоритет:** средний

Нет метрик для production мониторинга.

**Что нужно:**
- Интеграция с `tracing` для структурированного логирования
- Счётчики: handshake duration, replay rejections, frame sizes, IAT overhead
- Опциональный `metrics` feature flag (чтобы не тянуть deps для мобильных)
- Совместимость с Prometheus/OpenTelemetry

**Затронутые файлы:** практически все модули

---

## 4. Бенчмарки

**Статус:** только `benches/framing.rs`  
**Приоритет:** средний

**Что нужно:**
- Бенчмарк handshake (client + server)
- Бенчмарк IAT overhead (None vs Enabled vs Paranoid)
- Бенчмарк пропускной способности (throughput)
- Бенчмарк latency (p50, p95, p99)
- Сравнение с Go-реализацией

**Затронутые файлы:** `benches/handshake.rs`, `benches/throughput.rs`, `benches/iat_overhead.rs`

---

## 5. Документация

**Статус:** базовая  
**Приоритет:** средний

Много модулей без публичной документации.

**Что нужно:**
- Doc-строки для всех публичных типов и функций
- Примеры кода в doc-строках (`/// # Examples`)
- Architecture Decision Records (почему выбраны именно эти алгоритмы, почему Randomized variant Elligator2)
- Threat model документ (что защищает, что нет)
- Guide для новичков (как работает obfs4 пошагово)

**Затронутые файлы:** все публичные модули

---

## 6. ReplayFilter — защита от утечки памяти

**Статус:** уязвимость  
**Приоритет:** высокий

`ReplayFilter` хранит все MAC'и в `HashSet` без лимита. При атаке можно забить память, отправляя уникальные MAC'и.

**Что нужно:**
- Max capacity с LRU eviction или Bloom filter
- Метрика: количество отброшенных записей при переполнении
- Тест: memory limit under attack

**Затронутые файлы:** `src/replay_filter.rs`

---

## 7. Обработка ошибок

**Статус:** теряется типизация  
**Приоритет:** низкий

В `transport/mod.rs` ошибки маппятся в `io::Error::new(InvalidData, ...)` — теряется информация о типе ошибки.

**Что нужно:**
- `impl From<Error> for io::Error` с разными `io::ErrorKind`:
  - `FrameMacMismatch` → `io::ErrorKind::InvalidData`
  - `HandshakeTimeout` → `io::ErrorKind::TimedOut`
  - `NtorAuthMismatch` → `io::ErrorKind::PermissionDenied`
  - `UnexpectedEof` → `io::ErrorKind::UnexpectedEof`
- Пользователи смогут различать ошибки без парсинга строк

**Затронутые файлы:** `src/error.rs`, `src/transport/mod.rs`

---

## 8. Fuzz-тесты

**Статус:** не реализовано  
**Приоритет:** высокий

Критично для криптографического кода — fuzzing находит edge cases, которые не покрывают unit-тесты.

**Что нужно:**
- `cargo fuzz` для парсинга handshake (client + server)
- Fuzz frame decoder (malformed frames, truncated data, invalid MAC)
- Fuzz bridge line parser
- Fuzz Elligator2 encode/decode
- CI: запуск fuzzers на nightly (например, 1 час на fuzz target)

**Затронутые файлы:** `fuzz/` директория, CI workflow

---

## 9. Zero-copy оптимизации

**Статус:** не реализовано  
**Приоритет:** низкий

`poll_read` копирует данные через `BytesMut`. Можно оптимизировать.

**Что нужно:**
- Использовать `bytes::Bytes` напрямую для zero-copy чтения
- `read_buf: VecDeque<Bytes>` вместо `BytesMut`
- Бенчмарк до/после для подтверждения улучшения

**Затронутые файлы:** `src/transport/mod.rs`, `src/framing/decoder.rs`

---

## 10. iOS FFI — тесты и CI

**Статус:** код есть, тестов нет  
**Приоритет:** средний

`ffi.rs` существует, но нет тестов против реального Swift-кода и нет CI для iOS-сборки.

**Что нужно:**
- Swift-тесты (в `examples/` или отдельной директории)
- CI: сборка для `aarch64-apple-ios` и `aarch64-apple-ios-sim`
- Тест: proxy start → connect → send → receive → stop
- Документация: как интегрировать в Xcode проект

**Затронутые файлы:** CI workflow, `examples/swift_test/`

---

## 11. Конфигурация PaddingStrategy

**Статус:** частично  
**Приоритет:** низкий

`PaddingStrategy` есть, но нет гибкой настройки.

**Что нужно:**
- `PaddingStrategy::Fixed(usize)` — фиксированный размер
- `PaddingStrategy::RandomRange { min, max }` — случайный в диапазоне
- Бенчмарк влияния padding на throughput

**Затронутые файлы:** `src/framing/encoder.rs`

---

## 12. Graceful shutdown

**Статус:** не реализовано  
**Приоритет:** низкий

`Obfs4Stream` не отправляет graceful close — просто закрывает TCP.

**Что нужно:**
- Метод `shutdown()` с отправкой empty frame (signal peer)
- Корректная обработка EOF от peer
- Тест: graceful close не теряет данные

**Затронутые файлы:** `src/transport/mod.rs`

---

## Приоритизация

| # | Задача | Приоритет | Сложность | Зависимости |
|---|--------|-----------|-----------|-------------|
| 6 | ReplayFilter memory leak | высокий | низкая | — |
| 1 | tonic/hyper интеграция | высокий | средняя | — |
| 2 | TLS wrapper API | высокий | средняя | — |
| 8 | Fuzz-тесты | высокий | высокая | — |
| 4 | Бенчмарки | средний | низкая | — |
| 3 | Метрики и логирование | средний | средняя | — |
| 5 | Документация | средний | средняя | — |
| 10 | iOS FFI тесты | средний | средняя | 2 |
| 7 | Обработка ошибок | низкий | низкая | — |
| 9 | Zero-copy | низкий | средняя | — |
| 11 | PaddingStrategy | низкий | низкая | — |
| 12 | Graceful shutdown | низкий | низкая | — |

---

## 13. TLS fingerprint mimicry (uTLS) ← NEW

**Статус:** planned  
**Приоритет:** критический

ТСПУ (Россия) и GFW (Китай) классифицируют трафик по TLS ClientHello fingerprint. Стандартный `native-tls`/`rustls` ClientHello отличается от браузерных — это надёжный сигнал для DPI.

**Что нужно:**
- `TlsFingerprint` enum: `Chrome120`, `Firefox121`, `Safari17`, `Random`
- Кастомный `rustls::ClientConfig` с cipher suites, extensions, curves в порядке реального браузера
- Включается через `ClientConfig::with_tls_fingerprint(fingerprint)`
- Тесты: сравнить wire bytes ClientHello с эталонными значениями (JA3 hash)

**Затронутые файлы:** `src/transport/mod.rs`, `src/transport/tls_fingerprint.rs` (новый), `Cargo.toml` (добавить `rustls` как альтернативу `native-tls` под feature flag)

---

## 14. Domain fronting / CDN camouflage ← NEW

**Статус:** planned  
**Приоритет:** высокий

obfs4 подключается к relay IP напрямую — ТСПУ блокирует по IP-адресу. Domain fronting через Cloudflare скрывает реальный destination: DPI видит `CONNECT cdn-edge.cloudflare.com`, а не relay IP.

**Что нужно:**
- `DomainFrontedConfig`: `cdn_host`, `origin_host`, feature flag `cdn-fronting`
- `Obfs4Stream::connect_fronted(cdn_host, origin_host, config)` — HTTPS CONNECT → CDN → relay → obfs4
- Пример в `examples/fronted_client.rs`
- Документация: настройка Cloudflare Workers/Fastly для forwarding

**Зависимость:** #13 TLS fingerprint mimicry (CDN требует правдоподобного TLS ClientHello)

---

## 15. Active probing resistance tests ← NEW

**Статус:** planned  
**Приоритет:** высокий

obfs4 имеет anti-probing защиту, но нет автоматических тестов имитирующих GFW/ТСПУ probing patterns.

**Что нужно:**
- `tests/probing.rs` test suite:
  - probe с неверным cert → timeout/garbage, не TCP RST
  - probe с верным cert но неверным MAC → non-deterministic timing
  - sequential probes → разные response timings (не fingerprint-able)
  - HTTP GET probe → binary garbage в ответ
- CI: запускать в каждом PR (быстрые, < 30s)

**Затронутые файлы:** `tests/probing.rs` (новый)

---

## 16. Pluggable transport multiplexing ← NEW

**Статус:** planned  
**Приоритет:** средний

ТСПУ адаптируется — сегодня obfs4 работает, завтра может быть заблокирован. Нужна архитектура fallback без изменения клиентского кода.

**Что нужно:**
- `TransportKind` enum: `Obfs4`, `WebSocket`, `Meek`, `Quic`
- `TransportDialer` trait: `async fn dial(addr, config) -> Box<dyn AsyncRead + AsyncWrite>`
- `IceClient` с priority list + automatic fallback
- `ice_proxy_start` получает опциональный `transport_kind` параметр
- Начать с WebSocket (наименее блокируемый через CDN)

**Зависимость:** #7 улучшенная типизация ошибок (для правильного fallback)

---

## 17. Traffic analysis resistance — constant-rate channel ← NEW

**Статус:** planned  
**Приоритет:** средний

IAT modes существуют, но нет padding на уровне сессии. Объём трафика + паттерн отправки выдают мессенджер vs web-browsing даже при IAT=Paranoid.

**Что нужно:**
- PADDING frames когда нет реальных данных → constant bitrate (configurable `target_kbps`)
- Опционально — `PaddingStrategy::ConstantRate { kbps: u32 }` в `IATMode::Paranoid`
- Feature flag `session-padding` (чтобы не дренировать батарею на мобиле)
- Бенчмарк: entropy до/после на реальном трафике

**Зависимость:** #16 multiplexing (padding должен применяться поверх любого transport)

---

## Приоритизация (обновлено)

| # | Задача | Приоритет | Статус |
|---|--------|-----------|--------|
| iOS CI | iOS FFI CI + UDL gate | критический | planned |
| 15 | Active probing tests | высокий | planned |
| 13 | TLS fingerprint mimicry | высокий | planned |
| 8 | Fuzz-тесты | высокий | planned |
| 14 | Domain fronting | высокий | planned |
| 7 | Error typing | средний | planned |
| 16 | PT multiplexing | средний | planned |
| 17 | Session padding | средний | planned |
| 3 | Метрики/tracing | средний | planned |
| 4 | Бенчмарки | средний | planned |
| 5 | Документация | средний | planned |
| 6 | ReplayFilter | **done** ✅ | — |
| 1 | tonic интеграция | **done** ✅ | — |
| 2 | TLS wrapper API | **done** ✅ | — |
