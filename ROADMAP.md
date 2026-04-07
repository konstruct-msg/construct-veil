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
