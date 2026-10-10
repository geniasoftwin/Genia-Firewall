# Code signing policy / Политика подписи

## Current status (English)

0.7.4 RC builds are **testing artifacts**, not a signed Stable release by default. A public 0.7.4 Stable promotion requires successful CI/CodeQL, Windows 10/11 compatibility testing, and Authenticode signing of both the privileged service and the UI. The planned signing path is through SignPath Foundation, subject to enrollment and approval.

Proposed signed single-EXE flow: build reviewed service → sign service → embed signed payload in UI → sign UI → verify both signatures/timestamps → publish SHA-256 **after signing**.

A SHA-256 checksum establishes consistency against a published hash, **not the identity of the publisher**. Signing secrets and private keys must never be committed.

## Текущий статус (Русский)

0.7.4 RC — **тестовые артефакты**, а не гарантированно подписанный Stable. Для 0.7.4 Stable нужны зелёные CI/CodeQL, тесты на Windows 10/11 и Authenticode-подпись **службы и UI**. Планируемый путь — SignPath Foundation после допуска проекта.

Предполагаемая последовательность для single-EXE: сборка проверенной службы → подпись службы → встраивание в UI → подпись UI → проверка обеих подписей/временных меток → публикация SHA-256 **после подписи**.

SHA-256 подтверждает соответствие опубликованному хешу, **но не личность издателя**. Приватные ключи и signing secrets не должны попадать в репозиторий.
