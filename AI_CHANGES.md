# AI Changes

This file tracks changes made to this repository by an AI assistant.

## 2026-07-27 — claude-sonnet-5 (Claude Code)

Follow-up fixes from a code review of `crypto_extra.cc`.

- **`crypto_extra.cc`**: `get_cipher()` now rejects AEAD ciphers (e.g.
  `aes-256-gcm`, `chacha20-poly1305`) by checking
  `EVP_CIPHER_flags() & EVP_CIPH_FLAG_AEAD_CIPHER`. `Item_func_raw_cipher`
  never manages an authentication tag (no `EVP_CTRL_GET_TAG`/`SET_TAG`), so
  previously an AEAD cipher name would silently produce ciphertext missing
  its tag on encrypt, and would fail to decrypt. `CRYPTO_ENCRYPT`/
  `CRYPTO_DECRYPT` (and the `_IV` variants) now return `NULL` for such
  cipher names instead.
- **`crypto_extra.cc`**: Removed the redundant `parameters_end == 0` check
  in `Item_func_argon2id_verify::val_bool` — the preceding
  `sscanf(...) != 4` check already guarantees the trailing `%n` fired, and
  `parameters_end` was otherwise unused. Dropped the `%n` specifier and the
  variable entirely.
- **`crypto_extra.cc`**: Added a comment on
  `Item_func_argon2id_hash::fix_length_and_dec` explaining the derivation
  of the `max_length = 256` constant (worst case PHC string at the
  documented caps is ~150 bytes).
- **`README.md`**: Documented that the Argon2id override caps (256 MiB /
  16 lanes / 10 iterations) are memory- and CPU-hard and that `EXECUTE`
  on `ARGON2ID_HASH`/`ARGON2ID_VERIFY` should be restricted in
  multi-tenant deployments. Documented that AEAD ciphers are rejected by
  `CRYPTO_ENCRYPT`/`CRYPTO_DECRYPT`.
- **`mysql-test/crypto_extra/basic.test`** / **`basic.result`**: Added a
  test case asserting `CRYPTO_ENCRYPT(..., 'aes-256-gcm')` returns `NULL`.
