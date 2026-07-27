# mariadb-plugin-crypto-extra

![mariabd-plugin-crypto-extra](logo/crypto_extra.png)

`crypto_extra` is a MariaDB Server function plugin providing cryptographic
functions that are available in PostgreSQL's `pgcrypto`, together with a few
modern utility primitives. It complements rather than replaces MariaDB's
MySQL-compatible `MD5()`, `SHA1()`, `SHA2()`, `AES_ENCRYPT()`,
`AES_DECRYPT()`, and `RANDOM_BYTES()`.

## Functions

All byte-oriented functions return binary strings and accept arbitrary binary
input.

| Function | Result |
|---|---|
| `DIGEST(data, algorithm)` | Raw message digest |
| `HMAC(data, key, algorithm)` | Raw keyed message authentication code |
| `PBKDF2_HMAC(password, salt, iterations, length, algorithm)` | Derived key |
| `GEN_RANDOM_BYTES(length)` | Cryptographically secure random bytes |
| `RANDOM_BYTES_HEX(length)` | Secure random bytes as uppercase hexadecimal |
| `ARGON2ID_HASH(password [, memory_kib [, iterations [, parallelism [, hash_length]]]])` | Argon2id PHC password hash |
| `ARGON2ID_VERIFY(password, encoded_hash)` | Verify an Argon2id PHC password hash |
| `CRYPTO_EQUALS(left, right)` | Constant-time equality for equal-length values |
| `CRYPTO_ENCRYPT(data, key, cipher)` | PostgreSQL-style raw symmetric encryption |
| `CRYPTO_DECRYPT(data, key, cipher)` | PostgreSQL-style raw symmetric decryption |
| `CRYPTO_ENCRYPT_IV(data, key, cipher, iv)` | Raw encryption with an explicit IV |
| `CRYPTO_DECRYPT_IV(data, key, cipher, iv)` | Raw decryption with an explicit IV |

Algorithms are supplied by the OpenSSL provider configured for MariaDB.
Common digest names include `md5`, `sha1`, `sha224`, `sha256`, `sha384`,
`sha512`, `sha3-256`, `sha3-512`, `blake2b512`, and `blake2s256`. Common
cipher names include `aes-128-cbc`, `aes-192-cbc`, and `aes-256-cbc`.
`aes` is accepted as an alias for `aes-128-cbc`. Underscores and hyphens are
interchangeable in algorithm names. PostgreSQL's `/pad:pkcs` and `/pad:none`
cipher suffixes are supported.

The key must have exactly the size required by the selected cipher. IVs must
also have exactly the cipher's IV size. The three-argument forms use an
all-zero IV for PostgreSQL compatibility. New applications should normally
prefer authenticated encryption at the application layer; raw CBC encryption
does not authenticate ciphertext.

Limits: random and derived outputs are at most 1 MiB, and PBKDF2 is limited to
10 million iterations. Argon2id defaults to 64 MiB, three iterations, one
lane, and a 32-byte hash. Overrides are limited to 256 MiB, ten iterations,
16 lanes, and a 16-to-64-byte hash. Every hash receives a fresh 16-byte salt.
Verification rejects PHC strings whose memory, iteration, or lane parameters
exceed those limits before invoking libargon2.

The upper end of the Argon2id override range (256 MiB, 16 lanes, 10
iterations) is intentionally memory- and CPU-hard. Any user with `EXECUTE` on
`ARGON2ID_HASH`/`ARGON2ID_VERIFY` can request the maximum on every call;
concurrent callers doing so can pressure server memory and CPU. Restrict
`EXECUTE` on these functions in multi-tenant deployments if that is a
concern.

`CRYPTO_ENCRYPT`/`CRYPTO_DECRYPT` (and their `_IV` variants) reject AEAD
ciphers (e.g. `aes-256-gcm`, `chacha20-poly1305`): the functions only ever
run `EVP_*Update`/`EVP_*Final` and never manage an authentication tag, so an
AEAD cipher's tag would silently be dropped on encryption, making the
ciphertext undecryptable. Use a CBC or ECB-style cipher name instead.

## Comparison with PostgreSQL and MySQL

`crypto_extra`'s function names and argument order deliberately mirror
PostgreSQL's `pgcrypto`, so most `pgcrypto` SQL ports over by just dropping
the schema qualification and upper-casing the function name.

| Capability | `crypto_extra` (this plugin) | PostgreSQL `pgcrypto` | MySQL / MariaDB built-in |
|---|---|---|---|
| Message digest | `DIGEST(data, algo)` — any OpenSSL digest | `digest(data, type)` | `MD5()`, `SHA1()`, `SHA2()` — fixed algorithm set |
| HMAC | `HMAC(data, key, algo)` | `hmac(data, key, type)` | not available |
| PBKDF2 key derivation | `PBKDF2_HMAC(password, salt, iter, len, algo)` | not built in (composed by hand from `hmac()`) | not available |
| Password hashing | `ARGON2ID_HASH()` / `ARGON2ID_VERIFY()` (Argon2id, memory-hard) | `crypt()` / `gen_salt()` (bcrypt `bf`, `md5`, `des`, `xdes` — no Argon2) | not available |
| Secure random bytes | `GEN_RANDOM_BYTES()`, `RANDOM_BYTES_HEX()` | `gen_random_bytes()`, `gen_random_uuid()` | `RANDOM_BYTES()` |
| Constant-time comparison | `CRYPTO_EQUALS()` | not available | not available |
| Raw symmetric encryption | `CRYPTO_ENCRYPT()`/`CRYPTO_DECRYPT()` (+ `_IV` forms) | `encrypt()`/`decrypt()` (+ `_iv` forms) | `AES_ENCRYPT()`/`AES_DECRYPT()` |
| OpenPGP-style encryption | not provided | `pgp_sym_encrypt()`/`pgp_pub_encrypt()` etc. | not available |

Notes:

- **Algorithm coverage.** Like `pgcrypto`, `crypto_extra` delegates digest
  and cipher selection to OpenSSL, so both support anything the linked
  OpenSSL provider offers (`sha3-256`, `blake2b512`, ...). MySQL/MariaDB's
  `SHA2()` and `AES_ENCRYPT()` only implement a small, hardcoded set of
  algorithms and cannot be extended without a server rebuild.
- **Cipher mode and padding.** MySQL/MariaDB's `AES_ENCRYPT()` historically
  defaulted to ECB, with mode selected server-wide via
  `block_encryption_mode`. `crypto_extra` and `pgcrypto` instead encode the
  mode in the algorithm string per call (e.g. `aes-256-cbc`) and default to
  CBC, matching `pgcrypto`'s `/pad:pkcs` / `/pad:none` suffix convention.
  None of the three expose AEAD ciphers through their raw-encryption
  functions — `crypto_extra` rejects AEAD cipher names outright (see
  above), and `pgcrypto`'s `encrypt()`/`decrypt()` are documented as
  supporting only `bf` and `aes` in CBC mode.
- **Password hashing.** `crypto_extra` is the only one of the three with a
  modern, memory-hard KDF (Argon2id) intended for password storage.
  `pgcrypto`'s `crypt()` offers bcrypt, which is CPU-hard but not
  memory-hard. MySQL/MariaDB have no built-in SQL function for password
  hashing at all — that's handled by authentication plugins, not by SQL.
- **Constant-time comparison.** Neither `pgcrypto` nor MySQL/MariaDB expose
  a constant-time equality function; comparing MACs or tokens with `=`
  risks a timing side-channel. `CRYPTO_EQUALS()` fills that gap.
- **OpenPGP.** `pgcrypto` additionally provides `pgp_sym_encrypt()` /
  `pgp_pub_encrypt()` and their counterparts for OpenPGP-format messages;
  `crypto_extra` has no equivalent — use `CRYPTO_ENCRYPT()` for raw
  symmetric encryption instead.

## Examples

```sql
SELECT HEX(DIGEST('abc', 'sha256'));
SELECT HEX(HMAC('what do ya want for nothing?', 'Jefe', 'sha256'));
SELECT HEX(PBKDF2_HMAC('password', 'salt', 1, 32, 'sha256'));
SET @password_hash= ARGON2ID_HASH('correct horse battery staple');
SELECT ARGON2ID_VERIFY('correct horse battery staple', @password_hash);
SELECT RANDOM_BYTES_HEX(16);

SET @key= UNHEX('000102030405060708090A0B0C0D0E0F');
SET @iv = UNHEX('101112131415161718191A1B1C1D1E1F');
SET @ciphertext= CRYPTO_ENCRYPT_IV('secret', @key, 'aes-128-cbc', @iv);
SELECT CONVERT(CRYPTO_DECRYPT_IV(@ciphertext, @key, 'aes-128-cbc', @iv) USING utf8mb4);
```

Build this directory as `plugin/crypto_extra` in a MariaDB Server source tree,
with OpenSSL and libargon2 development files available, then install the
generated plugin:

```sql
INSTALL SONAME 'crypto_extra';

SELECT plugin_name, plugin_type, plugin_library, plugin_description, plugin_author i
FROM information_schema.PLUGINS WHERE plugin_library LIKE 'crypto_extra.so';
+-------------------+-------------+-----------------+------------------------------+---------------+
| plugin_name       | plugin_type | plugin_library  | plugin_description           | plugin_author |
+-------------------+-------------+-----------------+------------------------------+---------------+
| digest            | FUNCTION    | crypto_extra.so | Function DIGEST()            | lefred        |
| hmac              | FUNCTION    | crypto_extra.so | Function HMAC()              | lefred        |
| pbkdf2_hmac       | FUNCTION    | crypto_extra.so | Function PBKDF2_HMAC()       | lefred        |
| gen_random_bytes  | FUNCTION    | crypto_extra.so | Function GEN_RANDOM_BYTES()  | lefred        |
| random_bytes_hex  | FUNCTION    | crypto_extra.so | Function RANDOM_BYTES_HEX()  | lefred        |
| argon2id_hash     | FUNCTION    | crypto_extra.so | Function ARGON2ID_HASH()     | lefred        |
| argon2id_verify   | FUNCTION    | crypto_extra.so | Function ARGON2ID_VERIFY()   | lefred        |
| crypto_equals     | FUNCTION    | crypto_extra.so | Function CRYPTO_EQUALS()     | lefred        |
| crypto_encrypt    | FUNCTION    | crypto_extra.so | Function CRYPTO_ENCRYPT()    | lefred        |
| crypto_decrypt    | FUNCTION    | crypto_extra.so | Function CRYPTO_DECRYPT()    | lefred        |
| crypto_encrypt_iv | FUNCTION    | crypto_extra.so | Function CRYPTO_ENCRYPT_IV() | lefred        |
| crypto_decrypt_iv | FUNCTION    | crypto_extra.so | Function CRYPTO_DECRYPT_IV() | lefred        |
+-------------------+-------------+-----------------+------------------------------+---------------+
12 rows in set (0.002 sec)
```

With MariaDB's bundled TLS library the plugin is linked statically and enabled
as part of the server build.
