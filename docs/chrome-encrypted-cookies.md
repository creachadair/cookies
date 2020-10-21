# Google Chrome Encrypted Cookies

Google Chrome stores browser cookies in an SQLite database.  The database has two tables, `meta` containing format and version metadata, and `cookies` with the contents of the cookies. The `cookies` table uses this schema:

```sql
-- To reproduce: sqlite path/to/Cookies .schema
CREATE TABLE cookies (
   creation_utc     INTEGER  NOT NULL,  -- microseconds since epoch
   host_key         TEXT     NOT NULL,  -- domain
   name             TEXT     NOT NULL,
   value            TEXT     NOT NULL,
   path             TEXT     NOT NULL,
   expires_utc      INTEGER  NOT NULL,  -- microseconds since epoch
   is_secure        INTEGER  NOT NULL,
   is_httponly      INTEGER  NOT NULL,
   last_access_utc  INTEGER  NOT NULL,
   has_expires      INTEGER  NOT NULL DEFAULT  1,
   is_persistent    INTEGER  NOT NULL DEFAULT  1,
   priority         INTEGER  NOT NULL DEFAULT  1,
   encrypted_value  BLOB              DEFAULT '',
   samesite         INTEGER  NOT NULL DEFAULT  -1,
   source_scheme    INTEGER  NOT NULL DEFAULT  0,

   -- samesite values, from Chromium cookies/cookie_constants.h
   --   UNSPECIFIED    = -1
   --   NO_RESTRICTION = 0    "None"
   --   LAX_MODE       = 1    "Lax"
   --   STRICT_MODE    = 2    "Strict"

   UNIQUE (host_key, name, path)
);
```

## Timestamps

The `expires_utc` and `creation_utc` fields contain timestamps given as integer numbers of microseconds elapsed since midnight 01-Jan-1601 UTC in the proleptic calendar. The Unix epoch is 11644473600 seconds after this moment.

## Values

The `value` and `encrypted_value` fields are used to store cookie values. In practice, one or the other is populated, but not both.

| `value`   | `encrypted_value` | Description                        |
| --------- | ----------------- | ---------------------------------- |
| empty     | non-empty         | Encrypted value                    |
| non-empty | empty             | Non-zero length value, unencrypted |
| empty     | empty             | Zero-length value, unencrypted     |
| non-empty | non-empty         | (not observed)                     |

## Storage Format

An encrypted value consists of a data packet that is encrypted with AES-128 in CBC mode. The encrypted data packet has the following format:

| Bytes | Content                | Description                     |
| ----- | ---------------------- | ------------------------------- |
| 3     | "v10" (0x76 0x31 0x30) | Version tag (unencrypted)       |
| n     | value                  | Payload (encrypted)             |
| p     | padding                | Padding (encrypted), 1–16 bytes |

The encrypted portion of the packet (n+ p) contains a multiple of 16 bytes. If n is a multiple of 16, p = 16; otherwise 1 ≤ p ≤ 15.

### Padding

Before encryption, p bytes of padding are added to the plaintext value to ensure a multiple of 16 bytes. At least one byte of padding is always added, so if the value is already a multiple of 16 bytes, p=16 additional are added. Each padding byte has the value p, so if p=5, the padding is the 5-byte sequence [5, 5, 5, 5, 5].

After decryption, the padding must be removed, and it can be used to verify that the decryption key was correct. The final byte of the decrypted packet must be a padding byte with value 1 ≤ p ≤ 16, and the last p bytes of the packet must contain the value p. Otherwise, the decryption key can be assumed to be incorrect.

### Encryption

Encryption and decryption are performed using AES-128 in cipher-block chaining (CBC) mode with an initialization vector consisting of 16 space bytes (Unicode 32). The encryption key is described below.

## Key Generation

The 16-byte AES-128 encryption key is generated using the [PBKDF2 (RFC 2898)](https://tools.ietf.org/html/rfc2898) algorithm from a user-provided passphrase. The key generation salt is the fixed string `saltysalt`. On macOS, Chrome uses 1003 iterations of the key generation algorithm; on Linux it uses 1 iteration. I don't know what it does on Windows.
