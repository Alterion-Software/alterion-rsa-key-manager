<div align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
        <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
        <img alt="Alterion Logo" src="assets/logo-dark.png" width="400">
    </picture>
</div>

<div align="center">

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/alterion-ecdh.svg)](https://crates.io/crates/alterion-ecdh)
[![Rust](https://img.shields.io/badge/Rust-2024-orange?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![X25519](https://img.shields.io/badge/X25519-ECDH-blue?style=flat)](https://docs.rs/x25519-dalek)
[![GitHub](https://img.shields.io/badge/GitHub-Alterion--Software-181717?style=flat&logo=github&logoColor=white)](https://github.com/Alterion-Software)
[![Socket Badge](https://badge.socket.dev/cargo/package/alterion-ecdh/0.3.0)](https://badge.socket.dev/cargo/package/alterion-ecdh/0.3.0)

_X25519 ECDH key store with timed rotation, a 300-second grace window, and HKDF-SHA256 session key derivation — designed as the key exchange layer for the [alterion-encrypt](https://crates.io/crates/alterion-encrypt)._

---

</div>

## What it does

Manages a live X25519 key pair that rotates automatically on a configurable interval. A 300-second grace window keeps the previous key valid after rotation so any in-flight request sent just before a rotation still completes successfully.

```
┌─────────────────────────────────────────────┐
│                  KeyStore                    │
│  current  ──→  active X25519 key pair        │
│  previous ──→  retiring key (≤300s grace)    │
└─────────────────────────────────────────────┘
```

On each request the client performs X25519 ECDH with the server's current public key. The resulting shared secret is passed to HKDF-SHA256 to derive separate `enc_key` and `mac_key` — both parties derive identical keys without ever transmitting them.

---

## Quick start

### 1. Add the dependency

```toml
[dependencies]
alterion-ecdh = "0.1"
```

### 2. Initialise and rotate

```rust
use alterion_ecdh::{init_key_store, start_rotation};

#[tokio::main]
async fn main() {
    // Rotate every hour; previous key stays live for 5 minutes.
    let store = init_key_store(3600);
    start_rotation(store.clone(), 3600);

    // pass `store` into your application state
}
```

### 3. Expose the public key to clients

```rust
use actix_web::{get, web, HttpResponse};
use alterion_ecdh::{KeyStore, get_current_public_key};
use std::sync::Arc;
use tokio::sync::RwLock;

#[get("/api/pubkey")]
async fn public_key_handler(
    store: web::Data<Arc<RwLock<KeyStore>>>,
) -> HttpResponse {
    let (key_id, public_key_b64) = get_current_public_key(&store).await;
    HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": public_key_b64 }))
}
```

The `public_key` field is a base64-encoded 32-byte X25519 public key. The client uses it to generate an ephemeral key pair and perform ECDH.

### 4. Perform ECDH on an incoming request

```rust
use alterion_ecdh::ecdh;

// client_pk is the 32-byte ephemeral X25519 public key sent by the client
let (shared_secret, server_pk) = ecdh(&store, &key_id, &client_pk).await?;
// Pass shared_secret + both public keys to HKDF to derive enc_key and mac_key
```

`shared_secret` is `Zeroizing<[u8; 32]>` — memory is wiped on drop.

---

## API

| Function | Description |
|---|---|
| `init_key_store(interval_secs)` | Generates the initial X25519 key pair, returns `Arc<RwLock<KeyStore>>` |
| `start_rotation(store, interval_secs)` | Spawns a background task that rotates the key every `interval_secs` seconds |
| `get_current_public_key(store)` | Returns `(key_id, base64_public_key)` for the active key |
| `ecdh(store, key_id, client_pk)` | Performs X25519 ECDH, returns `(Zeroizing<[u8; 32]>, [u8; 32])` — shared secret and server public key bytes |

### `EcdhError`

| Variant | Meaning |
|---|---|
| `KeyExpired` | The `key_id` is unknown or its grace window has closed |
| `InvalidPublicKey` | The client's public key is not a valid 32-byte X25519 point |

---

## Grace window

The previous key remains valid for **300 seconds** after rotation. Pre-fetch a new public key on the client at `rotation_interval − 300` seconds to ensure the cached key is never stale when a rotation occurs.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Open an issue before writing any code.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

<div align="center">

**Made with ❤️ by the Alterion Software team**

[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.com/invite/3gy9gJyJY8)
[![Website](https://img.shields.io/badge/Website-Coming%20Soon-blue?style=flat&logo=globe&logoColor=white)](.)
[![GitHub](https://img.shields.io/badge/GitHub-Alterion--Software-181717?style=flat&logo=github&logoColor=white)](https://github.com/Alterion-Software)

</div>
