// SPDX-License-Identifier: GPL-3.0
use std::sync::Arc;
use rand_core::OsRng;
use tokio::sync::RwLock;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;
use dashmap::DashMap;

pub struct KeyEntry {
    pub key_id:         String,
    pub public_key_b64: String,
    pub public_key_raw: [u8; 32],
    pub secret:         StaticSecret,
    pub created_at:     DateTime<Utc>,
    pub expires_at:     DateTime<Utc>,
}

pub struct KeyStore {
    pub current:  KeyEntry,
    pub previous: Option<KeyEntry>,
    /// Pre-warmed entry generated `KEY_WARM_LEAD_SECS` before the next rotation.
    /// The rotation tick consumes this instead of generating a new key on the hot path.
    pub next:     Option<KeyEntry>,
}

/// A single-use ephemeral server key pair created by [`init_handshake`].
/// Consumed and removed by the first [`ecdh`] call that references its ID.
struct HandshakeEntry {
    secret:     StaticSecret,
    public_raw: [u8; 32],
    expires_at: DateTime<Utc>,
}

/// Thread-safe store of pending ephemeral handshake entries, keyed by handshake ID.
///
/// Separate from [`KeyStore`] so that handshake writes (use-once removals) never contend
/// with the read-heavy static key lock.
#[derive(Clone)]
pub struct HandshakeStore(Arc<DashMap<String, HandshakeEntry>>);

#[derive(Debug, thiserror::Error)]
pub enum EcdhError {
    #[error("key_expired")]
    KeyExpired,
    #[error("invalid client public key")]
    InvalidClientKey,
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),
}

const KEY_GRACE_SECS:       u64 = 300;
const KEY_WARM_LEAD_SECS:   u64 = 600;
const HANDSHAKE_TTL_SECS:   i64 = 60;

fn generate_entry(interval_secs: u64) -> KeyEntry {
    let secret     = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret);
    let raw        = *public_key.as_bytes();
    let now        = Utc::now();
    let secs       = i64::try_from(interval_secs + KEY_GRACE_SECS)
        .expect("interval overflow");
    KeyEntry {
        key_id:         Uuid::new_v4().to_string(),
        public_key_b64: B64.encode(raw),
        public_key_raw: raw,
        secret,
        created_at:     now,
        expires_at:     now + Duration::seconds(secs),
    }
}

/// Generates an initial X25519 key pair and wraps it in a shared, RwLock-guarded `KeyStore`.
pub fn init_key_store(interval_secs: u64) -> Arc<RwLock<KeyStore>> {
    Arc::new(RwLock::new(KeyStore {
        current:  generate_entry(interval_secs),
        previous: None,
        next:     None,
    }))
}

/// Creates an empty `HandshakeStore`. Call once at startup and share the handle across all workers.
pub fn init_handshake_store() -> HandshakeStore {
    HandshakeStore(Arc::new(DashMap::new()))
}

/// Generates a fresh ephemeral X25519 key pair, stores the private key in `hs` with a 60-second
/// TTL, and returns `(handshake_id, base64_public_key)`.
///
/// The private key is consumed and deleted on the first matching [`ecdh_ephemeral`] call.
/// Any entry not consumed within `HANDSHAKE_TTL_SECS` is pruned by [`prune_handshakes`].
pub fn init_handshake(hs: &HandshakeStore) -> (String, String) {
    let secret     = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret);
    let raw        = *public_key.as_bytes();
    let id         = format!("hs_{}", Uuid::new_v4());
    hs.0.insert(id.clone(), HandshakeEntry {
        secret,
        public_raw: raw,
        expires_at: Utc::now() + Duration::seconds(HANDSHAKE_TTL_SECS),
    });
    (id, B64.encode(raw))
}

/// Performs a use-once X25519 ECDH using a handshake entry created by [`init_handshake`].
/// Removes the entry on success — replaying the same handshake ID returns `EcdhError::KeyExpired`.
pub async fn ecdh_ephemeral(
    hs:              &HandshakeStore,
    handshake_id:    &str,
    client_pk_bytes: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), EcdhError> {
    let entry = hs.0.remove(handshake_id)
        .ok_or(EcdhError::KeyExpired)?;
    let (_, entry) = entry;
    if Utc::now() > entry.expires_at {
        return Err(EcdhError::KeyExpired);
    }
    let client_public = PublicKey::from(*client_pk_bytes);
    let shared        = entry.secret.diffie_hellman(&client_public);
    Ok((Zeroizing::new(*shared.as_bytes()), entry.public_raw))
}

/// Removes all expired handshake entries from `hs`. Call periodically (e.g. every 30 seconds).
pub fn prune_handshakes(hs: &HandshakeStore) {
    let now = Utc::now();
    hs.0.retain(|_, v| v.expires_at > now);
}

/// Spawns two background tasks:
/// - **Warm-up**: generates the next key `KEY_WARM_LEAD_SECS` before each rotation and stores it
///   in `KeyStore::next` so key generation never blocks the hot path.
/// - **Rotation**: swaps `next` (or falls back to a fresh key) into `current` and retires the old
///   key to `previous` for the grace-window period.
/// - **Cleanup**: prunes `previous` once its grace window expires, and prunes expired handshake
///   entries from `hs` every 30 seconds.
pub fn start_rotation(store: Arc<RwLock<KeyStore>>, interval_secs: u64, hs: HandshakeStore) {
    let warm_lead = KEY_WARM_LEAD_SECS.min(interval_secs.saturating_sub(1));
    let warm_offset = interval_secs.saturating_sub(warm_lead);

    let store_warm    = store.clone();
    let store_rotate  = store.clone();

    tokio::spawn(async move {
        let mut warm_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(warm_offset),
            tokio::time::Duration::from_secs(interval_secs),
        );
        loop {
            warm_interval.tick().await;
            let next = tokio::task::spawn_blocking(move || generate_entry(interval_secs))
                .await
                .expect("key generation panicked");
            store_warm.write().await.next = Some(next);
            tracing::debug!("next X25519 key pre-warmed");
        }
    });

    tokio::spawn(async move {
        let mut rotation_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(interval_secs),
            tokio::time::Duration::from_secs(interval_secs),
        );
        let mut cleanup_interval = tokio::time::interval(
            tokio::time::Duration::from_secs(30),
        );
        loop {
            tokio::select! {
                _ = rotation_interval.tick() => {
                    let mut w = store_rotate.write().await;
                    let new_entry = w.next.take().unwrap_or_else(|| generate_entry(interval_secs));
                    let old = std::mem::replace(&mut w.current, new_entry);
                    w.previous = Some(old);
                    tracing::info!("X25519 key rotated → {}", w.current.key_id);
                }
                _ = cleanup_interval.tick() => {
                    let needs_cleanup = {
                        let r = store_rotate.read().await;
                        r.previous.as_ref().map_or(false, |p| Utc::now() > p.expires_at)
                    };
                    if needs_cleanup {
                        store_rotate.write().await.previous = None;
                        tracing::debug!("previous X25519 key pruned");
                    }
                    prune_handshakes(&hs);
                }
            }
        }
    });
}

/// Returns `(key_id, base64_public_key)` for the currently active key.
pub async fn get_current_public_key(store: &Arc<RwLock<KeyStore>>) -> (String, String) {
    let guard = store.read().await;
    (guard.current.key_id.clone(), guard.current.public_key_b64.clone())
}

/// Performs X25519 ECDH using the server key identified by `key_id` and the client's
/// ephemeral public key bytes. Returns `(shared_secret, server_public_key_bytes)`.
///
/// Falls back to the previous key within its grace window; returns `EcdhError::KeyExpired` otherwise.
pub async fn ecdh(
    store:           &Arc<RwLock<KeyStore>>,
    key_id:          &str,
    client_pk_bytes: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), EcdhError> {
    let guard = store.read().await;

    let entry = if guard.current.key_id == key_id {
        &guard.current
    } else if let Some(prev) = &guard.previous {
        if prev.key_id == key_id {
            if Utc::now() > prev.expires_at {
                return Err(EcdhError::KeyExpired);
            }
            prev
        } else {
            return Err(EcdhError::KeyExpired);
        }
    } else {
        return Err(EcdhError::KeyExpired);
    };

    let client_public  = PublicKey::from(*client_pk_bytes);
    let shared         = entry.secret.diffie_hellman(&client_public);
    let server_pub_raw = entry.public_key_raw;

    Ok((Zeroizing::new(*shared.as_bytes()), server_pub_raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init_produces_valid_keypair() {
        let store         = init_key_store(3600);
        let (key_id, b64) = get_current_public_key(&store).await;
        assert!(!key_id.is_empty());
        let bytes = B64.decode(&b64).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[tokio::test]
    async fn ecdh_roundtrip() {
        let store = init_key_store(3600);
        let (key_id, b64) = get_current_public_key(&store).await;
        let server_pub_bytes: [u8; 32] = B64.decode(&b64).unwrap().try_into().unwrap();

        // Simulate client side
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let client_shared = client_secret.diffie_hellman(&PublicKey::from(server_pub_bytes));

        // Server side
        let (server_shared, _) = ecdh(&store, &key_id, client_public.as_bytes()).await.unwrap();

        assert_eq!(client_shared.as_bytes(), server_shared.as_slice());
    }

    #[tokio::test]
    async fn unknown_key_id_returns_expired() {
        let store = init_key_store(3600);
        let fake_pk = [0u8; 32];
        let result = ecdh(&store, "nonexistent", &fake_pk).await;
        assert!(matches!(result, Err(EcdhError::KeyExpired)));
    }
}
