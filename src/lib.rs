// SPDX-License-Identifier: GPL-3.0
//! # alterion-key-exchange
//!
//! X25519 ECDH key store with timed rotation, a 300-second grace window, and HKDF-SHA256
//! session key derivation — the key exchange layer for the
//! [alterion-enc-pipeline](https://crates.io/crates/alterion-enc-pipeline).
//!
//! ## Example
//!
//! ```rust,no_run
//! use alterion_key_exchange::{init_key_store, start_rotation, get_current_public_key, ecdh};
//! use actix_web::{web, App, HttpServer, get, HttpResponse};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use alterion_key_exchange::KeyStore;
//!
//! #[get("/api/pubkey")]
//! async fn pubkey_handler(
//!     store: web::Data<Arc<RwLock<KeyStore>>>,
//! ) -> HttpResponse {
//!     let (key_id, public_key) = get_current_public_key(&store).await;
//!     HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": public_key }))
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let store = init_key_store(3600);
//!     start_rotation(store.clone(), 3600);
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .app_data(web::Data::new(store.clone()))
//!             .service(pubkey_handler)
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```

pub mod keystore;

pub use keystore::{
    KeyStore, KeyEntry, EcdhError,
    init_key_store, start_rotation, get_current_public_key, ecdh,
};
