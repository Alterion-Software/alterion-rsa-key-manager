// SPDX-License-Identifier: GPL-3.0
//! # alterion-rsa-key-manager
//!
//! RSA-2048 key store with timed rotation, a 300-second grace window, and OAEP-SHA256 decryption.
//!
//! ## Example
//!
//! ```rust,no_run
//! use alterion_rsa_key_manager::{init_key_store, start_rotation, get_current_public_key, decrypt};
//! use actix_web::{web, App, HttpServer, get, HttpResponse};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use alterion_rsa_key_manager::KeyStore;
//!
//! #[get("/api/pubkey")]
//! async fn pubkey_handler(
//!     store: web::Data<Arc<RwLock<KeyStore>>>,
//! ) -> HttpResponse {
//!     let (key_id, pem) = get_current_public_key(&store).await;
//!     HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": pem }))
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Rotate every hour; previous key stays live for 5 minutes (grace window).
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
    KeyStore, KeyEntry, RsaError,
    init_key_store, start_rotation, get_current_public_key, decrypt,
};
