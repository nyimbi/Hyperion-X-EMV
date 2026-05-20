//! Hyperion EMV Level 2 kernel core.
//!
//! This crate intentionally keeps the certified protocol engine separate from
//! platform adapters. The C ABI in [`ffi`] exposes stable byte-buffer entry
//! points, while the Rust modules retain explicit state and typed errors.

pub mod afl;
pub mod apdu;
pub mod cid;
pub mod cvm;
pub mod dol;
pub mod error;
pub mod ffi;
pub mod gac;
pub mod issuer;
pub mod restrictions;
pub mod state;
pub mod sw;
pub mod taa;
pub mod tlv;
pub mod trm;

pub use error::{KernelError, KernelResult};
