//! Hyperion EMV Level 2 kernel core.
//!
//! This crate intentionally keeps the certified protocol engine separate from
//! platform adapters. The C ABI in [`ffi`] exposes stable byte-buffer entry
//! points, while the Rust modules retain explicit state and typed errors.

pub mod afl;
pub mod apdu;
pub mod c8;
pub mod cid;
pub mod config;
pub mod conformance;
pub mod cvm;
pub mod dol;
pub mod error;
pub mod ffi;
pub mod fsm;
pub mod gac;
pub mod gpo;
pub mod issuer;
pub mod oda;
pub mod perf;
pub mod provenance;
pub mod quality;
pub mod record;
pub mod restrictions;
pub mod selection;
mod sha1;
pub mod state;
pub mod sw;
pub mod taa;
pub mod terminal;
pub mod tlv;
pub mod trace;
pub mod trm;

pub use error::{KernelError, KernelResult};
