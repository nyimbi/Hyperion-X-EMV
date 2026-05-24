//! Hyperion EMV Level 2 kernel core.
//!
//! This crate intentionally keeps the certified protocol engine separate from
//! platform adapters. The C ABI in [`ffi`] exposes stable byte-buffer entry
//! points, while the Rust modules retain explicit state and typed errors.

pub mod afl;
pub mod aip;
pub mod apdu;
pub mod c8;
pub mod cid;
pub mod config;
pub mod conformance;
pub mod coverage;
pub mod cvm;
pub mod data_boundary;
pub mod device;
pub mod dol;
pub mod error;
pub mod evidence;
pub mod ffi;
pub mod freeze;
pub mod fsm;
pub mod gac;
pub mod gpo;
pub mod integration;
pub mod issuer;
pub mod numeric;
pub mod oda;
pub mod perf;
pub mod provenance;
pub mod quality;
pub mod record;
pub mod reporting;
pub mod restrictions;
pub mod security;
pub mod selection;
mod sha1;
pub mod state;
pub mod sw;
pub mod taa;
pub mod terminal;
pub mod tlv;
pub mod tooling;
pub mod trace;
pub mod trace_audit;
pub mod transaction;
pub mod trm;

pub use error::{KernelError, KernelResult};
