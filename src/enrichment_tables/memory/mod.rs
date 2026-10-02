//! Handles enrichment tables for `type = memory`.

mod config;
mod internal_events;
mod persist;
mod source;
mod table;

pub use config::*;
pub use table::*;
