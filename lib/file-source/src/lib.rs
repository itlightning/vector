#![deny(warnings)]
#![deny(clippy::all)]

pub mod encoding;
pub mod file_server;
pub mod file_watcher;
pub mod paths_provider;

pub use encoding::{
    EncodingDetectOutcome, FileEncodingDetector, FileEncodingMode, FileEncodingState,
};
