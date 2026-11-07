#![deny(warnings)]
#![deny(clippy::all)]

pub mod buffer;
pub mod checkpointer;
mod fingerprinter;
pub mod internal_events;
mod metadata_ext;
pub mod status;

use vector_config::configurable_component;

pub use self::{
    checkpointer::{CHECKPOINT_FILE_NAME, Checkpointer, CheckpointsView},
    fingerprinter::{FileFingerprint, FingerprintStrategy, Fingerprinter},
    internal_events::FileSourceInternalEvents,
    metadata_ext::{AsyncFileInfo, PortableFileExt},
    status::{
        DEFAULT_STATUS_INTERVAL_SECS, FileSourceStatus, FileState, FileStatus,
        MAX_STATUS_INTERVAL_SECS, STATUS_FILE_NAME, StatusWriter,
    },
};

pub type FilePosition = u64;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ReadFrom {
    #[default]
    Beginning,
    End,
    Checkpoint(FilePosition),
}

/// File position to use when reading a new file.
#[configurable_component]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadFromConfig {
    /// Read from the beginning of the file.
    Beginning,

    /// Start reading from the current end of the file.
    End,
}

impl From<ReadFromConfig> for ReadFrom {
    fn from(rfc: ReadFromConfig) -> Self {
        match rfc {
            ReadFromConfig::Beginning => ReadFrom::Beginning,
            ReadFromConfig::End => ReadFrom::End,
        }
    }
}
