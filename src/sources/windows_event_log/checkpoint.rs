use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};
use tracing::{debug, error, info, warn};
use windows::Win32::Storage::FileSystem::ReplaceFileW;
use windows::core::HSTRING;

use super::error::WindowsEventLogError;

const CHECKPOINT_FILENAME: &str = "windows_event_log_checkpoints.json";

/// Checkpoint data for a single Windows Event Log channel
///
/// Uses Windows Event Log bookmarks for robust position tracking that survives
/// channel clears, log rotations, and provides O(1) seeking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelCheckpoint {
    /// The channel name (e.g., "System", "Application", "Security")
    pub channel: String,
    /// Windows Event Log bookmark XML for position tracking
    pub bookmark_xml: String,
    /// Timestamp when this checkpoint was last updated (for debugging)
    #[serde(default)]
    pub updated_at: String,

    /// `TimeCreated` of the last processed event, at full FILETIME (100ns)
    /// resolution.
    ///
    /// Additive and skipped when absent, so checkpoints written by an older
    /// binary still load and checkpoints written by this one stay readable by
    /// an older binary. The bookmark remains the primary position; this is the
    /// fallback the resume ladder needs when the bookmark is dead, and full
    /// precision is what lets the exact in-process boundary contribute zero
    /// duplicates after a millisecond-floored XPath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_time: Option<String>,

    /// `EventRecordID` of the last processed event, paired with
    /// `last_event_time` to make the resume position exactly identifiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_record_id: Option<u64>,
}

/// A checkpoint update for one channel.
///
/// The time and record id travel with the bookmark rather than beside it,
/// because a bookmark written without its position fallback is exactly the
/// state the resume ladder cannot recover from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPosition {
    pub channel: String,
    pub bookmark_xml: String,
    pub last_event_time: Option<String>,
    pub last_record_id: Option<u64>,
}

impl ChannelPosition {
    /// A position carrying only a bookmark, for callers that have nothing else.
    #[cfg(test)]
    pub fn bookmark_only(channel: String, bookmark_xml: String) -> Self {
        Self {
            channel,
            bookmark_xml,
            last_event_time: None,
            last_record_id: None,
        }
    }
}

/// Container for all channel checkpoints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CheckpointState {
    /// Version for future compatibility
    version: u32,
    /// Map of channel name to checkpoint
    channels: HashMap<String, ChannelCheckpoint>,
}

impl Default for CheckpointState {
    fn default() -> Self {
        Self {
            version: 1, // Version 1: bookmark-based checkpointing
            channels: HashMap::new(),
        }
    }
}

/// Manages checkpoint persistence for Windows Event Log subscriptions
///
/// Uses Windows Event Log bookmarks (opaque XML handles) to track position in
/// each channel. Bookmarks are more robust than record IDs as they survive
/// channel clears, log rotations, and provide O(1) seeking on restart.
pub struct Checkpointer {
    checkpoint_path: PathBuf,
    state: Mutex<CheckpointState>,
}

impl Checkpointer {
    /// Create a new checkpointer for the given data directory
    pub async fn new(data_dir: &Path) -> Result<Self, WindowsEventLogError> {
        let checkpoint_path = data_dir.join(CHECKPOINT_FILENAME);

        // Ensure the data directory exists
        if let Err(e) = fs::create_dir_all(data_dir).await
            && e.kind() != ErrorKind::AlreadyExists
        {
            return Err(WindowsEventLogError::IoError { source: e });
        }

        // Load existing checkpoint state or create new
        let state = Self::load_from_disk(&checkpoint_path).await?;

        info!(
            message = "Windows Event Log checkpointer initialized.",
            checkpoint_path = %checkpoint_path.display(),
            channels = state.channels.len()
        );

        Ok(Self {
            checkpoint_path,
            state: Mutex::new(state),
        })
    }

    /// Get the last checkpoint for a specific channel
    pub async fn get(&self, channel: &str) -> Option<ChannelCheckpoint> {
        let state = self.state.lock().await;
        state.channels.get(channel).cloned()
    }

    /// Update the checkpoint for a specific channel using bookmark XML
    ///
    /// Bookmarks provide robust position tracking that survives channel clears,
    /// log rotations, and provides O(1) seeking on restart.
    ///
    /// Note: For better performance with multiple channels, prefer `set_batch()`
    /// which writes all checkpoints in a single disk operation.
    #[cfg(test)]
    pub async fn set(
        &self,
        channel: String,
        bookmark_xml: String,
    ) -> Result<(), WindowsEventLogError> {
        let mut state = self.state.lock().await;

        let checkpoint = ChannelCheckpoint {
            channel: channel.clone(),
            bookmark_xml,
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_event_time: None,
            last_record_id: None,
        };

        state.channels.insert(channel.clone(), checkpoint);

        // Persist to disk immediately for reliability
        self.save_to_disk(&state).await?;

        debug!(
            message = "Updated checkpoint for channel.",
            channel = %channel
        );

        Ok(())
    }

    /// Update multiple channel checkpoints in a single atomic disk write
    ///
    /// This is much more efficient than calling `set()` multiple times because:
    /// - Single file write instead of N writes
    /// - Single fsync instead of N fsyncs
    /// - Atomic - either all channels update or none do
    ///
    /// Batching checkpoint updates is standard practice for event log collectors
    /// and avoids per-event disk I/O overhead.
    pub async fn set_batch(
        &self,
        updates: Vec<ChannelPosition>,
    ) -> Result<(), WindowsEventLogError> {
        if updates.is_empty() {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        let timestamp = chrono::Utc::now().to_rfc3339();

        for position in &updates {
            let checkpoint = ChannelCheckpoint {
                channel: position.channel.clone(),
                bookmark_xml: position.bookmark_xml.clone(),
                updated_at: timestamp.clone(),
                last_event_time: position.last_event_time.clone(),
                last_record_id: position.last_record_id,
            };
            state.channels.insert(position.channel.clone(), checkpoint);
        }

        // Single disk write for all channels
        self.save_to_disk(&state).await?;

        debug!(
            message = "Batch updated checkpoints.",
            channels_updated = updates.len()
        );

        Ok(())
    }

    /// Load checkpoint state from disk
    async fn load_from_disk(path: &Path) -> Result<CheckpointState, WindowsEventLogError> {
        match fs::read(path).await {
            Ok(contents) => match serde_json::from_slice::<CheckpointState>(&contents) {
                Ok(state) => {
                    info!(
                        message = "Loaded existing checkpoints.",
                        channels = state.channels.len(),
                        path = %path.display()
                    );
                    Ok(state)
                }
                Err(e) => {
                    warn!(
                        message = "Failed to parse checkpoint file, starting fresh.",
                        error = %e,
                        path = %path.display()
                    );
                    Ok(CheckpointState::default())
                }
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {
                debug!(
                    message = "No existing checkpoint file, starting fresh.",
                    path = %path.display()
                );
                Ok(CheckpointState::default())
            }
            Err(e) => {
                error!(
                    message = "Failed to read checkpoint file.",
                    error = %e,
                    path = %path.display()
                );
                Err(WindowsEventLogError::IoError { source: e })
            }
        }
    }

    /// Save checkpoint state to disk atomically
    async fn save_to_disk(&self, state: &CheckpointState) -> Result<(), WindowsEventLogError> {
        // Use atomic write: write to temp file, then rename
        let temp_path = self.checkpoint_path.with_extension("tmp");

        // Serialize state
        let contents = match serde_json::to_vec_pretty(state) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    message = "Failed to serialize checkpoint state.",
                    error = %e
                );
                return Err(WindowsEventLogError::IoError {
                    source: io::Error::new(ErrorKind::InvalidData, e),
                });
            }
        };

        // Write to temp file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await
            .map_err(|e| WindowsEventLogError::IoError { source: e })?;

        file.write_all(&contents)
            .await
            .map_err(|e| WindowsEventLogError::IoError { source: e })?;

        file.sync_all()
            .await
            .map_err(|e| WindowsEventLogError::IoError { source: e })?;

        drop(file);

        // Use ReplaceFileW for atomic replacement on Windows; fall back to
        // rename when the destination doesn't exist yet (first run).
        #[cfg(windows)]
        {
            let dst = HSTRING::from(self.checkpoint_path.to_string_lossy().as_ref());
            let src = HSTRING::from(temp_path.to_string_lossy().as_ref());
            let replaced = unsafe {
                ReplaceFileW(
                    &dst,
                    &src,
                    None,
                    windows::Win32::Storage::FileSystem::REPLACE_FILE_FLAGS(0),
                    None,
                    None,
                )
            };
            if replaced.is_err() {
                // Destination may not exist yet — fall back to rename
                fs::rename(&temp_path, &self.checkpoint_path)
                    .await
                    .map_err(|e| WindowsEventLogError::IoError { source: e })?;
            }
        }
        #[cfg(not(windows))]
        {
            fs::rename(&temp_path, &self.checkpoint_path)
                .await
                .map_err(|e| WindowsEventLogError::IoError { source: e })?;
        }

        Ok(())
    }

    /// Remove checkpoint for a channel (useful for testing or reset)
    #[cfg(test)]
    pub async fn remove(&self, channel: &str) -> Result<(), WindowsEventLogError> {
        let mut state = self.state.lock().await;
        state.channels.remove(channel);
        self.save_to_disk(&state).await?;

        info!(
            message = "Removed checkpoint for channel.",
            channel = %channel
        );

        Ok(())
    }

    /// Get all channel checkpoints (useful for debugging)
    #[cfg(test)]
    pub async fn list(&self) -> Vec<ChannelCheckpoint> {
        let state = self.state.lock().await;
        state.channels.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper to create test bookmark XML
    fn test_bookmark_xml(channel: &str, record_id: u64) -> String {
        format!(
            r#"<BookmarkList><Bookmark Channel="{}" RecordId="{}" IsCurrent="True"/></BookmarkList>"#,
            channel, record_id
        )
    }

    async fn create_test_checkpointer() -> (Checkpointer, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
        (checkpointer, temp_dir)
    }

    #[tokio::test]
    async fn test_checkpoint_basic_operations() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        // Initially empty
        assert!(checkpointer.get("System").await.is_none());

        // Set checkpoint
        let bookmark = test_bookmark_xml("System", 12345);
        checkpointer
            .set("System".to_string(), bookmark.clone())
            .await
            .unwrap();

        // Retrieve checkpoint
        let checkpoint = checkpointer.get("System").await.unwrap();
        assert_eq!(checkpoint.channel, "System");
        assert_eq!(checkpoint.bookmark_xml, bookmark);
    }

    #[tokio::test]
    async fn test_checkpoint_persistence() {
        let temp_dir = TempDir::new().unwrap();

        let system_bookmark = test_bookmark_xml("System", 100);
        let app_bookmark = test_bookmark_xml("Application", 200);

        // Create first checkpointer and set values
        {
            let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
            checkpointer
                .set("System".to_string(), system_bookmark.clone())
                .await
                .unwrap();
            checkpointer
                .set("Application".to_string(), app_bookmark.clone())
                .await
                .unwrap();
        }

        // Create new checkpointer (simulating restart) and verify persistence
        {
            let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
            let system_checkpoint = checkpointer.get("System").await.unwrap();
            assert_eq!(system_checkpoint.bookmark_xml, system_bookmark);

            let app_checkpoint = checkpointer.get("Application").await.unwrap();
            assert_eq!(app_checkpoint.bookmark_xml, app_bookmark);
        }
    }

    #[tokio::test]
    async fn test_checkpoint_update() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        // Set initial value
        let bookmark1 = test_bookmark_xml("System", 100);
        checkpointer
            .set("System".to_string(), bookmark1)
            .await
            .unwrap();

        // Update value
        let bookmark2 = test_bookmark_xml("System", 200);
        checkpointer
            .set("System".to_string(), bookmark2.clone())
            .await
            .unwrap();

        // Verify updated value
        let checkpoint = checkpointer.get("System").await.unwrap();
        assert_eq!(checkpoint.bookmark_xml, bookmark2);
    }

    #[tokio::test]
    async fn test_checkpoint_multiple_channels() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let system_bookmark = test_bookmark_xml("System", 100);
        let app_bookmark = test_bookmark_xml("Application", 200);
        let security_bookmark = test_bookmark_xml("Security", 300);

        checkpointer
            .set("System".to_string(), system_bookmark.clone())
            .await
            .unwrap();
        checkpointer
            .set("Application".to_string(), app_bookmark.clone())
            .await
            .unwrap();
        checkpointer
            .set("Security".to_string(), security_bookmark.clone())
            .await
            .unwrap();

        assert_eq!(
            checkpointer.get("System").await.unwrap().bookmark_xml,
            system_bookmark
        );
        assert_eq!(
            checkpointer.get("Application").await.unwrap().bookmark_xml,
            app_bookmark
        );
        assert_eq!(
            checkpointer.get("Security").await.unwrap().bookmark_xml,
            security_bookmark
        );
    }

    #[tokio::test]
    async fn test_checkpoint_remove() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let bookmark = test_bookmark_xml("System", 100);
        checkpointer
            .set("System".to_string(), bookmark)
            .await
            .unwrap();
        assert!(checkpointer.get("System").await.is_some());

        checkpointer.remove("System").await.unwrap();
        assert!(checkpointer.get("System").await.is_none());
    }

    #[tokio::test]
    async fn test_checkpoint_list() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let system_bookmark = test_bookmark_xml("System", 100);
        let app_bookmark = test_bookmark_xml("Application", 200);

        checkpointer
            .set("System".to_string(), system_bookmark)
            .await
            .unwrap();
        checkpointer
            .set("Application".to_string(), app_bookmark)
            .await
            .unwrap();

        let checkpoints = checkpointer.list().await;
        assert_eq!(checkpoints.len(), 2);
    }

    #[tokio::test]
    async fn test_corrupted_checkpoint_file() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join(CHECKPOINT_FILENAME);

        // Write corrupted data
        fs::write(&checkpoint_path, b"invalid json {{{")
            .await
            .unwrap();

        // Should handle gracefully and start fresh
        let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
        assert!(checkpointer.get("System").await.is_none());

        // Should be able to write new checkpoints
        let bookmark = test_bookmark_xml("System", 100);
        checkpointer
            .set("System".to_string(), bookmark.clone())
            .await
            .unwrap();
        assert_eq!(
            checkpointer.get("System").await.unwrap().bookmark_xml,
            bookmark
        );
    }

    #[tokio::test]
    async fn test_checkpoint_batch_update() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let system_bookmark = test_bookmark_xml("System", 100);
        let app_bookmark = test_bookmark_xml("Application", 200);
        let security_bookmark = test_bookmark_xml("Security", 300);

        // Batch update all channels at once
        checkpointer
            .set_batch(vec![
                ChannelPosition::bookmark_only("System".to_string(), system_bookmark.clone()),
                ChannelPosition::bookmark_only("Application".to_string(), app_bookmark.clone()),
                ChannelPosition::bookmark_only("Security".to_string(), security_bookmark.clone()),
            ])
            .await
            .unwrap();

        // Verify all channels were updated
        assert_eq!(
            checkpointer.get("System").await.unwrap().bookmark_xml,
            system_bookmark
        );
        assert_eq!(
            checkpointer.get("Application").await.unwrap().bookmark_xml,
            app_bookmark
        );
        assert_eq!(
            checkpointer.get("Security").await.unwrap().bookmark_xml,
            security_bookmark
        );
    }

    /// The time and record id are additive: a checkpoint file written by an
    /// older binary must still load, and a file written by this one must stay
    /// readable by an older binary (the extra keys are simply unknown to it).
    #[tokio::test]
    async fn test_position_fields_are_additive_in_both_directions() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join(CHECKPOINT_FILENAME);

        // A file in the old shape, with no position fields at all.
        let legacy = r#"{"version":1,"channels":{"System":{"channel":"System",
            "bookmark_xml":"<BookmarkList/>","updated_at":"2026-01-01T00:00:00Z"}}}"#;
        fs::write(&checkpoint_path, legacy.as_bytes())
            .await
            .unwrap();

        let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
        let loaded = checkpointer.get("System").await.expect("legacy must load");
        assert_eq!(loaded.last_event_time, None);
        assert_eq!(loaded.last_record_id, None);

        // Writing without a position must not emit the keys at all, so an
        // older binary sees a byte-identical shape to what it wrote.
        checkpointer
            .set_batch(vec![ChannelPosition::bookmark_only(
                "System".to_string(),
                "<BookmarkList/>".to_string(),
            )])
            .await
            .unwrap();
        let written = fs::read_to_string(&checkpoint_path).await.unwrap();
        assert!(!written.contains("last_event_time"));
        assert!(!written.contains("last_record_id"));

        // With a position, both round-trip at full precision.
        checkpointer
            .set_batch(vec![ChannelPosition {
                channel: "System".to_string(),
                bookmark_xml: "<BookmarkList/>".to_string(),
                last_event_time: Some("2026-08-07T14:03:11.1234567Z".to_string()),
                last_record_id: Some(91827),
            }])
            .await
            .unwrap();

        let reopened = Checkpointer::new(temp_dir.path()).await.unwrap();
        let loaded = reopened.get("System").await.unwrap();
        assert_eq!(
            loaded.last_event_time.as_deref(),
            Some("2026-08-07T14:03:11.1234567Z")
        );
        assert_eq!(loaded.last_record_id, Some(91827));
    }

    #[tokio::test]
    async fn test_checkpoint_batch_empty() {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        // Empty batch should succeed without writing
        checkpointer.set_batch(vec![]).await.unwrap();

        // No checkpoints should exist
        assert!(checkpointer.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_checkpoint_batch_persistence() {
        let temp_dir = TempDir::new().unwrap();

        let system_bookmark = test_bookmark_xml("System", 100);
        let app_bookmark = test_bookmark_xml("Application", 200);

        // Create first checkpointer and batch update
        {
            let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
            checkpointer
                .set_batch(vec![
                    ChannelPosition::bookmark_only("System".to_string(), system_bookmark.clone()),
                    ChannelPosition::bookmark_only("Application".to_string(), app_bookmark.clone()),
                ])
                .await
                .unwrap();
        }

        // Create new checkpointer (simulating restart) and verify persistence
        {
            let checkpointer = Checkpointer::new(temp_dir.path()).await.unwrap();
            assert_eq!(
                checkpointer.get("System").await.unwrap().bookmark_xml,
                system_bookmark
            );
            assert_eq!(
                checkpointer.get("Application").await.unwrap().bookmark_xml,
                app_bookmark
            );
        }
    }
}
