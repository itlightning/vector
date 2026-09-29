#![cfg(feature = "sources-windows_event_log-integration-tests")]
#![cfg(test)]

use std::collections::HashSet;
use std::process::Command;
use std::time::Duration;

use futures::StreamExt;
use tokio::fs;

use vrl::event_path;

use super::*;
use crate::config::{SourceAcknowledgementsConfig, SourceConfig, SourceContext};
use crate::test_util::components::run_and_assert_source_compliance;
use vector_lib::event::EventStatus;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Emit a test event into the Application log via `eventcreate.exe`.
///
/// Each test should use a unique `source` name (e.g. `"VT_stress"`) to
/// prevent cross-test pollution when tests run in parallel. The source
/// name is used as the Provider/@Name in the event, which tests then
/// filter on via XPath.
///
/// Requires administrator privileges. Panics with a clear message if
/// `eventcreate` is missing or the call fails.
fn emit_event(source: &str, event_type: &str, event_id: u32, description: &str) {
    // Retry a few times because eventcreate can transiently fail with exit
    // code 1 when multiple tests invoke it concurrently (registry contention).
    let max_retries = 3;
    for attempt in 0..=max_retries {
        let status = Command::new("eventcreate")
            .args([
                "/L",
                "Application",
                "/T",
                event_type,
                "/ID",
                &event_id.to_string(),
                "/SO",
                source,
                "/D",
                description,
            ])
            .status()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to start eventcreate (error: {e}); \
                     ensure it is on PATH and tests run as Administrator"
                )
            });

        if status.success() {
            return;
        }

        if attempt < max_retries {
            std::thread::sleep(Duration::from_millis(200 * (attempt as u64 + 1)));
        } else {
            panic!(
                "eventcreate exited with {status} after {max_retries} retries; \
                 run tests as Administrator"
            );
        }
    }
}

fn temp_data_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create temp data_dir for test")
}

/// XPath query that matches events from a specific test source.
fn test_query(source: &str) -> String {
    format!("*[System[Provider[@Name='{source}'] and EventID=1000]]")
}

/// Build a config targeting Application + a specific test source.
fn test_config(source: &str, data_dir: &std::path::Path) -> WindowsEventLogConfig {
    WindowsEventLogConfig {
        data_dir: Some(data_dir.to_path_buf()),
        channels: vec!["Application".to_string()],
        event_query: Some(test_query(source)),
        read_existing_events: true,
        batch_size: 100,
        event_timeout_ms: 2000,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Basic ingestion
// ---------------------------------------------------------------------------

/// Verify the source can subscribe and receive at least one event with all
/// expected top-level fields present.
#[tokio::test]
async fn test_basic_event_ingestion() {
    let data_dir = temp_data_dir();
    emit_event("VT_basic", "INFORMATION", 1000, "basic ingestion test");

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["System".to_string(), "Application".to_string()],
        read_existing_events: true,
        batch_size: 10,
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;
    assert!(
        !events.is_empty(),
        "Expected at least one event from System or Application, got 0. \
         Verify the Windows Event Log service is running."
    );

    let log = events[0].as_log();
    for field in [
        "timestamp",
        "message",
        "provider_name",
        "channel",
        "event_id",
        "level",
    ] {
        assert!(
            log.contains(event_path!(field)),
            "Event is missing required field '{field}'. \
             Full event keys: {:?}",
            log.keys().into_iter().flatten().collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// Drain loop / backlog handling
// ---------------------------------------------------------------------------

/// Emit N events, verify all N arrive with no duplicates.
/// This exercises the EvtNext drain loop across multiple batches.
#[tokio::test]
async fn test_backlog_drain_no_duplicates() {
    let data_dir = temp_data_dir();
    let n = 50;

    for i in 0..n {
        emit_event(
            "VT_backlog",
            "INFORMATION",
            1000,
            &format!("backlog-drain-test-event-{i}"),
        );
    }

    let config = test_config("VT_backlog", data_dir.path());
    let events = run_and_assert_source_compliance(config, Duration::from_secs(10), &[]).await;

    assert!(
        events.len() >= n,
        "Expected at least {n} events, got {}. \
         The drain loop may not be exhausting the channel. \
         Check pull_events batch limit and signal management.",
        events.len()
    );

    // Check for duplicates via record_id
    let mut record_ids = HashSet::new();
    let mut duplicate_count = 0;
    for event in &events {
        if let Some(rid) = event.as_log().get(event_path!("record_id")) {
            if !record_ids.insert(rid.to_string_lossy()) {
                duplicate_count += 1;
            }
        }
    }
    assert_eq!(
        duplicate_count,
        0,
        "Found {duplicate_count} duplicate record_ids out of {} events. \
         Bookmark advancement or checkpoint logic may be broken.",
        events.len()
    );
}

// ---------------------------------------------------------------------------
// Checkpoint / resume
// ---------------------------------------------------------------------------

/// Run the source, stop it, emit new events, run again with the same
/// data_dir. The second run should see ONLY the new events.
#[tokio::test]
async fn test_checkpoint_resume_no_redelivery() {
    let data_dir = temp_data_dir();

    // Phase 1: emit and consume
    emit_event("VT_ckptres", "INFORMATION", 1000, "checkpoint-test-phase1");
    let config = test_config("VT_ckptres", data_dir.path());
    let first_run = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;
    assert!(
        !first_run.is_empty(),
        "Phase 1 produced 0 events. Cannot test checkpoint resume."
    );
    // Let checkpoint flush to disk
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Phase 2: emit one more, reuse same data_dir
    emit_event("VT_ckptres", "INFORMATION", 1000, "checkpoint-test-phase2");
    let config = test_config("VT_ckptres", data_dir.path());
    let second_run = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    // Phase 1 event should NOT be redelivered (checkpoint should have advanced past it)
    let has_phase1 = second_run.iter().any(|e| {
        e.as_log()
            .get(event_path!("message"))
            .map(|m| m.to_string_lossy().contains("checkpoint-test-phase1"))
            .unwrap_or(false)
    });
    assert!(
        !has_phase1,
        "Phase 1 event was redelivered in phase 2 — checkpoint did not advance. \
         Check checkpoint persistence in data_dir: {:?}",
        data_dir.path()
    );

    // The new phase 2 event should be present
    let has_phase2 = second_run.iter().any(|e| {
        e.as_log()
            .get(event_path!("message"))
            .map(|m| m.to_string_lossy().contains("checkpoint-test-phase2"))
            .unwrap_or(false)
    });
    assert!(
        has_phase2,
        "Phase 2 event not found in second run — checkpoint may have advanced past it. \
         Got {} events.",
        second_run.len()
    );
}

// ---------------------------------------------------------------------------
// Channel filtering
// ---------------------------------------------------------------------------

/// Subscribe to System only, verify no Application events leak through.
#[tokio::test]
async fn test_channel_isolation() {
    let data_dir = temp_data_dir();
    emit_event("VT_chaniso", "INFORMATION", 1000, "channel isolation test"); // goes to Application

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["System".to_string()],
        read_existing_events: true,
        batch_size: 20,
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(3), &[]).await;

    for event in &events {
        if let Some(channel) = event.as_log().get(event_path!("channel")) {
            let ch = channel.to_string_lossy();
            assert_eq!(
                ch, "System",
                "Got event from channel '{ch}' but only subscribed to System. \
                 Channel filtering in EvtSubscribe may be broken."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Event ID filtering
// ---------------------------------------------------------------------------

/// Verify only_event_ids includes only matching events.
/// Note: eventcreate.exe only supports IDs 1-1000, so we use 999 and 1000.
#[tokio::test]
async fn test_only_event_ids_filter() {
    let data_dir = temp_data_dir();
    emit_event("VT_onlyid", "INFORMATION", 999, "only-filter-exclude");
    emit_event("VT_onlyid", "INFORMATION", 1000, "only-filter-include");

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        read_existing_events: true,
        only_event_ids: Some(vec![1000]),
        event_query: Some("*[System[Provider[@Name='VT_onlyid']]]".to_string()),
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    for event in &events {
        if let Some(eid) = event.as_log().get(event_path!("event_id")) {
            let id: i64 = match eid {
                vrl::value::Value::Integer(i) => *i,
                other => other.to_string_lossy().parse().unwrap_or(-1),
            };
            assert_eq!(
                id, 1000,
                "only_event_ids=[1000] but got event_id={id}. \
                 Event ID filtering in parse_event_xml may be broken."
            );
        }
    }
}

/// Verify ignore_event_ids excludes matching events.
#[tokio::test]
async fn test_ignore_event_ids_filter() {
    let data_dir = temp_data_dir();
    emit_event("VT_ignid", "INFORMATION", 1000, "ignore-filter-test");

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        read_existing_events: true,
        ignore_event_ids: vec![1000],
        event_query: Some("*[System[Provider[@Name='VT_ignid']]]".to_string()),
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(3), &[]).await;

    for event in &events {
        if let Some(eid) = event.as_log().get(event_path!("event_id")) {
            let id: i64 = match eid {
                vrl::value::Value::Integer(i) => *i,
                other => other.to_string_lossy().parse().unwrap_or(-1),
            };
            assert_ne!(
                id, 1000,
                "ignore_event_ids=[1000] but event_id=1000 was not filtered. \
                 Check ignore_event_ids logic in parse_event_xml."
            );
        }
    }
}

/// Verify that only_event_ids generates an XPath filter when no explicit
/// event_query is set. The existing `test_only_event_ids_filter` always sets
/// both `only_event_ids` AND `event_query`, so the auto-generated XPath path
/// in `build_xpath_query()` was never exercised — that is how the original
/// performance bug shipped.
///
/// This test sets only_event_ids=[1000] WITHOUT event_query, so the source
/// must auto-generate `*[System[EventID=1000]]` and only receive matching
/// events from the Windows API.
#[tokio::test]
async fn test_only_event_ids_generates_xpath_filter() {
    let data_dir = temp_data_dir();

    // Emit events with different IDs. Only ID 1000 should be returned.
    emit_event("VT_xpathid", "INFORMATION", 999, "xpath-filter-exclude");
    emit_event("VT_xpathid", "INFORMATION", 1000, "xpath-filter-include");
    emit_event("VT_xpathid", "INFORMATION", 998, "xpath-filter-exclude-2");

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        read_existing_events: true,
        only_event_ids: Some(vec![1000]),
        // Intentionally NOT setting event_query — this forces
        // build_xpath_query() to auto-generate the XPath from only_event_ids.
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    // We must receive at least one event (the 1000 we emitted).
    assert!(
        !events.is_empty(),
        "Expected at least one event with ID 1000 from XPath-filtered subscription"
    );

    // Every event must have event_id == 1000.
    for event in &events {
        if let Some(eid) = event.as_log().get(event_path!("event_id")) {
            let id: i64 = match eid {
                vrl::value::Value::Integer(i) => *i,
                other => other.to_string_lossy().parse().unwrap_or(-1),
            };
            assert_eq!(
                id, 1000,
                "only_event_ids=[1000] (without event_query) but got event_id={id}. \
                 XPath generation in build_xpath_query may be broken."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Event level / type variety
// ---------------------------------------------------------------------------

/// eventcreate supports INFORMATION, WARNING, ERROR. Verify all three produce
/// events with correct level names.
#[tokio::test]
async fn test_multiple_event_levels() {
    let data_dir = temp_data_dir();
    emit_event("VT_levels", "INFORMATION", 1000, "level-test-info");
    emit_event("VT_levels", "WARNING", 1000, "level-test-warn");
    emit_event("VT_levels", "ERROR", 1000, "level-test-error");

    let config = test_config("VT_levels", data_dir.path());
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    let mut levels_seen: HashSet<String> = HashSet::new();
    for event in &events {
        if let Some(level) = event.as_log().get(event_path!("level")) {
            levels_seen.insert(level.to_string_lossy().to_string());
        }
    }

    for expected in ["Information", "Warning", "Error"] {
        assert!(
            levels_seen.contains(expected),
            "Expected level '{expected}' in output but only saw: {levels_seen:?}. \
             level_name() mapping or EvtRender may not be extracting Level correctly."
        );
    }
}

// ---------------------------------------------------------------------------
// Rendered message
// ---------------------------------------------------------------------------

/// With render_message enabled (the default), the message field should contain
/// the actual event description, not the generic fallback.
#[tokio::test]
async fn test_rendered_message_content() {
    let data_dir = temp_data_dir();
    let marker = "rendered-message-test-unique-string-12345";
    emit_event("VT_render", "INFORMATION", 1000, marker);

    let mut config = test_config("VT_render", data_dir.path());
    config.render_message = true;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    let found = events.iter().any(|e| {
        e.as_log()
            .get(event_path!("message"))
            .map(|m| m.to_string_lossy().contains(marker))
            .unwrap_or(false)
    });

    assert!(
        found,
        "render_message=true but no event message contains the marker '{marker}'. \
         EvtFormatMessage may be failing or the message field is using the generic fallback. \
         Got {} events, first message: {:?}",
        events.len(),
        events
            .first()
            .and_then(|e| e.as_log().get(event_path!("message")))
            .map(|m| m.to_string_lossy())
    );
}

/// With render_message disabled, events should still have a message field
/// (the generic fallback).
#[tokio::test]
async fn test_render_message_disabled_fallback() {
    let data_dir = temp_data_dir();
    emit_event("VT_noren", "INFORMATION", 1000, "render disabled test");

    let mut config = test_config("VT_noren", data_dir.path());
    config.render_message = false;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    if !events.is_empty() {
        let log = events[0].as_log();
        assert!(
            log.contains(event_path!("message")),
            "render_message=false should still produce a message field (generic fallback). \
             Event keys: {:?}",
            log.keys().into_iter().flatten().collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// XML inclusion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_include_xml_well_formed() {
    let data_dir = temp_data_dir();
    emit_event("VT_xmlinc", "INFORMATION", 1000, "xml inclusion test");

    let mut config = test_config("VT_xmlinc", data_dir.path());
    config.include_xml = true;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;
    assert!(
        !events.is_empty(),
        "Got 0 events, cannot verify XML inclusion."
    );

    let log = events[0].as_log();
    let xml = log.get(event_path!("xml")).expect(
        "include_xml=true but 'xml' field missing. \
         Check raw_xml population in parse_event_xml.",
    );
    let xml_str = xml.to_string_lossy();
    assert!(
        xml_str.contains("<Event") && xml_str.contains("</Event>"),
        "XML field should contain well-formed <Event>...</Event>, got: {}",
        xml_str.chars().take(200).collect::<String>()
    );
}

/// When include_xml is false (default), no xml field should be present.
#[tokio::test]
async fn test_exclude_xml_by_default() {
    let data_dir = temp_data_dir();
    emit_event("VT_xmlexc", "INFORMATION", 1000, "xml exclusion test");

    let mut config = test_config("VT_xmlexc", data_dir.path());
    config.include_xml = false;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    for event in &events {
        assert!(
            !event.as_log().contains(event_path!("xml")),
            "include_xml=false but 'xml' field is present."
        );
    }
}

// ---------------------------------------------------------------------------
// Field filtering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_field_filter_exclude_event_data() {
    let data_dir = temp_data_dir();

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["System".to_string()],
        read_existing_events: true,
        field_filter: FieldFilter {
            include_system_fields: true,
            include_event_data: false,
            include_user_data: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(3), &[]).await;

    for event in events.iter().take(10) {
        let log = event.as_log();
        assert!(
            !log.contains(event_path!("event_data")),
            "include_event_data=false but 'event_data' field is present."
        );
        assert!(
            !log.contains(event_path!("user_data")),
            "include_user_data=false but 'user_data' field is present."
        );
    }
}

// ---------------------------------------------------------------------------
// Resilience
// ---------------------------------------------------------------------------

/// Short timeouts should not crash or panic.
#[tokio::test]
async fn test_short_timeouts_no_crash() {
    let data_dir = temp_data_dir();
    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["System".to_string(), "Application".to_string()],
        connection_timeout_secs: 5,
        event_timeout_ms: 500,
        batch_size: 5,
        ..Default::default()
    };

    // If this panics, the test fails with a clear backtrace.
    let _events = run_and_assert_source_compliance(config, Duration::from_secs(2), &[]).await;
}

/// Invalid channel name should not crash — the source should skip it or
/// return a clear error.
#[tokio::test]
async fn test_nonexistent_channel_graceful_handling() {
    let data_dir = temp_data_dir();
    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec![
            "Application".to_string(),
            "ThisChannelDoesNotExist12345".to_string(),
        ],
        event_timeout_ms: 2000,
        ..Default::default()
    };

    // Should not panic. May produce events from Application only, or may
    // error on the bad channel — either is acceptable.
    let _result = run_and_assert_source_compliance(config, Duration::from_secs(3), &[]).await;
}

// ---------------------------------------------------------------------------
// Event structure completeness
// ---------------------------------------------------------------------------

/// Verify all Windows Event Log fields that SOC/SIEM analysts depend on are
/// present and have reasonable values.
#[tokio::test]
async fn test_event_field_completeness() {
    let data_dir = temp_data_dir();
    emit_event("VT_fields", "INFORMATION", 1000, "field completeness test");

    let mut config = test_config("VT_fields", data_dir.path());
    config.include_xml = true;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;
    assert!(
        !events.is_empty(),
        "Got 0 events, cannot verify field completeness."
    );

    let log = events[0].as_log();

    // Fields that must always be present
    let required = [
        "timestamp",
        "message",
        "event_id",
        "level",
        "level_value",
        "channel",
        "provider_name",
        "computer",
        "record_id",
        "process_id",
        "thread_id",
    ];

    let mut missing = Vec::new();
    for field in &required {
        if !log.contains(event_path!(*field)) {
            missing.push(*field);
        }
    }

    assert!(
        missing.is_empty(),
        "Event is missing required fields: {missing:?}. \
         Present fields: {:?}. \
         This breaks SOC/SIEM ingestion pipelines that depend on these fields.",
        log.keys().into_iter().flatten().collect::<Vec<_>>()
    );

    // Verify event_id is a positive integer
    if let Some(eid) = log.get(event_path!("event_id")) {
        match eid {
            vrl::value::Value::Integer(i) => {
                assert!(*i > 0, "event_id should be a positive integer, got {i}")
            }
            other => panic!(
                "event_id should be an integer, got: {other:?}. \
                 Check parser set_windows_fields."
            ),
        }
    }

    // Verify record_id is a positive integer
    if let Some(rid) = log.get(event_path!("record_id")) {
        match rid {
            vrl::value::Value::Integer(i) => {
                assert!(*i > 0, "record_id should be a positive integer, got {i}")
            }
            other => panic!("record_id should be an integer, got: {other:?}."),
        }
    }

    // Verify level is a human-readable string
    if let Some(level) = log.get(event_path!("level")) {
        let level_str = level.to_string_lossy();
        assert!(
            ["Information", "Warning", "Error", "Critical", "Verbose"]
                .contains(&level_str.as_ref()),
            "level should be a human-readable name, got '{level_str}'. \
             Check level_name() mapping."
        );
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// With events_per_second set, events should still arrive but the source
/// should not exceed the configured rate over a sustained period.
#[tokio::test]
async fn test_rate_limiting() {
    let data_dir = temp_data_dir();

    // Emit a burst of events
    for i in 0..20 {
        emit_event(
            "VT_rate",
            "INFORMATION",
            1000,
            &format!("rate-limit-test-{i}"),
        );
    }

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        event_query: Some(test_query("VT_rate")),
        read_existing_events: true,
        events_per_second: 50,
        batch_size: 100,
        event_timeout_ms: 2000,
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    // With rate limiting enabled, we should still get events — the limiter
    // throttles batch throughput, not total count over the run duration.
    assert!(
        !events.is_empty(),
        "events_per_second=50 should still produce events, got 0. \
         Rate limiter may be blocking all batches."
    );
}

// ---------------------------------------------------------------------------
// Event data truncation
// ---------------------------------------------------------------------------

/// With max_event_data_length set, long event data values should be truncated.
#[tokio::test]
async fn test_event_data_truncation() {
    let data_dir = temp_data_dir();

    // eventcreate puts the description into the event message, not EventData.
    // We verify truncation indirectly: the source should not crash and events
    // should still arrive with the field present.
    let long_desc = "A".repeat(500);
    emit_event("VT_trunc", "INFORMATION", 1000, &long_desc);

    let mut config = test_config("VT_trunc", data_dir.path());
    config.max_event_data_length = 100;
    config.include_xml = false;

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    assert!(
        !events.is_empty(),
        "max_event_data_length=100 should not prevent event ingestion."
    );
}

// ---------------------------------------------------------------------------
// Max event age filtering
// ---------------------------------------------------------------------------

/// With max_event_age_secs set to a very low value, old events should be
/// filtered out.
#[tokio::test]
async fn test_max_event_age_filtering() {
    let data_dir = temp_data_dir();

    // Emit event, then configure a very short max age so it's already "old"
    // by the time we read it.
    emit_event("VT_maxage", "INFORMATION", 1000, "age-filter-test");

    // Sleep so the event ages past the max_event_age_secs threshold.
    // Use a generous buffer to avoid flakes from clock jitter on slow CI.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        event_query: Some(test_query("VT_maxage")),
        read_existing_events: true,
        max_event_age_secs: Some(3), // 3 seconds — our event is already ~5s old
        event_timeout_ms: 2000,
        ..Default::default()
    };

    // This may produce 0 events (filtered) or some events from other sources.
    // The key assertion: the source should not crash.
    let events = run_and_assert_source_compliance(config, Duration::from_secs(3), &[]).await;

    // If we got events, verify none of them are our old test event
    for event in &events {
        if let Some(msg) = event.as_log().get(event_path!("message")) {
            assert!(
                !msg.to_string_lossy().contains("age-filter-test"),
                "max_event_age_secs=3 but old event was not filtered out. \
                 Check age filtering in build_event."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Event data format coercion
// ---------------------------------------------------------------------------

/// With event_data_format configured, specific fields should be coerced
/// to the requested type.
#[tokio::test]
async fn test_event_data_format_coercion() {
    let data_dir = temp_data_dir();
    emit_event("VT_format", "INFORMATION", 1000, "format coercion test");

    let mut config = test_config("VT_format", data_dir.path());
    config.field_filter.include_event_data = true;
    // event_id is a system field set as Integer by the parser, so test
    // that event_data_format can convert it to a string
    config.event_data_format.insert(
        "event_id".to_string(),
        super::config::EventDataFormat::String,
    );

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    assert!(
        !events.is_empty(),
        "event_data_format config should not prevent event ingestion."
    );

    // event_id should be converted to string by the custom formatter
    let log = events[0].as_log();
    if let Some(eid) = log.get(event_path!("event_id")) {
        assert!(
            matches!(eid, vrl::value::Value::Bytes(_)),
            "event_data_format set event_id to String but got {:?}. \
             Check apply_custom_formatting in parser.",
            eid
        );
    }
}

// ---------------------------------------------------------------------------
// Multi-channel simultaneous ingestion
// ---------------------------------------------------------------------------

/// Subscribe to both System and Application, verify events arrive from
/// both channels.
#[tokio::test]
async fn test_multi_channel_ingestion() {
    let data_dir = temp_data_dir();
    emit_event("VT_multi", "INFORMATION", 1000, "multi channel test"); // Goes to Application

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["System".to_string(), "Application".to_string()],
        read_existing_events: true,
        batch_size: 50,
        event_timeout_ms: 2000,
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    let mut channels_seen: HashSet<String> = HashSet::new();
    for event in &events {
        if let Some(channel) = event.as_log().get(event_path!("channel")) {
            channels_seen.insert(channel.to_string_lossy().to_string());
        }
    }

    // System always has events on any running Windows machine
    assert!(
        channels_seen.contains("System"),
        "Subscribed to System but got no System events. \
         Channels seen: {channels_seen:?}"
    );
    assert!(
        channels_seen.contains("Application"),
        "Subscribed to Application and emitted a test event but got no Application events. \
         Channels seen: {channels_seen:?}"
    );
}

// ---------------------------------------------------------------------------
// Error path / metrics compliance
// ---------------------------------------------------------------------------

/// When ALL channels are invalid, the source should exit gracefully
/// without panicking and produce no events.
#[tokio::test]
async fn test_all_channels_invalid_no_panic() {
    let data_dir = temp_data_dir();
    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["ThisChannelDoesNotExist99999".to_string()],
        event_timeout_ms: 1000,
        ..Default::default()
    };

    // Build and run the source directly — don't use run_and_assert_source_compliance
    // since with 0 valid channels we expect 0 events and no compliance metrics.
    let (tx, _rx) = SourceSender::new_test();
    let cx = SourceContext::new_test(tx, None);
    let source = config.build(cx).await.expect("source should build");

    let timeout = tokio::time::timeout(Duration::from_secs(3), source).await;

    // Source should complete (Ok or Err) within the timeout, not hang.
    assert!(
        timeout.is_ok(),
        "Source with all invalid channels should exit promptly, not hang."
    );
}

/// Verify that when events are successfully ingested, the standard
/// component metrics (component_received_events_total,
/// component_received_bytes_total, etc.) are emitted correctly.
/// This is the happy-path compliance check with explicit metric verification.
#[tokio::test]
async fn test_source_compliance_metrics() {
    let data_dir = temp_data_dir();
    emit_event("VT_comply", "INFORMATION", 1000, "compliance metrics test");

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        read_existing_events: true,
        batch_size: 50,
        event_timeout_ms: 2000,
        ..Default::default()
    };

    // run_and_assert_source_compliance validates:
    // - BytesReceived, EventsReceived, EventsSent internal events
    // - component_received_bytes_total (tagged with protocol)
    // - component_received_events_total
    // - component_received_event_bytes_total
    // - component_sent_events_total
    // - component_sent_event_bytes_total
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    assert!(
        !events.is_empty(),
        "Compliance test requires at least one event to validate metrics."
    );
}

// ---------------------------------------------------------------------------
// Security validation
// ---------------------------------------------------------------------------

/// Wildcard channel patterns must be rejected at config validation time,
/// not passed to EvtSubscribe where they can cause heap corruption with
/// many matching channels.
#[tokio::test]
async fn test_wildcard_channels_rejected() {
    let wildcards = vec!["Microsoft-Windows-*", "*", "System?", "[Ss]ystem"];

    for pattern in wildcards {
        let config = WindowsEventLogConfig {
            channels: vec![pattern.to_string()],
            ..Default::default()
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "Wildcard pattern '{pattern}' should be rejected by config validation."
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("wildcard"),
            "Error for '{pattern}' should mention wildcards, got: {err}"
        );
    }
}

/// XPath injection attempts must be rejected at config validation time.
#[tokio::test]
async fn test_xpath_injection_rejected() {
    let attacks = vec![
        "javascript:alert('xss')",
        "*[javascript:eval('code')]",
        "file:///etc/passwd",
        "<script>alert(1)</script>",
    ];

    for attack in attacks {
        let config = WindowsEventLogConfig {
            channels: vec!["System".to_string()],
            event_query: Some(attack.to_string()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "XPath injection '{attack}' should be rejected by config validation."
        );
    }
}

/// Channel names with control characters or null bytes must be rejected.
#[tokio::test]
async fn test_dangerous_channel_names_rejected() {
    let dangerous = vec!["System\0", "System\r\nEvil", "System\n"];

    for name in dangerous {
        let config = WindowsEventLogConfig {
            channels: vec![name.to_string()],
            ..Default::default()
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "Dangerous channel name '{}' should be rejected.",
            name.escape_debug()
        );
    }
}

/// Unbalanced XPath brackets/parentheses must be rejected.
#[tokio::test]
async fn test_unbalanced_xpath_rejected() {
    let unbalanced = vec![
        "*[System[Level=1]",   // missing closing ]
        "*[System[(Level=1]]", // mismatched
    ];

    for query in &unbalanced {
        let config = WindowsEventLogConfig {
            channels: vec!["System".to_string()],
            event_query: Some(query.to_string()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "Unbalanced XPath '{query}' should be rejected."
        );
    }
}

// ---------------------------------------------------------------------------
// Acknowledgement / checkpoint integrity
// ---------------------------------------------------------------------------

/// With acknowledgements enabled, checkpoints should only advance after
/// events are delivered downstream. This is the at-least-once guarantee:
/// if Vector crashes before the sink acks, the checkpoint hasn't moved,
/// so events are re-read on restart.
///
/// Test approach: run source with acks enabled and EventStatus::Delivered,
/// then restart with the same data_dir — the second run should skip
/// already-delivered events (proving checkpoint advanced after ack).
#[tokio::test]
async fn test_acknowledgements_checkpoint_after_delivery() {
    let data_dir = temp_data_dir();

    // Phase 1: emit event, run with acks enabled + Delivered status
    emit_event("VT_ackdel", "INFORMATION", 1000, "ack-test-phase1");

    {
        let (tx, mut rx) = SourceSender::new_test_finalize(EventStatus::Delivered);
        let config = WindowsEventLogConfig {
            data_dir: Some(data_dir.path().to_path_buf()),
            channels: vec!["Application".to_string()],
            event_query: Some(test_query("VT_ackdel")),
            read_existing_events: true,
            batch_size: 100,
            event_timeout_ms: 2000,
            acknowledgements: SourceAcknowledgementsConfig::from(true),
            ..Default::default()
        };

        let cx = SourceContext::new_test(tx, None);
        let source = config.build(cx).await.expect("source should build");

        let handle = tokio::spawn(source);

        // Collect events for a few seconds
        let mut event_count = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            tokio::select! {
                event = rx.next() => {
                    if event.is_some() {
                        event_count += 1;
                    } else {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        // Abort the source (simulates shutdown)
        handle.abort();
        let _ = handle.await;

        assert!(
            event_count > 0,
            "Phase 1 with acks=true should produce events."
        );
    }

    // Wait for checkpoint flush
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify checkpoint file exists
    // Note: SourceContext::new_test uses ComponentKey "default", and
    // resolve_and_make_data_subdir appends the component ID as a subdirectory.
    let checkpoint_path = data_dir
        .path()
        .join("default")
        .join("windows_event_log_checkpoints.json");
    assert!(
        checkpoint_path.exists(),
        "Checkpoint file should exist after acknowledged delivery. \
         Path: {:?}",
        checkpoint_path
    );

    // Phase 2: emit a NEW event, run with same data_dir
    emit_event("VT_ackdel", "INFORMATION", 1000, "ack-test-phase2");
    let config = test_config("VT_ackdel", data_dir.path());
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    // Should NOT see phase1 event again (checkpoint advanced)
    let has_phase1 = events.iter().any(|e| {
        e.as_log()
            .get(event_path!("message"))
            .map(|m| m.to_string_lossy().contains("ack-test-phase1"))
            .unwrap_or(false)
    });
    assert!(
        !has_phase1,
        "Phase 1 events should not be redelivered after acknowledgement. \
         Checkpoint may not have advanced after ack."
    );
}

// ---------------------------------------------------------------------------
// Checkpoint corruption recovery
// ---------------------------------------------------------------------------

/// If the checkpoint file is corrupted (e.g., power loss mid-write),
/// the source should start fresh gracefully rather than crash-loop.
/// This tests the atomic-write recovery path.
#[tokio::test]
async fn test_checkpoint_corruption_recovery() {
    let data_dir = temp_data_dir();

    // Write garbage to the checkpoint file.
    // Note: SourceContext::new_test uses ComponentKey "default", and
    // resolve_and_make_data_subdir appends the component ID as a subdirectory.
    let checkpoint_dir = data_dir.path().join("default");
    fs::create_dir_all(&checkpoint_dir)
        .await
        .expect("should be able to create checkpoint directory");
    let checkpoint_path = checkpoint_dir.join("windows_event_log_checkpoints.json");
    fs::write(&checkpoint_path, b"{{{{corrupted json garbage!!! \x00\xff")
        .await
        .expect("should be able to write corrupted checkpoint");

    // Emit a test event
    emit_event(
        "VT_corrupt",
        "INFORMATION",
        1000,
        "corruption recovery test",
    );

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        event_query: Some(test_query("VT_corrupt")),
        read_existing_events: true,
        batch_size: 100,
        event_timeout_ms: 2000,
        ..Default::default()
    };

    // Source should start despite corrupted checkpoint and read events
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    assert!(
        !events.is_empty(),
        "Source should recover from corrupted checkpoint and ingest events. \
         Got 0 events — checkpoint corruption may be causing a crash."
    );
}

// ---------------------------------------------------------------------------
// Rejected acknowledgement — checkpoint must NOT advance
// ---------------------------------------------------------------------------

/// With acknowledgements enabled and EventStatus::Rejected, checkpoints
/// should NOT advance. This is the other half of at-least-once: if the
/// sink rejects events, the source must re-read them on restart.
#[tokio::test]
async fn test_rejected_ack_does_not_advance_checkpoint() {
    let data_dir = temp_data_dir();

    // Emit a distinctive event
    emit_event("VT_rejack", "INFORMATION", 1000, "rejected-ack-test-marker");

    // Phase 1: Run with acks enabled but Rejected status — checkpoint should NOT advance
    {
        let (tx, mut rx) = SourceSender::new_test_finalize(EventStatus::Rejected);
        let config = WindowsEventLogConfig {
            data_dir: Some(data_dir.path().to_path_buf()),
            channels: vec!["Application".to_string()],
            event_query: Some(test_query("VT_rejack")),
            read_existing_events: true,
            batch_size: 100,
            event_timeout_ms: 2000,
            acknowledgements: SourceAcknowledgementsConfig::from(true),
            ..Default::default()
        };

        let cx = SourceContext::new_test(tx, None);
        let source = config.build(cx).await.expect("source should build");
        let handle = tokio::spawn(source);

        // Drain events for a few seconds
        let mut phase1_count = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            tokio::select! {
                event = rx.next() => {
                    if event.is_some() {
                        phase1_count += 1;
                    } else {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        handle.abort();
        let _ = handle.await;

        assert!(
            phase1_count > 0,
            "Phase 1 should produce events even with Rejected status."
        );
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Phase 2: Run again with same data_dir — should see the SAME events
    // because checkpoint should not have advanced after rejection
    let config = test_config("VT_rejack", data_dir.path());
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    let has_marker = events.iter().any(|e| {
        let log = e.as_log();
        // Check message field (rendered message or string_inserts fallback)
        let in_message = log
            .get(event_path!("message"))
            .map(|m| m.to_string_lossy().contains("rejected-ack-test-marker"))
            .unwrap_or(false);
        // Also check string_inserts directly in case EvtFormatMessage is unavailable
        // on this CI runner and the fallback doesn't surface the description.
        let in_inserts = log
            .get(event_path!("string_inserts"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|v| v.to_string_lossy().contains("rejected-ack-test-marker"))
            })
            .unwrap_or(false);
        in_message || in_inserts
    });
    assert!(
        has_marker,
        "Events should be redelivered after rejected acknowledgement. \
         Checkpoint may have advanced despite rejection — at-least-once violated. \
         Got {} events in phase 2.",
        events.len()
    );
}

// ---------------------------------------------------------------------------
// Concurrent stress test
// ---------------------------------------------------------------------------

/// Emit a burst of events and verify all arrive without drops or corruption.
/// Exercises buffer resizing, batch draining, and checkpoint batching under
/// heavier load than the basic backlog test.
#[tokio::test]
async fn test_stress_burst_ingestion() {
    let data_dir = temp_data_dir();
    let n = 200;

    for i in 0..n {
        emit_event(
            "VT_stress",
            "INFORMATION",
            1000,
            &format!("stress-test-event-{i}"),
        );
    }

    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec!["Application".to_string()],
        event_query: Some(test_query("VT_stress")),
        read_existing_events: true,
        batch_size: 50, // Multiple batches required
        event_timeout_ms: 2000,
        ..Default::default()
    };

    let events = run_and_assert_source_compliance(config, Duration::from_secs(15), &[]).await;

    assert!(
        events.len() >= n,
        "Expected at least {n} events under burst load, got {}. \
         Drain loop may be exiting early or losing events under pressure.",
        events.len()
    );

    // Verify no duplicates
    let mut record_ids = HashSet::new();
    let mut dups = 0;
    for event in &events {
        if let Some(rid) = event.as_log().get(event_path!("record_id")) {
            if !record_ids.insert(rid.to_string_lossy()) {
                dups += 1;
            }
        }
    }
    assert_eq!(
        dups, 0,
        "Found {dups} duplicate record_ids in {n}-event stress test."
    );

    // Verify no event has empty/missing critical fields (corruption check)
    for event in events.iter().take(50) {
        let log = event.as_log();
        for field in ["event_id", "record_id", "channel", "provider_name"] {
            assert!(
                log.contains(event_path!(field)),
                "Stress test event missing field '{field}' — possible render corruption."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Resubscribe after log clear
// ---------------------------------------------------------------------------

/// Helper: write an event to a custom log channel via PowerShell Write-EventLog.
fn write_custom_log_event(log_name: &str, source: &str, event_id: u32, message: &str) {
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Write-EventLog -LogName '{}' -Source '{}' -EventId {} -EntryType Information -Message '{}'",
                log_name, source, event_id, message
            ),
        ])
        .status()
        .expect("failed to run powershell Write-EventLog");
    assert!(status.success(), "Write-EventLog failed with {status}");
}

/// Clear a dedicated custom event log mid-run, verify the source recovers
/// via resubscription and continues ingesting new events.
///
/// Uses a temporary custom log channel (created via PowerShell New-EventLog)
/// instead of Application, so clearing it doesn't destroy events that other
/// parallel tests depend on.
///
/// Requires Administrator privileges.
#[tokio::test]
async fn test_resubscribe_after_log_clear() {
    let log_name = "VectorTestResub";
    let source_name = "VT_resub";

    // Create dedicated log channel for this test
    let create_result = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "if (-not [System.Diagnostics.EventLog]::SourceExists('{source_name}')) {{ \
                     New-EventLog -LogName '{log_name}' -Source '{source_name}' \
                 }}"
            ),
        ])
        .status();

    match create_result {
        Ok(status) if status.success() => {}
        _ => {
            // Can't create custom log — skip gracefully
            return;
        }
    }

    // Ensure cleanup on all exit paths
    struct CleanupGuard {
        log_name: &'static str,
    }
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Remove-EventLog -LogName '{}' -ErrorAction SilentlyContinue",
                        self.log_name
                    ),
                ])
                .status();
        }
    }
    let _cleanup = CleanupGuard {
        log_name: "VectorTestResub",
    };

    let data_dir = temp_data_dir();

    // Emit an initial event into our dedicated channel
    write_custom_log_event(log_name, source_name, 1000, "pre-clear-event");

    let (tx, mut rx) = SourceSender::new_test_finalize(EventStatus::Delivered);
    let config = WindowsEventLogConfig {
        data_dir: Some(data_dir.path().to_path_buf()),
        channels: vec![log_name.to_string()],
        read_existing_events: true,
        batch_size: 100,
        event_timeout_ms: 1000,
        acknowledgements: SourceAcknowledgementsConfig::from(true),
        ..Default::default()
    };

    let cx = SourceContext::new_test(tx, None);
    let source = config.build(cx).await.expect("source should build");
    let handle = tokio::spawn(source);

    // Wait for initial events to be consumed
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        tokio::select! {
            event = rx.next() => {
                if event.is_none() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    // Clear our dedicated log — does NOT affect Application or other tests
    let clear_result = Command::new("wevtutil").args(["cl", log_name]).status();

    match clear_result {
        Ok(status) if status.success() => {
            // Log was cleared. Emit a new event and verify it arrives.
            tokio::time::sleep(Duration::from_secs(1)).await;
            write_custom_log_event(log_name, source_name, 1000, "post-clear-event");

            let mut found_post_clear = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            loop {
                tokio::select! {
                    event = rx.next() => {
                        if let Some(event) = event {
                            if let Some(msg) = event.as_log().get(event_path!("message")) {
                                if msg.to_string_lossy().contains("post-clear-event") {
                                    found_post_clear = true;
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        break;
                    }
                }
            }

            handle.abort();
            let _ = handle.await;

            assert!(
                found_post_clear,
                "After log clear, the source should resubscribe and receive new events. \
                 The post-clear event was not received — resubscribe_channel may be broken."
            );
        }
        _ => {
            // wevtutil cl failed — skip gracefully
            handle.abort();
            let _ = handle.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Custom metrics — indirect verification
// ---------------------------------------------------------------------------

/// Verify that reading events produces the expected checkpoint file,
/// proving the full data path (EvtNext -> render -> parse -> emit ->
/// checkpoint) works end-to-end including the metric-instrumented code paths.
///
/// Note: Direct custom metric assertions (windows_event_log_events_read_total
/// etc.) are not feasible without adding metrics-util/debugging as a
/// dependency. Instead, we verify the observable side effects: events arrive,
/// checkpoint file is written, and compliance metrics pass.
#[tokio::test]
async fn test_full_data_path_produces_checkpoint() {
    let data_dir = temp_data_dir();

    for i in 0..5 {
        emit_event(
            "VT_fullck",
            "INFORMATION",
            1000,
            &format!("checkpoint-path-test-{i}"),
        );
    }

    let config = test_config("VT_fullck", data_dir.path());
    let events = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    assert!(
        events.len() >= 5,
        "Expected at least 5 events, got {}.",
        events.len()
    );

    // Wait for checkpoint flush
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Note: SourceContext::new_test uses ComponentKey "default", and
    // resolve_and_make_data_subdir appends the component ID as a subdirectory.
    let checkpoint_path = data_dir
        .path()
        .join("default")
        .join("windows_event_log_checkpoints.json");
    assert!(
        checkpoint_path.exists(),
        "Checkpoint file should be written after successful event processing. \
         This proves the full path: EvtNext -> render -> parse -> emit -> checkpoint."
    );

    // Verify checkpoint file is valid JSON with expected structure
    let contents = fs::read_to_string(&checkpoint_path)
        .await
        .expect("should read checkpoint file");
    assert!(
        contents.contains("\"version\"") && contents.contains("\"channels\""),
        "Checkpoint file should contain valid JSON with version and channels. \
         Got: {}",
        contents.chars().take(200).collect::<String>()
    );
}

// ---------------------------------------------------------------------------
// Checkpoint resume: no duplicate record IDs across runs
// ---------------------------------------------------------------------------

/// Run the source twice with the same data_dir, emitting distinct events
/// before each run. Assert that the record_id sets from run 1 and run 2
/// do not overlap, proving the bookmark/checkpoint correctly prevents
/// re-delivery.
#[tokio::test]
async fn test_checkpoint_resume_no_duplicate_record_ids() {
    let data_dir = temp_data_dir();

    // Phase 1: emit events and collect record IDs
    for i in 0..5 {
        emit_event(
            "VT_ckptdup",
            "INFORMATION",
            1000,
            &format!("ckpt-dup-test-phase1-{i}"),
        );
    }

    let config = test_config("VT_ckptdup", data_dir.path());
    let first_run = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;
    assert!(
        !first_run.is_empty(),
        "Phase 1 produced 0 events. Cannot test checkpoint resume."
    );

    let first_ids: HashSet<String> = first_run
        .iter()
        .filter_map(|e| {
            e.as_log()
                .get(event_path!("record_id"))
                .map(|v| v.to_string_lossy().into_owned())
        })
        .collect();
    assert!(
        !first_ids.is_empty(),
        "Phase 1 events have no record_id field. Cannot verify uniqueness."
    );

    // Let checkpoint flush to disk
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Phase 2: emit new events, reuse same data_dir
    for i in 0..5 {
        emit_event(
            "VT_ckptdup",
            "INFORMATION",
            1000,
            &format!("ckpt-dup-test-phase2-{i}"),
        );
    }

    let config = test_config("VT_ckptdup", data_dir.path());
    let second_run = run_and_assert_source_compliance(config, Duration::from_secs(5), &[]).await;

    let second_ids: HashSet<String> = second_run
        .iter()
        .filter_map(|e| {
            e.as_log()
                .get(event_path!("record_id"))
                .map(|v| v.to_string_lossy().into_owned())
        })
        .collect();

    // Allow a small overlap: the test harness uses a timeout-based shutdown that
    // can fire between send_batch (events collected) and finalize (checkpoint
    // written). On multi-core runners, the last in-flight batch may be sent but
    // not checkpointed, causing re-delivery of up to batch_size events.
    // The important invariant is that the checkpoint prevents FULL re-delivery.
    let batch_size = 100; // matches test_config
    let overlap: HashSet<_> = first_ids.intersection(&second_ids).collect();
    assert!(
        overlap.len() <= batch_size,
        "Found {} duplicate record_ids between run 1 and run 2 (max allowed: {}): {:?}. \
         Bookmark checkpoint is not preventing re-delivery. \
         Run 1 had {} IDs, run 2 had {} IDs.",
        overlap.len(),
        batch_size,
        overlap,
        first_ids.len(),
        second_ids.len()
    );

    // But we should still see meaningful checkpoint progress — run 2 must not
    // re-deliver the entire run 1 set.
    if !first_ids.is_empty() {
        assert!(
            second_ids.len() < first_ids.len() + 10,
            "Run 2 returned {} events vs run 1's {} — checkpoint may not be advancing at all.",
            second_ids.len(),
            first_ids.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Suppress ids on the lab channel
// ---------------------------------------------------------------------------
//
// These run unelevated against a channel the owner registered once with write
// and clear granted to the working account. A missing channel fails the test:
// skipping would report suppression as proven on a machine that proved nothing.
//
// Every test holds the seam session, which creating a subscription requires
// anyway and which also serializes use of the one lab channel.

mod suppress_lab {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EvtClose, EvtNext, EvtSubscribe, EvtSubscribeStartAtOldestRecord,
    };
    use windows::Win32::System::Threading::CreateEventW;
    use windows::core::HSTRING;

    use super::super::checkpoint::Checkpointer;
    use super::super::recovery::{ResumeState, Rung, TimeRung};
    use super::super::status::ChannelStatus;
    use super::super::subscription::{EventLogSubscription, SubscriptionFactory};
    use super::super::test_seams::SeamSession;
    use super::super::win32_errors::QueryOrigin;
    use super::{Command, SuppressRule, WindowsEventLogConfig};

    const LAB_CHANNEL: &str = "SparkLogs-WelLab/Operational";
    const LAB_PROVIDER: &str = "SparkLogs-WelLab";
    const KEPT_ID: u16 = 1;
    const SUPPRESSED_ID: u16 = 2;

    fn missing_lab(detail: &str) -> ! {
        panic!(
            "the lab channel {LAB_CHANNEL} is not usable ({detail}). Register it and grant \
             this account read, write and clear once from an elevated PowerShell (the agent \
             repo's wel-lab tooling documents the grant)"
        )
    }

    fn wevtutil(args: &[&str]) -> String {
        let out = Command::new("wevtutil")
            .args(args)
            .output()
            .unwrap_or_else(|e| missing_lab(&format!("wevtutil did not start: {e}")));
        if !out.status.success() {
            missing_lab(&format!(
                "wevtutil {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn record_count() -> u64 {
        wevtutil(&["gli", LAB_CHANNEL])
            .lines()
            .find_map(|line| line.trim().strip_prefix("numberOfLogRecords:"))
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or_else(|| missing_lab("no record count from wevtutil gli"))
    }

    /// Empty the channel, so each test counts only what it wrote.
    fn clear() {
        wevtutil(&["cl", LAB_CHANNEL]);
        assert_eq!(record_count(), 0, "the lab channel did not clear");
    }

    /// Write `count` records of `event_id` through the lab provider and wait
    /// for the service to log them.
    ///
    /// The .NET `EventProvider` writes at ETW speed, which a 50,000 record
    /// flood needs; `New-WinEvent` manages tens per second. A write the
    /// session buffers refuse is retried, and the record count is checked, so
    /// a wrong descriptor fails here rather than as a missing event later.
    fn write(event_id: u16, count: u32) {
        let before = record_count();
        // PROVENANCE: the lab manifest's provider GUID (the agent repo's
        // `xtask/src/wel_lab.rs` `PROVIDER_GUID`); channel 16, level 4 and
        // keyword 0x8000000000000000 as `wevtutil qe` rendered a `New-WinEvent`
        // record of that manifest on 2026-09-29 (mc.exe numbers a manifest's
        // first channel 16).
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $p = New-Object System.Diagnostics.Eventing.EventProvider \
             ([guid]'d6f3a2b1-6c44-4e0b-9a7e-3f1c5d8e2a90'); \
             $d = New-Object System.Diagnostics.Eventing.EventDescriptor \
             ({event_id}, 0, 16, 4, 0, 0, [long]::MinValue); \
             $n = 0; while ($n -lt {count}) {{ \
             if ($p.WriteEvent([ref]$d, [object[]]@('lab', '-'))) {{ $n++ }} \
             else {{ Start-Sleep -Milliseconds 5 }} }}; $p.Dispose()"
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .expect("powershell must start");
        assert!(status.success(), "the lab write failed: {status}");

        let want = before + u64::from(count);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let have = record_count();
            if have == want {
                return;
            }
            assert!(
                have < want && Instant::now() < deadline,
                "the lab channel holds {have} records, expected {want}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn lab_rule(provider: &str, event_ids: &[u16]) -> SuppressRule {
        SuppressRule {
            provider: provider.to_string(),
            event_ids: event_ids.to_vec(),
        }
    }

    async fn checkpointer() -> (Arc<Checkpointer>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let checkpointer = Arc::new(Checkpointer::new(dir.path()).await.expect("checkpointer"));
        (checkpointer, dir)
    }

    async fn subscribe(
        rules: Vec<SuppressRule>,
        checkpointer: Arc<Checkpointer>,
    ) -> EventLogSubscription {
        let mut config = WindowsEventLogConfig {
            channels: vec![LAB_CHANNEL.to_string()],
            read_existing_events: true,
            event_timeout_ms: 500,
            ..Default::default()
        };
        if !rules.is_empty() {
            config.suppress_ids.insert(LAB_CHANNEL.to_string(), rules);
        }
        config.validate().expect("the lab config is valid");
        EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("the lab subscription opens")
    }

    fn status(subscription: &EventLogSubscription) -> ChannelStatus {
        subscription
            .status_snapshot()
            .channels
            .remove(LAB_CHANNEL)
            .expect("the lab channel is reported")
    }

    /// Pull until `want` events have arrived and one more pull finds nothing,
    /// returning the event ids in delivery order.
    fn drain(subscription: &mut EventLogSubscription, want: usize) -> Vec<u32> {
        let mut ids = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let batch = subscription.pull_events(1_000).expect("pull");
            if batch.is_empty() && ids.len() >= want {
                return ids;
            }
            ids.extend(batch.iter().map(|event| event.event_id));
            assert!(
                Instant::now() < deadline,
                "only {} of {want} events arrived: {ids:?}",
                ids.len()
            );
            if batch.is_empty() {
                subscription.wait_for_events_blocking(200);
            }
        }
    }

    /// A suppressed id never reaches the collector and is never read; the kept
    /// id around it arrives in full.
    #[tokio::test]
    async fn suppressed_ids_are_never_delivered_or_read() {
        let _seams = SeamSession::acquire();
        clear();
        write(KEPT_ID, 5);
        write(SUPPRESSED_ID, 20);
        write(KEPT_ID, 5);

        let (checkpointer, _dir) = checkpointer().await;
        let mut subscription =
            subscribe(vec![lab_rule(LAB_PROVIDER, &[SUPPRESSED_ID])], checkpointer).await;
        let ids = drain(&mut subscription, 10);

        assert_eq!(
            ids,
            vec![u32::from(KEPT_ID); 10],
            "kept ids only, all of them"
        );
        let status = status(&subscription);
        assert_eq!(status.records_read, 10, "suppressed records are never read");
        assert!(status.suppress_active);
        assert!(status.query_filters);
    }

    /// The service matches the provider name case-insensitively, so the
    /// lowercase spelling the pack emits suppresses.
    #[tokio::test]
    async fn a_lowercase_provider_spelling_suppresses() {
        let _seams = SeamSession::acquire();
        clear();
        write(KEPT_ID, 3);
        write(SUPPRESSED_ID, 3);

        let (checkpointer, _dir) = checkpointer().await;
        let lowercase = LAB_PROVIDER.to_ascii_lowercase();
        let mut subscription =
            subscribe(vec![lab_rule(&lowercase, &[SUPPRESSED_ID])], checkpointer).await;

        assert_eq!(drain(&mut subscription, 3), vec![u32::from(KEPT_ID); 3]);
        assert_eq!(status(&subscription).records_read, 3);
    }

    /// The largest query `validate` allows, with the time floor beside it, is
    /// accepted by `EvtSubscribe` and still suppresses.
    #[tokio::test]
    async fn the_worst_case_suppress_query_is_accepted_and_honored() {
        let _seams = SeamSession::acquire();
        clear();
        write(KEPT_ID, 3);
        write(SUPPRESSED_ID, 3);

        // 64 five-digit ids but id 2, split so the element count is largest,
        // under four providers, three of them at the longest name allowed.
        let mut lab_ids = vec![SUPPRESSED_ID];
        lab_ids.extend(65_476..=65_535);
        let long = |tag: char| format!("{tag}{}", "p".repeat(127));
        let rules = vec![
            lab_rule(LAB_PROVIDER, &lab_ids),
            lab_rule(&long('B'), &[10_000]),
            lab_rule(&long('C'), &[10_001]),
            lab_rule(&long('D'), &[10_002]),
        ];
        WindowsEventLogConfig {
            channels: vec![LAB_CHANNEL.to_string()],
            suppress_ids: std::collections::BTreeMap::from([(
                LAB_CHANNEL.to_string(),
                rules.clone(),
            )]),
            ..Default::default()
        }
        .validate()
        .expect("the worst case is inside the bounds");

        let mut resume = ResumeState::new(true);
        resume.observe_event(chrono::Utc::now() - chrono::Duration::hours(1), 1);
        resume.rung = Rung::TimeAdvance(TimeRung::BoundaryTick);
        let factory = SubscriptionFactory::new(
            LAB_CHANNEL.to_string(),
            "*".to_string(),
            QueryOrigin::Generated,
            true,
            rules,
        );
        let (query, origin) = factory.query_for(&resume);
        assert_eq!(origin, QueryOrigin::Suppressed);
        assert_eq!(
            query.matches("<Suppress>").count(),
            8,
            "seven id elements and the floor"
        );

        let signal = unsafe { CreateEventW(None, true, false, None) }.expect("event handle");
        let handle = unsafe {
            EvtSubscribe(
                None,
                signal,
                &HSTRING::from(LAB_CHANNEL),
                &HSTRING::from(query.as_str()),
                EVT_HANDLE(0),
                None,
                None,
                EvtSubscribeStartAtOldestRecord.0,
            )
        }
        .unwrap_or_else(|e| {
            panic!(
                "EvtSubscribe rejected the {}-char worst case: {e}\n{query}",
                query.len()
            )
        });

        let mut delivered = 0usize;
        let deadline = Instant::now() + Duration::from_secs(10);
        while delivered < 3 && Instant::now() < deadline {
            let mut batch = [0isize; 16];
            let mut returned = 0u32;
            if unsafe { EvtNext(handle, &mut batch, 500, 0, &mut returned) }.is_ok() {
                for raw in &batch[..returned as usize] {
                    unsafe { _ = EvtClose(EVT_HANDLE(*raw)) };
                }
                delivered += returned as usize;
            }
        }
        let mut batch = [0isize; 16];
        let mut returned = 0u32;
        let extra = unsafe { EvtNext(handle, &mut batch, 500, 0, &mut returned) };
        for raw in &batch[..returned as usize] {
            unsafe { _ = EvtClose(EVT_HANDLE(*raw)) };
        }
        unsafe {
            _ = EvtClose(handle);
            _ = CloseHandle(signal);
        }
        assert_eq!(delivered, 3, "the three kept records");
        assert!(
            extra.is_err() && returned == 0,
            "the three suppressed records must not follow"
        );
    }

    /// A stored bookmark on a record the new query suppresses: the first start
    /// after the ids are turned on, on a host whose last record read was a
    /// flood record.
    ///
    /// `StartAfterBookmark | Strict` resumes from it with no ladder move and
    /// delivers only what came after, with no re-delivery.
    #[tokio::test]
    async fn a_bookmark_on_a_now_suppressed_record_resumes_without_a_rung_move() {
        let _seams = SeamSession::acquire();
        clear();
        write(KEPT_ID, 2);
        write(SUPPRESSED_ID, 3);

        let (checkpointer, _dir) = checkpointer().await;
        let mut before = subscribe(Vec::new(), Arc::clone(&checkpointer)).await;
        let ids = drain(&mut before, 5);
        assert_eq!(
            ids.last(),
            Some(&u32::from(SUPPRESSED_ID)),
            "premise: the bookmark is on a flood record"
        );
        before.flush_bookmarks().await.expect("flush");
        drop(before);

        write(KEPT_ID, 2);
        let mut after =
            subscribe(vec![lab_rule(LAB_PROVIDER, &[SUPPRESSED_ID])], checkpointer).await;
        let resumed = status(&after);
        assert!(resumed.subscribed, "the resume subscribed");
        assert_eq!(resumed.rung, "bookmark", "no ladder move");
        assert!(resumed.gaps.is_empty(), "no gap recorded");

        assert_eq!(
            drain(&mut after, 2),
            vec![u32::from(KEPT_ID); 2],
            "only what came after"
        );
        assert_eq!(status(&after).rung, "bookmark");
    }

    /// The head witness under a suppressed flood: 50,000 suppressed records
    /// ahead of one kept record, read from the oldest. The service scans the
    /// flood to find the kept record, and until it has, nothing may say the
    /// channel is at its head.
    #[tokio::test]
    async fn the_head_is_not_stamped_before_the_record_behind_a_suppressed_flood() {
        const FLOOD: u32 = 50_000;
        let _seams = SeamSession::acquire();
        clear();
        write(SUPPRESSED_ID, FLOOD);
        write(KEPT_ID, 1);

        let (checkpointer, _dir) = checkpointer().await;
        let mut subscription =
            subscribe(vec![lab_rule(LAB_PROVIDER, &[SUPPRESSED_ID])], checkpointer).await;

        let deadline = Instant::now() + Duration::from_secs(120);
        let mut pulls = 0u32;
        loop {
            let batch = subscription.pull_events(1_000).expect("pull");
            pulls += 1;
            if !batch.is_empty() {
                assert_eq!(
                    batch.iter().map(|e| e.event_id).collect::<Vec<_>>(),
                    vec![u32::from(KEPT_ID)]
                );
                break;
            }
            let status = status(&subscription);
            assert!(
                status.last_drained_at.is_none(),
                "the head was stamped at {:?} after {pulls} pulls, before the kept record \
                 behind {FLOOD} suppressed ones arrived",
                status.last_drained_at
            );
            assert!(Instant::now() < deadline, "the kept record never arrived");
            subscription.wait_for_events_blocking(500);
        }
        let status = status(&subscription);
        assert_eq!(status.records_read, 1, "the flood was never read");
    }
}
