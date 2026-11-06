//! Event rendering and channel statistics helpers for Windows Event Log.
//!
//! Extracted from `subscription.rs` to keep that module focused on
//! subscription lifecycle and event pulling.

use metrics::Gauge;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_LOG_PROPERTY_ID, EvtClose, EvtGetLogInfo, EvtLogNumberOfLogRecords, EvtNext,
    EvtOpenLog, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EvtVarTypeUInt64,
};
use windows::core::{HSTRING, w};

use super::error::WindowsEventLogError;
use super::win32_errors::{RenderDisposition, classify_render, win32_code};
use super::xml_parser;

/// Test-only rewrite of the rendered XML, applied to the string this function
/// is about to return.
///
/// This supplies an INPUT, not a decision. Everything downstream that cares
/// about `<RenderingInfo>` derives it by parsing this XML, so injecting an
/// event whose XML carries the element exercises the real derivation. A WEC
/// forwarding pair is the only way to obtain such an event from the API, and
/// setting the derived flag directly would assert the seam instead.
///
/// Returning `None` fails this one render, so a test can place a render
/// failure at a chosen record rather than failing every render.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(super) static RENDER_XML_REWRITE: std::sync::Mutex<
    Option<std::sync::Arc<dyn Fn(String) -> Option<String> + Send + Sync>>,
> = std::sync::Mutex::new(None);

/// Apply the test-only rewrite, if one is installed.
#[cfg(test)]
fn rewrite_xml(xml: String) -> Result<String, WindowsEventLogError> {
    let rewrite = RENDER_XML_REWRITE.lock().unwrap().clone();
    match rewrite {
        Some(f) => f(xml).ok_or_else(|| WindowsEventLogError::ReadEventError {
            source: windows::core::Error::from_hresult(windows::core::HRESULT(13)),
        }),
        None => Ok(xml),
    }
}

#[cfg(not(test))]
const fn rewrite_xml(xml: String) -> Result<String, WindowsEventLogError> {
    Ok(xml)
}

/// Render an event handle to XML using reusable buffers.
pub(super) fn render_event_xml(
    render_buffer: &mut Vec<u8>,
    decode_buffer: &mut Vec<u16>,
    event_handle: EVT_HANDLE,
) -> Result<String, WindowsEventLogError> {
    const MAX_BUFFER_SIZE: u32 = 10 * 1024 * 1024; // 10MB limit

    // Test-only fault injection for the unprocessable-event path. A real
    // malformed event is not producible on demand, and the behavior under test
    // (skip the event, keep the subscription, advance past it) is exactly what
    // must not be asserted from the implementation.
    #[cfg(test)]
    if super::subscription::FAIL_ALL_RENDERS.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(WindowsEventLogError::ReadEventError {
            source: windows::core::Error::from_hresult(windows::core::HRESULT(13)),
        });
    }

    let buffer_size = render_buffer.len() as u32;
    let mut buffer_used = 0u32;
    let mut property_count = 0u32;

    let result = unsafe {
        EvtRender(
            None,
            event_handle,
            EvtRenderEventXml.0,
            buffer_size,
            Some(render_buffer.as_mut_ptr() as *mut std::ffi::c_void),
            &mut buffer_used,
            &mut property_count,
        )
    };

    if let Err(e) = result {
        // Classified on the render path, whose disposition type has no
        // subscription-rebuild arm at all. ERROR_INSUFFICIENT_BUFFER is routine
        // here on every size probe; routing it anywhere near the drain
        // classifier would tear down subscriptions on normal buffer growth.
        if classify_render(win32_code(&e)) == RenderDisposition::GrowBuffer {
            if buffer_used == 0 {
                return Ok(String::new());
            }
            if buffer_used > MAX_BUFFER_SIZE {
                return Err(WindowsEventLogError::ReadEventError { source: e });
            }

            // Grow the reusable buffer
            render_buffer.resize(buffer_used as usize, 0);
            let mut second_buffer_used = 0u32;
            let mut second_property_count = 0u32;

            unsafe {
                EvtRender(
                    None,
                    event_handle,
                    EvtRenderEventXml.0,
                    buffer_used,
                    Some(render_buffer.as_mut_ptr() as *mut std::ffi::c_void),
                    &mut second_buffer_used,
                    &mut second_property_count,
                )
            }
            .map_err(|e2| WindowsEventLogError::ReadEventError { source: e2 })?;

            let result = decode_utf16_buffer(render_buffer, second_buffer_used, decode_buffer);

            // Shrink if buffer grew very large (match normal-path threshold)
            const SHRINK_THRESHOLD: usize = 64 * 1024;
            if render_buffer.len() > SHRINK_THRESHOLD {
                render_buffer.resize(SHRINK_THRESHOLD, 0);
                render_buffer.shrink_to_fit();
            }
            shrink_decode_buffer(decode_buffer);

            return rewrite_xml(result);
        }
        return Err(WindowsEventLogError::ReadEventError { source: e });
    }

    let result = decode_utf16_buffer(render_buffer, buffer_used, decode_buffer);

    // Shrink the buffer back down if a large event caused it to grow.
    // 64 KB covers the vast majority of events without repeated reallocation.
    const SHRINK_THRESHOLD: usize = 64 * 1024;
    if render_buffer.len() > SHRINK_THRESHOLD {
        render_buffer.resize(SHRINK_THRESHOLD, 0);
        render_buffer.shrink_to_fit();
    }
    shrink_decode_buffer(decode_buffer);

    rewrite_xml(result)
}

/// Decoded UTF-16 scratch: its resting size, and the size past which an outsized
/// event has to give the memory back.
///
/// The buffer only ever grows. It is resized to whatever the largest event so
/// far needed and never handed back, so one 2 MB event pins 4 MB of scratch per
/// source for the life of the process. That is the cost being removed.
///
/// Both numbers are RULED, not derived: rest at 16 KiB, shrink above 256 KiB.
/// They are written in `u16` elements because that is what this buffer holds, so
/// 8 K elements is the 16 KiB rest and 128 K elements is the 256 KiB ceiling.
/// The ratio to the render buffer's own 64 KiB threshold is a consequence of
/// those two numbers, not a reason for them.
const DECODE_BUFFER_AT_REST: usize = 8 * 1024;
const DECODE_SHRINK_THRESHOLD: usize = 128 * 1024;

/// Return the decode scratch to its resting size after an outsized event.
fn shrink_decode_buffer(decode_buffer: &mut Vec<u16>) {
    if decode_buffer.len() > DECODE_SHRINK_THRESHOLD {
        decode_buffer.resize(DECODE_BUFFER_AT_REST, 0);
        decode_buffer.shrink_to_fit();
    }
}

/// Test-only count of `update_channel_records` calls.
///
/// The whole point of the speculative-pull flag is to avoid steady
/// `EvtOpenLog`/`EvtGetLogInfo` churn on an idle host, so "was the metadata
/// query issued" IS the contract, and a gauge write is not observable.
#[cfg(test)]
pub(super) static CHANNEL_RECORDS_UPDATES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Test-only answers for [`dormancy_record_count`], one per read, in order.
/// `None` in the queue is a read that failed. An exhausted queue reads the real
/// channel.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(super) static RECORD_COUNT_SCRIPT: std::sync::Mutex<
    Option<std::collections::VecDeque<Option<u64>>>,
> = std::sync::Mutex::new(None);

/// Test-only count of [`dormancy_record_count`] calls, the observable for "a
/// channel with records is never checked again".
#[cfg(test)]
pub(super) static DORMANCY_CHECKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Reports total records in the channel. SOC teams compare this against
/// `rate(events_read_total)` to detect ingestion lag.
/// Best-effort: if the read fails, the gauge is left unchanged.
pub(super) fn update_channel_records(channel: &str, gauge: &Gauge) {
    #[cfg(test)]
    CHANNEL_RECORDS_UPDATES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    if let Some(record_count) = channel_record_count(channel) {
        gauge.set(record_count as f64);
    }
}

/// The read a channel's dormancy turns on. See [`channel_record_count`].
pub(super) fn dormancy_record_count(channel: &str) -> Option<u64> {
    #[cfg(test)]
    {
        DORMANCY_CHECKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let scripted = RECORD_COUNT_SCRIPT
            .lock()
            .unwrap()
            .as_mut()
            .and_then(std::collections::VecDeque::pop_front);
        if let Some(count) = scripted {
            return count;
        }
    }
    channel_record_count(channel)
}

/// Records the channel holds, or `None` when that cannot be read.
///
/// Moves the moment a record lands, on a fresh handle or a cached one. A full,
/// wrapping log keeps a constant count, so it says nothing about a channel's
/// progress, only about whether the channel holds anything at all.
fn channel_record_count(channel: &str) -> Option<u64> {
    let channel_hstring = HSTRING::from(channel);
    let log_handle = unsafe {
        // EvtOpenChannelPath = 1
        EvtOpenLog(None, &channel_hstring, 1).ok()?
    };

    // EVT_VARIANT is 16 bytes: 8 bytes value + 4 bytes count + 4 bytes type
    let mut buffer = [0u8; 16];
    let mut buffer_used = 0u32;

    let result = unsafe {
        EvtGetLogInfo(
            log_handle,
            EVT_LOG_PROPERTY_ID(EvtLogNumberOfLogRecords.0),
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut buffer_used,
        )
    };

    unsafe {
        _ = EvtClose(log_handle);
    }

    result.ok()?;
    record_count_from_variant(&buffer)
}

/// The count out of a raw `EVT_VARIANT`: 8 bytes of value, a 4 byte count, a 4
/// byte type. A variant of any other type carries no count, and its zeroed
/// value must not read as an empty channel.
fn record_count_from_variant(variant: &[u8; 16]) -> Option<u64> {
    let (value, rest) = variant.split_first_chunk::<8>()?;
    let variant_type = u32::from_le_bytes(*rest.last_chunk::<4>()?);
    (variant_type == EvtVarTypeUInt64.0 as u32).then(|| u64::from_le_bytes(*value))
}

/// Longest `EvtNext` wait for the newest record. The caller holds the
/// subscription's blocking thread, so a stalled read must not hold it longer.
const NEWEST_RECORD_TIMEOUT_MS: u32 = 1_000;

/// `EventRecordID` of the newest record in a channel, read off that record.
///
/// One reverse-direction query, one `EvtNext` for a single handle, then the
/// render and System parse the drain uses. Every handle opened here is closed
/// before returning.
///
/// `None` when the channel is empty or any step fails, including a channel
/// that refuses a reverse read (analytic and debug logs).
pub(super) fn newest_record_id(channel: &str) -> Option<u64> {
    let channel_hstring = HSTRING::from(channel);
    let query = unsafe {
        EvtQuery(
            None,
            &channel_hstring,
            w!("*"),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }
    .ok()?;

    let mut handles = [0isize; 1];
    let mut returned = 0u32;
    let next = unsafe {
        EvtNext(
            query,
            &mut handles,
            NEWEST_RECORD_TIMEOUT_MS,
            0,
            &mut returned,
        )
    };
    let returned = (returned as usize).min(handles.len());

    let newest = if next.is_ok() && returned == 1 {
        // Both buffers are sized by the first render.
        let (mut render_buffer, mut decode_buffer) = (Vec::new(), Vec::new());
        render_event_xml(
            &mut render_buffer,
            &mut decode_buffer,
            EVT_HANDLE(handles[0]),
        )
        .ok()
        .map(|xml| xml_parser::parse_system_section(&xml).record_id)
        .filter(|&id| id != 0)
    } else {
        None
    };

    // `EvtNext` can fail with a handle already populated.
    for &raw in &handles[..returned] {
        if raw != 0 {
            unsafe {
                _ = EvtClose(EVT_HANDLE(raw));
            }
        }
    }
    unsafe {
        _ = EvtClose(query);
    }
    newest
}

/// Decode a UTF-16LE buffer (as returned by Windows EvtRender) into a String.
///
/// Uses a reusable `Vec<u16>` decode buffer to avoid per-event heap allocations.
/// Copies byte pairs into the properly-aligned buffer instead of casting the
/// pointer, which would be undefined behavior when the source buffer is not
/// 2-byte aligned.
fn decode_utf16_buffer(buffer: &[u8], bytes_used: u32, decode_buf: &mut Vec<u16>) -> String {
    if bytes_used == 0 || bytes_used as usize > buffer.len() {
        return String::new();
    }
    if bytes_used < 2 || !bytes_used.is_multiple_of(2) {
        return String::new();
    }

    let u16_len = bytes_used as usize / 2;
    decode_buf.resize(u16_len, 0);
    for i in 0..u16_len {
        decode_buf[i] = u16::from_le_bytes([buffer[i * 2], buffer[i * 2 + 1]]);
    }

    // Strip trailing null terminator
    let xml_len = if !decode_buf.is_empty() && decode_buf[u16_len - 1] == 0 {
        u16_len - 1
    } else {
        u16_len
    };

    if xml_len == 0 {
        return String::new();
    }

    String::from_utf16_lossy(&decode_buf[..xml_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant(value: u64, variant_type: u32) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes[12..].copy_from_slice(&variant_type.to_le_bytes());
        bytes
    }

    /// Dormancy turns on this read being exactly zero, so a variant that is not
    /// a count, whose value bytes are zero, has to read as no answer.
    #[test]
    fn only_a_uint64_variant_is_a_record_count() {
        const UINT64: u32 = 10;
        const NULL: u32 = 0;
        assert_eq!(record_count_from_variant(&variant(0, UINT64)), Some(0));
        assert_eq!(record_count_from_variant(&variant(7, UINT64)), Some(7));
        assert_eq!(record_count_from_variant(&variant(0, NULL)), None);
    }
}
