use std::collections::HashMap;
use std::num::NonZeroUsize;

use lru::LruCache;
use metrics::Counter;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtFormatMessage, EvtFormatMessageEvent, EvtFormatMessageKeyword,
    EvtFormatMessageOpcode, EvtFormatMessageTask, EvtOpenPublisherMetadata,
};
use windows::core::HSTRING;

use super::rendering_info;
use super::subscription::{FORMAT_CACHE_CAPACITY, PublisherHandle};
use super::win32_errors::{RenderDisposition, classify_render, win32_code};
use super::xml_parser::SystemFields;

/// Test-only accounting for the render path.
///
/// The `<RenderingInfo>` crash guard is a process-crash fix, so the merge gate
/// for it is a direct assertion that an event carrying `<RenderingInfo>` reaches
/// zero `EvtFormatMessage` calls. These counters are the seam that assertion
/// reads; they are `#[cfg(test)]` and compile out of shipped binaries.
#[cfg(test)]
pub(super) mod seam {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) static FORMAT_MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static PUBLISHER_PATH_ENTRIES: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn reset() {
        FORMAT_MESSAGE_CALLS.store(0, Ordering::SeqCst);
        PUBLISHER_PATH_ENTRIES.store(0, Ordering::SeqCst);
    }

    pub(crate) fn format_message_calls() -> usize {
        FORMAT_MESSAGE_CALLS.load(Ordering::SeqCst)
    }

    pub(crate) fn publisher_path_entries() -> usize {
        PUBLISHER_PATH_ENTRIES.load(Ordering::SeqCst)
    }
}

/// Record one `EvtFormatMessage` invocation for the test seam. No-op and
/// zero-cost in non-test builds.
#[inline]
fn note_format_message_call() {
    #[cfg(test)]
    seam::FORMAT_MESSAGE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Record one entry into the publisher-metadata render path for the test seam.
#[inline]
fn note_publisher_path_entry() {
    #[cfg(test)]
    seam::PUBLISHER_PATH_ENTRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Display fields for one event: task/opcode/keyword names plus the rendered
/// message, together with how they were obtained.
#[derive(Debug, Clone, Default)]
pub(super) struct EventDisplay {
    pub(super) task_name: Option<String>,
    pub(super) opcode_name: Option<String>,
    pub(super) keyword_names: Vec<String>,
    pub(super) rendered_message: Option<String>,
    /// True when the event XML carried `<RenderingInfo>`, meaning it was
    /// delivered as rendered text (Windows Event Forwarding). Two consequences:
    /// `EvtFormatMessage` was not called for this event, and this channel's
    /// record IDs are not trustworthy for gap detection.
    pub(super) rendered_delivery: bool,
}

/// Resolve an event's display fields.
///
/// This is the single decision point for the `<RenderingInfo>` crash guard: if
/// the event XML carries `<RenderingInfo>`, everything is parsed out of the XML
/// and no publisher API is touched at all. See [`super::rendering_info`] for
/// why that matters (`EvtFormatMessage` faults the process, it does not return
/// an error). Otherwise the normal publisher-metadata path runs.
pub(super) fn resolve_event_display(
    publisher_cache: &mut LruCache<String, PublisherHandle>,
    format_cache: &mut HashMap<String, LruCache<(u32, u64), Option<String>>>,
    cache_hits_counter: &Counter,
    cache_misses_counter: &Counter,
    event_handle: EVT_HANDLE,
    xml: &str,
    system_fields: &SystemFields,
    render_message: bool,
) -> EventDisplay {
    if let Some(info) = rendering_info::parse(xml) {
        return EventDisplay {
            task_name: info.task_name,
            opcode_name: info.opcode_name,
            keyword_names: info.keyword_names,
            rendered_message: if render_message { info.message } else { None },
            rendered_delivery: true,
        };
    }

    let provider_name = system_fields.provider_name.as_str();
    if provider_name.is_empty() {
        return EventDisplay::default();
    }

    note_publisher_path_entry();

    let (task_name, opcode_name, keyword_names) = resolve_event_metadata(
        publisher_cache,
        format_cache,
        cache_hits_counter,
        cache_misses_counter,
        event_handle,
        provider_name,
        system_fields.task as u64,
        system_fields.opcode as u64,
        system_fields.keywords,
    );

    let rendered_message = if render_message {
        format_event_message(publisher_cache, event_handle, provider_name)
    } else {
        None
    };

    EventDisplay {
        task_name,
        opcode_name,
        keyword_names,
        rendered_message,
        rendered_delivery: false,
    }
}

/// Whether an `EvtFormatMessage` result should be treated as producing usable
/// buffer contents.
///
/// The partial-render statuses (15029 / 15030 / 15031) mean the template
/// rendered but one or more inserts could not be resolved. Winlogbeat, Fluentd
/// and Fluent Bit all keep that text; discarding it loses the entire message
/// for the sake of one unresolved parameter.
fn render_result_usable(result: &windows::core::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(e) => classify_render(win32_code(e)) == RenderDisposition::UseBuffer,
    }
}

/// Resolves task, opcode, and keyword names from provider metadata via EvtFormatMessage.
pub fn resolve_event_metadata(
    publisher_cache: &mut LruCache<String, PublisherHandle>,
    format_cache: &mut HashMap<String, LruCache<(u32, u64), Option<String>>>,
    cache_hits_counter: &Counter,
    cache_misses_counter: &Counter,
    event_handle: EVT_HANDLE,
    provider_name: &str,
    task: u64,
    opcode: u64,
    keywords: u64,
) -> (Option<String>, Option<String>, Vec<String>) {
    let raw_handle = get_or_open_publisher(publisher_cache, provider_name);

    if raw_handle == 0 {
        return (None, None, Vec::new());
    }

    let metadata_handle = EVT_HANDLE(raw_handle);

    let task_flag = EvtFormatMessageTask.0 as u32;
    let opcode_flag = EvtFormatMessageOpcode.0 as u32;
    let keyword_flag = EvtFormatMessageKeyword.0 as u32;

    let task_name = cached_format(
        format_cache,
        cache_hits_counter,
        cache_misses_counter,
        metadata_handle,
        event_handle,
        provider_name,
        task_flag,
        task,
    );
    let opcode_name = cached_format(
        format_cache,
        cache_hits_counter,
        cache_misses_counter,
        metadata_handle,
        event_handle,
        provider_name,
        opcode_flag,
        opcode,
    );
    let keyword_str = cached_format(
        format_cache,
        cache_hits_counter,
        cache_misses_counter,
        metadata_handle,
        event_handle,
        provider_name,
        keyword_flag,
        keywords,
    );

    let keyword_names = keyword_str
        .map(|s| {
            s.split(';')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect()
        })
        .unwrap_or_default();

    (task_name, opcode_name, keyword_names)
}

fn get_or_open_publisher(
    cache: &mut LruCache<String, PublisherHandle>,
    provider_name: &str,
) -> isize {
    if let Some(handle) = cache.get(provider_name) {
        return handle.0;
    }

    let provider_hstring = HSTRING::from(provider_name);
    let raw = unsafe {
        EvtOpenPublisherMetadata(None, &provider_hstring, None, 0, 0)
            .map(|h| h.0)
            .unwrap_or(0)
    };

    cache.put(provider_name.to_string(), PublisherHandle(raw));
    raw
}

/// Two-level cache lookup: outer HashMap keyed by `&str` (zero allocation),
/// inner LRU keyed by `(flag, field_value)`.
fn cached_format(
    cache: &mut HashMap<String, LruCache<(u32, u64), Option<String>>>,
    cache_hits_counter: &Counter,
    cache_misses_counter: &Counter,
    metadata_handle: EVT_HANDLE,
    event_handle: EVT_HANDLE,
    provider: &str,
    flag: u32,
    field_value: u64,
) -> Option<String> {
    let inner_key = (flag, field_value);

    // Fast path: borrowed &str lookup on outer HashMap — zero allocation.
    // peek() intentionally skips LRU promotion — get() requires &mut which
    // would need get_mut() on the outer HashMap. The put() on every miss
    // already handles insertion/promotion, so peek is correct here.
    if let Some(inner) = cache.get(provider) {
        if let Some(cached) = inner.peek(&inner_key) {
            cache_hits_counter.increment(1);
            return cached.clone();
        }
    }

    // Slow path: call API and populate cache
    cache_misses_counter.increment(1);
    let result = format_metadata_field(metadata_handle, event_handle, flag);
    let inner = cache
        .entry(provider.to_string())
        .or_insert_with(|| LruCache::new(NonZeroUsize::new(FORMAT_CACHE_CAPACITY).unwrap()));
    inner.put(inner_key, result.clone());
    result
}

fn format_metadata_field(
    metadata_handle: EVT_HANDLE,
    event_handle: EVT_HANDLE,
    flags: u32,
) -> Option<String> {
    let mut buffer_used: u32 = 0;
    note_format_message_call();
    let _ = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            0,
            None,
            flags,
            None,
            &mut buffer_used,
        )
    };

    if buffer_used == 0 || buffer_used > 4096 {
        return None;
    }

    let mut buffer = vec![0u16; buffer_used as usize];
    let mut actual_used: u32 = 0;
    note_format_message_call();
    let result = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            0,
            None,
            flags,
            Some(&mut buffer),
            &mut actual_used,
        )
    };

    // Partial renders keep their buffer; only a genuine failure discards it.
    if !render_result_usable(&result) {
        return None;
    }

    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let s = String::from_utf16_lossy(&buffer[..len]);
    if s.is_empty() { None } else { Some(s) }
}

/// Renders a human-readable event message using the Windows EvtFormatMessage API.
pub fn format_event_message(
    publisher_cache: &mut LruCache<String, PublisherHandle>,
    event_handle: EVT_HANDLE,
    provider_name: &str,
) -> Option<String> {
    let raw_handle = get_or_open_publisher(publisher_cache, provider_name);

    if raw_handle == 0 {
        return None;
    }

    let metadata_handle = EVT_HANDLE(raw_handle);
    let flags = EvtFormatMessageEvent.0 as u32;
    let max_size = 64 * 1024;

    let mut buffer_used: u32 = 0;
    note_format_message_call();
    let _ = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            0,
            None,
            flags,
            None,
            &mut buffer_used,
        )
    };

    if buffer_used == 0 || buffer_used as usize > max_size {
        return None;
    }

    let mut buffer = vec![0u16; buffer_used as usize];
    let mut actual_used: u32 = 0;
    note_format_message_call();
    let result = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            0,
            None,
            flags,
            Some(&mut buffer),
            &mut actual_used,
        )
    };

    // Partial renders keep their buffer; only a genuine failure discards it.
    if !render_result_usable(&result) {
        return None;
    }

    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let s = String::from_utf16_lossy(&buffer[..len]);
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::windows_event_log::xml_parser::parse_system_section;

    const FORWARDED_FIXTURE: &str = include_str!("testdata/forwarded_rendering_info.xml");
    const LOCAL_FIXTURE: &str = include_str!("testdata/local_no_rendering_info.xml");

    fn empty_caches() -> (
        LruCache<String, PublisherHandle>,
        HashMap<String, LruCache<(u32, u64), Option<String>>>,
    ) {
        (LruCache::new(NonZeroUsize::new(8).unwrap()), HashMap::new())
    }

    /// MERGE GATE for the `<RenderingInfo>` crash guard.
    ///
    /// `EvtFormatMessage` faults the process (0xc0000005) against an
    /// unreachable publisher, so this cannot be defended with error handling
    /// and must not ship on reasoning alone. An event carrying
    /// `<RenderingInfo>` must take the XML parse path and reach EXACTLY ZERO
    /// `EvtFormatMessage` calls, counted through the test seam. The event
    /// handle passed here is null on purpose: if the publisher path were ever
    /// taken, that would be visible as a nonzero counter rather than as a
    /// silent behavior change.
    #[test]
    #[serial_test::serial]
    fn rendering_info_event_makes_zero_evtformatmessage_calls() {
        seam::reset();

        let (mut publisher_cache, mut format_cache) = empty_caches();
        let hits = metrics::counter!("test_cache_hits");
        let misses = metrics::counter!("test_cache_misses");
        let system_fields = parse_system_section(FORWARDED_FIXTURE);
        assert!(
            !system_fields.provider_name.is_empty(),
            "fixture must name a provider, otherwise the publisher path is \
             skipped for an unrelated reason and the assertion proves nothing"
        );

        let display = resolve_event_display(
            &mut publisher_cache,
            &mut format_cache,
            &hits,
            &misses,
            EVT_HANDLE(0),
            FORWARDED_FIXTURE,
            &system_fields,
            true,
        );

        assert_eq!(
            seam::format_message_calls(),
            0,
            "an event carrying <RenderingInfo> must never reach EvtFormatMessage"
        );
        assert_eq!(
            seam::publisher_path_entries(),
            0,
            "an event carrying <RenderingInfo> must never open publisher metadata"
        );
        assert!(display.rendered_delivery);
        assert_eq!(
            display.rendered_message.as_deref(),
            Some("The Windows Firewall service entered the running state.")
        );
        assert_eq!(display.task_name.as_deref(), Some("Service state change"));
        assert_eq!(display.opcode_name.as_deref(), Some("Info"));
        assert_eq!(display.keyword_names, vec!["Classic".to_string()]);
    }

    /// Control for the gate above: the same event read locally has no
    /// `<RenderingInfo>`, so the publisher path is the correct one and the
    /// guard must not swallow it. Asserted on the routing decision rather than
    /// by calling into Win32 with a null event handle.
    #[test]
    fn local_event_routes_to_publisher_path() {
        assert!(
            rendering_info::parse(LOCAL_FIXTURE).is_none(),
            "a locally-read event must route to the publisher path"
        );
        assert!(
            rendering_info::parse(FORWARDED_FIXTURE).is_some(),
            "a forwarded rendered-text event must route to the parse path"
        );
    }

    /// `render_message = false` must suppress the message on the parse path
    /// exactly as it does on the publisher path, while still returning the
    /// task/opcode/keyword names.
    #[test]
    #[serial_test::serial]
    fn rendering_info_respects_render_message_disabled() {
        seam::reset();

        let (mut publisher_cache, mut format_cache) = empty_caches();
        let hits = metrics::counter!("test_cache_hits");
        let misses = metrics::counter!("test_cache_misses");
        let system_fields = parse_system_section(FORWARDED_FIXTURE);

        let display = resolve_event_display(
            &mut publisher_cache,
            &mut format_cache,
            &hits,
            &misses,
            EVT_HANDLE(0),
            FORWARDED_FIXTURE,
            &system_fields,
            false,
        );

        assert_eq!(seam::format_message_calls(), 0);
        assert!(display.rendered_message.is_none());
        assert_eq!(display.task_name.as_deref(), Some("Service state change"));
    }

    #[test]
    fn partial_render_statuses_keep_their_buffer() {
        // 15029 / 15030 / 15031 mean "template rendered, some inserts
        // unresolved". Winlogbeat, Fluentd and Fluent Bit all keep that text.
        for code in [15029u32, 15030, 15031] {
            assert_eq!(classify_render(code), RenderDisposition::UseBuffer);
        }
        // A real failure must still discard, and a buffer probe must not.
        assert_eq!(classify_render(2), RenderDisposition::DropEvent);
        assert_eq!(classify_render(122), RenderDisposition::GrowBuffer);
    }
}
