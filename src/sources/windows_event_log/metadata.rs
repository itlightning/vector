use std::mem::size_of;
use std::time::{Duration, Instant};

use lru::LruCache;
use metrics::Counter;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_PUBLISHER_METADATA_PROPERTY_ID, EVT_VARIANT, EvtClose, EvtFormatMessage,
    EvtFormatMessageEvent, EvtFormatMessageId, EvtFormatMessageKeyword, EvtFormatMessageOpcode,
    EvtFormatMessageTask, EvtGetObjectArrayProperty, EvtGetObjectArraySize,
    EvtGetPublisherMetadataProperty, EvtOpenPublisherMetadata,
    EvtPublisherMetadataKeywordMessageID, EvtPublisherMetadataKeywordName,
    EvtPublisherMetadataKeywordValue, EvtPublisherMetadataKeywords,
    EvtPublisherMetadataLevelMessageID, EvtPublisherMetadataLevelName,
    EvtPublisherMetadataLevelValue, EvtPublisherMetadataLevels,
    EvtPublisherMetadataOpcodeMessageID, EvtPublisherMetadataOpcodeName,
    EvtPublisherMetadataOpcodeValue, EvtPublisherMetadataOpcodes,
    EvtPublisherMetadataTaskMessageID, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskValue,
    EvtPublisherMetadataTasks, EvtVarTypeEvtHandle, EvtVarTypeString, EvtVarTypeUInt32,
    EvtVarTypeUInt64,
};
use windows::core::HSTRING;

use super::format_cache::{FormatCache, NameField, PublisherNames, SYSTEM_DEFAULT_LOCALE};
use super::rendering_info;
use super::subscription::PublisherHandle;
use super::win32_errors::{RenderDisposition, classify_render, win32_code};
use super::xml_parser::{SystemFields, fallback_level_name};

/// Test-only accounting for the render path.
///
/// The `<RenderingInfo>` crash guard is a process-crash fix, so the merge gate
/// for it is a direct assertion that an event carrying `<RenderingInfo>` reaches
/// zero `EvtFormatMessage` calls. These counters are the seam that assertion
/// reads; they are `#[cfg(test)]` and compile out of shipped binaries.
#[cfg(test)]
pub(super) mod seam {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::test_seams::SeamSession;

    pub(crate) static FORMAT_MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static PUBLISHER_PATH_ENTRIES: AtomicUsize = AtomicUsize::new(0);

    /// Reset both counters. Called by `SeamSession` on acquire and on drop, so
    /// it deliberately does NOT assert the session is held: it runs while the
    /// session is being established and while it is being torn down.
    pub(crate) fn reset() {
        FORMAT_MESSAGE_CALLS.store(0, Ordering::SeqCst);
        PUBLISHER_PATH_ENTRIES.store(0, Ordering::SeqCst);
    }

    /// These counters are process globals, so a reader without the session can
    /// observe another test's renders. Taking `&SeamSession` makes that a
    /// COMPILE error rather than a runtime one, matching the seam installers.
    ///
    /// `EventLogSubscription::new` has to assert at runtime instead, because it
    /// is production code and cannot take a test-only parameter. These are
    /// `cfg(test)` only, so they can do better.
    pub(crate) fn format_message_calls(_seams: &SeamSession) -> usize {
        FORMAT_MESSAGE_CALLS.load(Ordering::SeqCst)
    }

    /// Compile-time session requirement, see [`format_message_calls`].
    pub(crate) fn publisher_path_entries(_seams: &SeamSession) -> usize {
        PUBLISHER_PATH_ENTRIES.load(Ordering::SeqCst)
    }
}

/// Record one `EvtFormatMessage` invocation for the test seam. No-op and
/// zero-cost in non-test builds.
// Const in a non-test build, where the body is empty, but never in a test
// build, where it is an atomic increment. Marking it const would break the
// test configuration this seam exists for.
#[allow(clippy::missing_const_for_fn)]
#[inline]
fn note_format_message_call() {
    #[cfg(test)]
    seam::FORMAT_MESSAGE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Record one entry into the publisher-metadata render path for the test seam.
#[allow(clippy::missing_const_for_fn)]
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
    /// Table-resolved level display string. `None` keeps the hardcoded English
    /// match on the event.
    pub(super) level_name: Option<String>,
    pub(super) rendered_message: Option<String>,
    /// True when the event XML carried `<RenderingInfo>`, meaning it was
    /// delivered as rendered text (Windows Event Forwarding). Two consequences:
    /// `EvtFormatMessage` was not called for this event, and this channel's
    /// record IDs are not trustworthy for gap detection.
    pub(super) rendered_delivery: bool,
    /// Count of scalar/keyword lookups that missed the table and ran fallback.
    pub(super) table_misses: u32,
}

/// Resolve an event's display fields.
///
/// This is the single decision point for the `<RenderingInfo>` crash guard: if
/// the event XML carries `<RenderingInfo>`, everything is parsed out of the XML
/// and no publisher API is touched at all. See [`super::rendering_info`] for
/// why that matters (`EvtFormatMessage` faults the process, it does not return
/// an error). Otherwise the normal publisher-metadata path runs.
// The render path takes its caches, counters, handle, XML and system fields
// as separate arguments rather than a context struct, matching the in-tree
// precedent for wide internal helpers.
#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_event_display(
    publisher_cache: &mut LruCache<String, PublisherHandle>,
    format_cache: &mut FormatCache,
    cache_hits_counter: &Counter,
    cache_misses_counter: &Counter,
    event_handle: EVT_HANDLE,
    xml: &str,
    system_fields: &SystemFields,
    render_message: bool,
    now: Instant,
    refresh: Duration,
) -> EventDisplay {
    if let Some(info) = rendering_info::parse(xml) {
        return EventDisplay {
            task_name: info.task_name,
            opcode_name: info.opcode_name,
            keyword_names: info.keyword_names,
            level_name: None,
            rendered_message: if render_message { info.message } else { None },
            rendered_delivery: true,
            table_misses: 0,
        };
    }

    let provider_name = system_fields.provider_name.as_str();
    if provider_name.is_empty() {
        return EventDisplay::default();
    }

    note_publisher_path_entry();

    let resolved = resolve_event_metadata(
        publisher_cache,
        format_cache,
        cache_hits_counter,
        cache_misses_counter,
        event_handle,
        provider_name,
        system_fields.task,
        system_fields.opcode,
        system_fields.keywords,
        system_fields.level,
        now,
        refresh,
    );

    let rendered_message = if render_message {
        format_event_message(publisher_cache, event_handle, provider_name)
    } else {
        None
    };

    EventDisplay {
        task_name: resolved.task_name,
        opcode_name: resolved.opcode_name,
        keyword_names: resolved.keyword_names,
        level_name: resolved.level_name,
        rendered_message,
        rendered_delivery: false,
        table_misses: resolved.table_misses,
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

struct ResolvedNames {
    task_name: Option<String>,
    opcode_name: Option<String>,
    keyword_names: Vec<String>,
    level_name: Option<String>,
    table_misses: u32,
}

/// Resolves task, opcode, keyword, and level names from the publisher table.
#[allow(clippy::too_many_arguments)]
fn resolve_event_metadata(
    publisher_cache: &mut LruCache<String, PublisherHandle>,
    format_cache: &mut FormatCache,
    cache_hits_counter: &Counter,
    cache_misses_counter: &Counter,
    event_handle: EVT_HANDLE,
    provider_name: &str,
    task: u16,
    opcode: u8,
    keywords: u64,
    level: u8,
    now: Instant,
    refresh: Duration,
) -> ResolvedNames {
    use super::format_cache::Prepare;

    match format_cache.prepare(provider_name, SYSTEM_DEFAULT_LOCALE, now, refresh) {
        Prepare::Unopenable => {
            return ResolvedNames {
                task_name: None,
                opcode_name: None,
                keyword_names: Vec::new(),
                level_name: Some(fallback_level_name(level).to_string()),
                table_misses: 0,
            };
        }
        Prepare::NeedEnumerate => {
            let raw = get_or_open_publisher(publisher_cache, provider_name, true);
            if raw == 0 {
                format_cache.store_unopenable(provider_name, SYSTEM_DEFAULT_LOCALE, now);
                return ResolvedNames {
                    task_name: None,
                    opcode_name: None,
                    keyword_names: Vec::new(),
                    level_name: Some(fallback_level_name(level).to_string()),
                    table_misses: 0,
                };
            }
            format_cache.store_table(
                provider_name,
                SYSTEM_DEFAULT_LOCALE,
                now,
                enumerate_publisher_names(EVT_HANDLE(raw)),
            );
        }
        Prepare::Ready => {}
    }

    let metadata = publisher_handle(publisher_cache, provider_name);

    let (task_name, task_miss) = match format_cache.get_scalar(
        provider_name,
        SYSTEM_DEFAULT_LOCALE,
        NameField::Task,
        u64::from(task),
    ) {
        Some(name) => {
            cache_hits_counter.increment(1);
            (Some(name.to_string()), false)
        }
        None => {
            cache_misses_counter.increment(1);
            (
                format_metadata_field(metadata, event_handle, EvtFormatMessageTask.0),
                true,
            )
        }
    };

    let (opcode_name, opcode_miss) = match format_cache.get_scalar(
        provider_name,
        SYSTEM_DEFAULT_LOCALE,
        NameField::Opcode,
        u64::from(opcode),
    ) {
        Some(name) => {
            cache_hits_counter.increment(1);
            (Some(name.to_string()), false)
        }
        None => {
            cache_misses_counter.increment(1);
            (
                format_metadata_field(metadata, event_handle, EvtFormatMessageOpcode.0),
                true,
            )
        }
    };

    let (keyword_names, keyword_miss) =
        match format_cache.get_keywords(provider_name, SYSTEM_DEFAULT_LOCALE, keywords) {
            Some(names) if !names.is_empty() || keywords == 0 => {
                cache_hits_counter.increment(1);
                (names, false)
            }
            _ => {
                cache_misses_counter.increment(1);
                let names =
                    format_metadata_field(metadata, event_handle, EvtFormatMessageKeyword.0)
                        .map(|s| {
                            s.split(';')
                                .map(|k| k.trim().to_string())
                                .filter(|k| !k.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();
                (names, true)
            }
        };

    let (level_name, level_miss) = match format_cache.get_scalar(
        provider_name,
        SYSTEM_DEFAULT_LOCALE,
        NameField::Level,
        u64::from(level),
    ) {
        Some(name) => {
            cache_hits_counter.increment(1);
            (Some(name.to_string()), false)
        }
        None => {
            // Levels 0-5 live in winmeta and are often absent from the
            // publisher table. Hardcoded English is the miss fallback, not a
            // diagnostic miss. Custom levels at 16+ that miss ARE a miss.
            let fallback = fallback_level_name(level);
            let miss = fallback == "Unknown";
            if miss {
                cache_misses_counter.increment(1);
            }
            (Some(fallback.to_string()), miss)
        }
    };

    let mut table_misses = 0u32;
    if task_miss {
        table_misses += 1;
    }
    if opcode_miss {
        table_misses += 1;
    }
    if keyword_miss {
        table_misses += 1;
    }
    if level_miss {
        table_misses += 1;
    }

    ResolvedNames {
        task_name,
        opcode_name,
        keyword_names,
        level_name,
        table_misses,
    }
}

fn publisher_handle(
    cache: &mut LruCache<String, PublisherHandle>,
    provider_name: &str,
) -> EVT_HANDLE {
    EVT_HANDLE(get_or_open_publisher(cache, provider_name, false))
}

fn get_or_open_publisher(
    cache: &mut LruCache<String, PublisherHandle>,
    provider_name: &str,
    retry_failed: bool,
) -> isize {
    if let Some(handle) = cache.get(provider_name) {
        if handle.0 != 0 || !retry_failed {
            return handle.0;
        }
        cache.pop(provider_name);
    }

    let provider_hstring = HSTRING::from(provider_name);
    // Locale 0 is the thread/system default, matching prior behavior and the
    // locked product choice: forwarded events keep origin `<Locale>` in XML
    // and we ignore it.
    let raw = unsafe {
        EvtOpenPublisherMetadata(None, &provider_hstring, None, SYSTEM_DEFAULT_LOCALE, 0)
            .map(|h| h.0)
            .unwrap_or(0)
    };

    cache.put(provider_name.to_string(), PublisherHandle(raw));
    raw
}

/// Walk the publisher's task / opcode / keyword / level tables.
///
/// Display strings come from the message ID (`EvtFormatMessageId`, null event
/// handle). The symbolic name is used only when the ID is `-1`, matching
/// Winlogbeat. The table is filled only from this walk.
fn enumerate_publisher_names(handle: EVT_HANDLE) -> PublisherNames {
    let mut names = PublisherNames::default();
    fill_tasks(handle, &mut names);
    fill_opcodes(handle, &mut names);
    fill_keywords(handle, &mut names);
    fill_levels(handle, &mut names);
    names
}

fn fill_tasks(handle: EVT_HANDLE, names: &mut PublisherNames) {
    walk_metadata_array(handle, EvtPublisherMetadataTasks, |array, index| {
        let message_id = variant_u32(&array_property(
            array,
            EvtPublisherMetadataTaskMessageID,
            index,
        ));
        let symbolic = variant_string(&array_property(array, EvtPublisherMetadataTaskName, index));
        let value =
            variant_u32(&array_property(array, EvtPublisherMetadataTaskValue, index)) as u16;
        if let Some(display) = display_or_symbolic(handle, message_id, symbolic) {
            names.tasks.insert(value, display);
        }
    });
}

fn fill_opcodes(handle: EVT_HANDLE, names: &mut PublisherNames) {
    walk_metadata_array(handle, EvtPublisherMetadataOpcodes, |array, index| {
        let message_id = variant_u32(&array_property(
            array,
            EvtPublisherMetadataOpcodeMessageID,
            index,
        ));
        let symbolic = variant_string(&array_property(
            array,
            EvtPublisherMetadataOpcodeName,
            index,
        ));
        // High word is the opcode; low word is the task it is scoped to
        // (zero means global). The event XML opcode is the high word.
        let value_mask = variant_u32(&array_property(
            array,
            EvtPublisherMetadataOpcodeValue,
            index,
        ));
        let opcode = ((value_mask >> 16) & 0xFFFF) as u8;
        if let Some(display) = display_or_symbolic(handle, message_id, symbolic) {
            names.opcodes.insert(opcode, display);
        }
    });
}

fn fill_keywords(handle: EVT_HANDLE, names: &mut PublisherNames) {
    walk_metadata_array(handle, EvtPublisherMetadataKeywords, |array, index| {
        let message_id = variant_u32(&array_property(
            array,
            EvtPublisherMetadataKeywordMessageID,
            index,
        ));
        let symbolic = variant_string(&array_property(
            array,
            EvtPublisherMetadataKeywordName,
            index,
        ));
        let bit = variant_u64(&array_property(
            array,
            EvtPublisherMetadataKeywordValue,
            index,
        ));
        if let Some(display) = display_or_symbolic(handle, message_id, symbolic) {
            names.keywords.push((bit, display));
        }
    });
}

fn fill_levels(handle: EVT_HANDLE, names: &mut PublisherNames) {
    walk_metadata_array(handle, EvtPublisherMetadataLevels, |array, index| {
        let message_id = variant_u32(&array_property(
            array,
            EvtPublisherMetadataLevelMessageID,
            index,
        ));
        let symbolic = variant_string(&array_property(array, EvtPublisherMetadataLevelName, index));
        let value = variant_u32(&array_property(
            array,
            EvtPublisherMetadataLevelValue,
            index,
        )) as u8;
        if let Some(display) = display_or_symbolic(handle, message_id, symbolic) {
            names.levels.insert(value, display);
        }
    });
}

/// Message ID `-1` (0xFFFFFFFF) means the entry has no message; use the
/// symbolic name. Any other ID is formatted with a null event handle. A
/// present ID that failed to format is omitted, never replaced by the
/// symbolic name.
fn display_or_symbolic(
    publisher: EVT_HANDLE,
    message_id: u32,
    symbolic: Option<String>,
) -> Option<String> {
    let formatted = if message_id != u32::MAX {
        format_message_id(publisher, message_id)
    } else {
        None
    };
    super::format_cache::choose_table_display(message_id, formatted, symbolic)
}

fn walk_metadata_array<F>(
    publisher: EVT_HANDLE,
    property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    mut visit: F,
) where
    F: FnMut(EVT_HANDLE, u32),
{
    let Some(variant) = publisher_property(publisher, property) else {
        return;
    };
    if variant.Type != EvtVarTypeEvtHandle.0 as u32 {
        return;
    }
    let array = unsafe { variant.Anonymous.EvtHandleVal };
    if array.0 == 0 {
        return;
    }
    let mut len = 0u32;
    if unsafe { EvtGetObjectArraySize(array.0, &mut len) }.is_err() {
        unsafe {
            _ = EvtClose(array);
        }
        return;
    }
    for index in 0..len {
        visit(array, index);
    }
    unsafe {
        _ = EvtClose(array);
    }
}

fn publisher_property(
    handle: EVT_HANDLE,
    property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
) -> Option<EVT_VARIANT> {
    sized_variant(|size, buf, used| unsafe {
        EvtGetPublisherMetadataProperty(handle, property, 0, size, buf, used)
    })
}

fn array_property(
    array: EVT_HANDLE,
    property: EVT_PUBLISHER_METADATA_PROPERTY_ID,
    index: u32,
) -> Option<EVT_VARIANT> {
    sized_variant(|size, buf, used| unsafe {
        EvtGetObjectArrayProperty(array.0, property.0 as u32, index, 0, size, buf, used)
    })
}

fn sized_variant<F>(mut get: F) -> Option<EVT_VARIANT>
where
    F: FnMut(u32, Option<*mut EVT_VARIANT>, *mut u32) -> windows::core::Result<()>,
{
    let mut used = 0u32;
    _ = get(0, None, &mut used);
    if used == 0 {
        return None;
    }
    let count = ((used as usize) / size_of::<EVT_VARIANT>()).max(1);
    let mut buf = vec![EVT_VARIANT::default(); count];
    let size = (buf.len() * size_of::<EVT_VARIANT>()) as u32;
    get(size, Some(buf.as_mut_ptr()), &mut used).ok()?;
    buf.into_iter().next()
}

fn variant_string(variant: &Option<EVT_VARIANT>) -> Option<String> {
    let variant = variant.as_ref()?;
    if variant.Type != EvtVarTypeString.0 as u32 {
        return None;
    }
    let ptr = unsafe { variant.Anonymous.StringVal };
    unsafe { ptr.to_string().ok() }
}

fn variant_u32(variant: &Option<EVT_VARIANT>) -> u32 {
    let Some(variant) = variant else {
        return 0;
    };
    if variant.Type != EvtVarTypeUInt32.0 as u32 {
        return 0;
    }
    unsafe { variant.Anonymous.UInt32Val }
}

fn variant_u64(variant: &Option<EVT_VARIANT>) -> u64 {
    let Some(variant) = variant else {
        return 0;
    };
    if variant.Type != EvtVarTypeUInt64.0 as u32 {
        return 0;
    }
    unsafe { variant.Anonymous.UInt64Val }
}

fn format_message_id(metadata_handle: EVT_HANDLE, message_id: u32) -> Option<String> {
    format_message(
        metadata_handle,
        EVT_HANDLE(0),
        message_id,
        EvtFormatMessageId.0,
        4096,
    )
}

fn format_metadata_field(
    metadata_handle: EVT_HANDLE,
    event_handle: EVT_HANDLE,
    flags: u32,
) -> Option<String> {
    if metadata_handle.0 == 0 || event_handle.0 == 0 {
        return None;
    }
    format_message(metadata_handle, event_handle, 0, flags, 4096)
}

fn format_message(
    metadata_handle: EVT_HANDLE,
    event_handle: EVT_HANDLE,
    message_id: u32,
    flags: u32,
    max_chars: u32,
) -> Option<String> {
    let mut buffer_used: u32 = 0;
    note_format_message_call();
    _ = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            message_id,
            None,
            flags,
            None,
            &mut buffer_used,
        )
    };

    if buffer_used == 0 || buffer_used > max_chars {
        return None;
    }

    let mut buffer = vec![0u16; buffer_used as usize];
    let mut actual_used: u32 = 0;
    note_format_message_call();
    let result = unsafe {
        EvtFormatMessage(
            metadata_handle,
            event_handle,
            message_id,
            None,
            flags,
            Some(&mut buffer),
            &mut actual_used,
        )
    };

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
    let raw_handle = get_or_open_publisher(publisher_cache, provider_name, false);

    if raw_handle == 0 {
        return None;
    }

    let metadata_handle = EVT_HANDLE(raw_handle);
    let flags = EvtFormatMessageEvent.0;
    let max_size = 64 * 1024;

    let mut buffer_used: u32 = 0;
    note_format_message_call();
    _ = unsafe {
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
    use std::num::NonZeroUsize;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::sources::windows_event_log::xml_parser::parse_system_section;

    const FORWARDED_FIXTURE: &str = include_str!("testdata/forwarded_rendering_info.xml");
    const LOCAL_FIXTURE: &str = include_str!("testdata/local_no_rendering_info.xml");

    fn empty_caches() -> (LruCache<String, PublisherHandle>, FormatCache) {
        let size = NonZeroUsize::new(8).expect("nonzero");
        (LruCache::new(size), FormatCache::new())
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
    fn rendering_info_event_makes_zero_evtformatmessage_calls() {
        // The counters below are process-global, and a concurrent test that
        // renders a real event would inflate them. The session both excludes
        // that test and hands these counters over reset.
        let seams = super::super::test_seams::SeamSession::acquire();

        let (mut publisher_cache, mut format_cache) = empty_caches();
        // Inert doubles. These are required arguments that this test never
        // reads, so a registered counter would only add a global side effect.
        let hits = Counter::noop();
        let misses = Counter::noop();
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
            Instant::now(),
            Duration::from_secs(86_400),
        );

        assert_eq!(
            seam::format_message_calls(&seams),
            0,
            "an event carrying <RenderingInfo> must never reach EvtFormatMessage"
        );
        assert_eq!(
            seam::publisher_path_entries(&seams),
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
    fn rendering_info_respects_render_message_disabled() {
        let seams = super::super::test_seams::SeamSession::acquire();

        let (mut publisher_cache, mut format_cache) = empty_caches();
        // Inert doubles. These are required arguments that this test never
        // reads, so a registered counter would only add a global side effect.
        let hits = Counter::noop();
        let misses = Counter::noop();
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
            Instant::now(),
            Duration::from_secs(86_400),
        );

        assert_eq!(seam::format_message_calls(&seams), 0);
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
