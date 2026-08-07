//! `<RenderingInfo>` handling for the Windows Event Log source.
//!
//! # Why this exists
//!
//! `EvtFormatMessage` does not merely fail when the publisher manifest for an
//! event is not installed on this machine: against certain unreachable
//! publishers it faults the whole process with `0xc0000005` (access violation).
//! The failure has been reported independently against Telegraf
//! (influxdata/telegraf#12328, #12375), Loki (grafana/loki#7825, #12492,
//! grafana/loki#16155) and Alloy (grafana/alloy#2616) over roughly 2.5 years.
//! It is a process crash, not a recoverable error, so it cannot be defended
//! against with error handling at the call site.
//!
//! The population where the publisher manifest is guaranteed to be missing is
//! Windows Event Collector (WEC) forwarded events delivered as *rendered text*:
//! the originating machine has the manifest, the collector does not. Windows
//! marks exactly that population by embedding a `<RenderingInfo>` element in the
//! event XML carrying the already-rendered message, level, task, opcode and
//! keyword names.
//!
//! So: **if the event XML carries `<RenderingInfo>`, parse the rendered fields
//! out of the XML and never call `EvtFormatMessage` for that event.** This is a
//! per-event property, not a channel-kind concept: no config surface, no
//! channel-name matching, and no new operator concept. Locally-read events do
//! not carry `<RenderingInfo>` and continue to use the publisher path.
//!
//! The same signal is also the trigger for self-disabling record-id gap
//! detection: forwarded record IDs interleave many originating machines, so
//! they are not monotonic and every batch would otherwise look like a gap.

use quick_xml::{Reader, events::Event as XmlEvent};

/// Rendered display fields parsed out of an event's `<RenderingInfo>` element.
///
/// Every field is optional because publishers vary in which sub-elements they
/// populate; an absent field is simply not overridden downstream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RenderingInfoFields {
    /// `<Message>`: the fully rendered event message.
    pub(super) message: Option<String>,
    /// `<Task>`: the display name of the task.
    pub(super) task_name: Option<String>,
    /// `<Opcode>`: the display name of the opcode.
    pub(super) opcode_name: Option<String>,
    /// `<Keywords><Keyword>...`: display names of each keyword.
    pub(super) keyword_names: Vec<String>,
}

/// Bound on XML reader iterations, mirroring `xml_parser::parse_system_section`.
/// Rendered messages can be long, but the element count stays small.
const MAX_ITERATIONS: usize = 4000;

/// Bound on any single accumulated text run, so a hostile or corrupt document
/// cannot drive unbounded allocation here.
const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Which `<RenderingInfo>` child's text we are currently collecting.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    None,
    Message,
    Task,
    Opcode,
    Keyword,
}

/// Parse an event's `<RenderingInfo>` element.
///
/// Returns `Some` if and only if the document contains a `<RenderingInfo>`
/// element, which is the signal that this event was delivered with rendered
/// text and that `EvtFormatMessage` must not be called for it. `Some` is
/// returned even when every sub-element is absent, because the presence of the
/// element, not its contents, is what makes the publisher call unsafe.
pub(super) fn parse(xml: &str) -> Option<RenderingInfoFields> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut buf = Vec::new();

    let mut present = false;
    let mut in_rendering_info = false;
    let mut fields = RenderingInfoFields::default();
    let mut target = Target::None;
    let mut text_buf = String::new();
    let mut iterations = 0usize;

    loop {
        if iterations >= MAX_ITERATIONS {
            break;
        }
        iterations += 1;

        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                let local = e.name().local_name();
                let local = local.as_ref();

                if local == b"RenderingInfo" {
                    present = true;
                    in_rendering_info = true;
                } else if in_rendering_info {
                    text_buf.clear();
                    target = match local {
                        b"Message" => Target::Message,
                        b"Task" => Target::Task,
                        b"Opcode" => Target::Opcode,
                        b"Keyword" => Target::Keyword,
                        // <Keywords> is a container; its <Keyword> children carry the text.
                        _ => Target::None,
                    };
                }
            }
            Ok(XmlEvent::Empty(ref e)) => {
                // A self-closing <RenderingInfo/> still means rendered delivery.
                if e.name().local_name().as_ref() == b"RenderingInfo" {
                    present = true;
                }
            }
            Ok(XmlEvent::Text(ref e)) => {
                if in_rendering_info
                    && target != Target::None
                    && let Ok(text) = e.unescape()
                    && text_buf.len() + text.len() <= MAX_TEXT_BYTES
                {
                    text_buf.push_str(&text);
                }
            }
            Ok(XmlEvent::CData(ref e)) => {
                if in_rendering_info
                    && target != Target::None
                    && let Ok(text) = std::str::from_utf8(e.as_ref())
                    && text_buf.len() + text.len() <= MAX_TEXT_BYTES
                {
                    text_buf.push_str(text);
                }
            }
            Ok(XmlEvent::End(ref e)) => {
                let local = e.name().local_name();
                let local = local.as_ref();
                if local == b"RenderingInfo" {
                    commit(target, &text_buf, &mut fields);
                    break;
                }
                if in_rendering_info && target != Target::None {
                    commit(target, &text_buf, &mut fields);
                    target = Target::None;
                    text_buf.clear();
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }

        buf.clear();
    }

    present.then_some(fields)
}

fn commit(target: Target, text: &str, fields: &mut RenderingInfoFields) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    match target {
        Target::Message => fields.message = Some(trimmed.to_string()),
        Target::Task => fields.task_name = Some(trimmed.to_string()),
        Target::Opcode => fields.opcode_name = Some(trimmed.to_string()),
        Target::Keyword => fields.keyword_names.push(trimmed.to_string()),
        Target::None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forwarded event as Windows Event Collector delivers it in rendered-text
    /// mode: the `<RenderingInfo>` element is present and the originating
    /// publisher's manifest is not installed on this machine.
    pub(crate) const FORWARDED_FIXTURE: &str =
        include_str!("testdata/forwarded_rendering_info.xml");

    /// The same event as read locally: no `<RenderingInfo>`, so the publisher
    /// path is the correct and safe one.
    pub(crate) const LOCAL_FIXTURE: &str = include_str!("testdata/local_no_rendering_info.xml");

    #[test]
    fn parses_forwarded_rendering_info() {
        let fields = parse(FORWARDED_FIXTURE).expect("RenderingInfo must be detected");
        assert_eq!(
            fields.message.as_deref(),
            Some("The Windows Firewall service entered the running state.")
        );
        assert_eq!(fields.task_name.as_deref(), Some("Service state change"));
        assert_eq!(fields.opcode_name.as_deref(), Some("Info"));
        assert_eq!(fields.keyword_names, vec!["Classic".to_string()]);
    }

    #[test]
    fn local_event_has_no_rendering_info() {
        assert!(
            parse(LOCAL_FIXTURE).is_none(),
            "locally-read events must fall through to the publisher path"
        );
    }

    #[test]
    fn empty_rendering_info_still_counts_as_present() {
        let xml = r#"<Event><System><EventID>1</EventID></System><RenderingInfo Culture="en-US"/></Event>"#;
        assert_eq!(parse(xml), Some(RenderingInfoFields::default()));
    }

    #[test]
    fn malformed_xml_does_not_panic() {
        assert!(parse("<Event><System>").is_none());
        assert!(parse("").is_none());
    }
}
