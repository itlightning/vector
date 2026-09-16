//! Win32 error constants and the **(API call, code)** classification matrix.
//!
//! # Why this module exists
//!
//! The source originally hand-transcribed four Win32 constants and got all four
//! wrong: `ERROR_EVT_CHANNEL_NOT_FOUND` was defined as 15009 (real value
//! 15007), `ERROR_EVT_INVALID_QUERY` as 15007 (real 15001),
//! `ERROR_EVT_QUERY_RESULT_STALE` as 4317 (real 15011), and
//! `ERROR_EVT_QUERY_RESULT_INVALID_POSITION` as 16953 (real 15012). The pull
//! loop therefore had no handler for the real channel-not-found code at all and
//! fell into retry-forever, while the resubscribe path was gated on a value
//! Windows never returns and was unreachable dead code. A production agent
//! wedged for nine hours on that.
//!
//! Every constant here is bound from the `windows` crate, which makes that
//! whole bug class structurally unrepeatable. The one exception is documented
//! at [`INHERITED_UNDOCUMENTED_16953`].
//!
//! # Classification is a matrix, never an errno alone
//!
//! The same numeric means different things at different call sites.
//! `ERROR_INSUFFICIENT_BUFFER` (122) is routine on every render and every size
//! probe in all five surveyed collectors; if it reached the subscription-rebuild
//! arm we would tear down subscriptions on normal buffer growth. So the drain
//! classifier below applies to `EvtNext` **only**, and the render classifier
//! returns a type with no rebuild arm at all: the separation is structural, not
//! a convention someone has to remember.
//!
//! # Polarity: unknown codes rebuild
//!
//! Fluent Bit and Winlogbeat both default unknown codes to rebuild and both
//! survived production. Vector and otel-contrib both default to retrying the
//! same handle and both wedge. A missed code costs one rebuild from the
//! checkpoint; a missed rebuild costs a permanent wedge. The asymmetry decides
//! the polarity.

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_EVT_CHANNEL_NOT_FOUND,
    ERROR_EVT_INVALID_CHANNEL_PATH, ERROR_EVT_INVALID_QUERY,
    ERROR_EVT_QUERY_RESULT_INVALID_POSITION, ERROR_EVT_QUERY_RESULT_STALE,
    ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL, ERROR_INVALID_HANDLE, ERROR_INVALID_OPERATION,
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
};
use windows::Win32::System::Rpc::{
    RPC_S_CALL_CANCELLED, RPC_S_CALL_FAILED, RPC_S_INVALID_BOUND, RPC_S_SERVER_UNAVAILABLE,
    RPC_S_UNKNOWN_IF,
};

/// 16953 / 0x4239, inherited from the source's original commit under the name
/// `ERROR_EVT_QUERY_RESULT_INVALID_POSITION` (whose real value is 15012).
///
/// It is undocumented, appears in none of the five surveyed collectors, appears
/// nowhere in Winlogbeat's repository history, and has never been observed in
/// our own logs. It is kept, not deleted, purely on cost asymmetry: keeping a
/// dead branch costs one branch, while deleting a live one costs a permanent
/// wedge. The name states what we actually know about it.
pub(super) const INHERITED_UNDOCUMENTED_16953: u32 = 16953;

/// Extract the Win32 code from a `windows::core::Error`.
///
/// Windows Event Log APIs surface Win32 codes wrapped in an HRESULT, so the
/// low 16 bits carry the number. Both are logged on every state transition:
/// names are our guesses, numerics are ground truth.
pub(super) const fn win32_code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

/// Whether the active query on a channel came from the operator or from us.
///
/// `ERROR_EVT_INVALID_QUERY` (15001) means two different things depending on
/// this, and conflating them either kills a channel forever because of our own
/// bad XPath or retries a permanently bad operator config forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QueryOrigin {
    /// `event_query` (or a wildcard we substituted for it). Invalid means the
    /// configuration is wrong and will stay wrong.
    Operator,
    /// A resume-ladder predicate this source generated. Invalid means our
    /// predicate is wrong, which the next ladder rung may fix.
    Generated,
}

/// Why a channel is being skipped for this subscription generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SkipReason {
    /// 15000: the channel path itself is not a valid path.
    InvalidChannelPath,
    /// 15009: subscribing to a direct (analytic/debug) channel is not allowed.
    DirectChannel,
    /// 15001 on an operator-supplied query: permanent for this binding.
    OperatorQueryInvalid,
    /// 5: no read access. Per-generation only. The 24h periodic refresh is what
    /// retries it, so a transient ACL flap heals within a day out of a
    /// mechanism that already exists, and a permanently unreadable channel
    /// costs one warning per day rather than one per minute.
    AccessDenied,
}

impl SkipReason {
    /// The stable slug for this reason.
    ///
    /// This is a WIRE vocabulary, not a debug aid: the source pack keys on
    /// these exact strings, and the agent forwards them verbatim as the
    /// liveness `health_reason`. Deriving them from `Debug` would make the
    /// wire depend on Rust variant spelling, and minting a second vocabulary
    /// downstream would let the two drift. One name, defined here.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidChannelPath => "invalid_channel_path",
            Self::DirectChannel => "direct_channel",
            Self::OperatorQueryInvalid => "operator_query_invalid",
            Self::AccessDenied => "access_denied",
        }
    }
}

/// What the drain loop should do about an `EvtNext` error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DrainOutcome {
    /// Not an error condition: the channel is drained for now.
    Drained,
    /// Stop reading this channel for this subscription generation.
    SkipChannel(SkipReason),
    /// Halve the batch size and reopen from the bookmark: the batch was too
    /// large for the API to marshal.
    ReduceBatch,
    /// Discard any returned handles, tear down, and resubscribe from the last
    /// persisted checkpoint with backoff. This is also where unknown codes go.
    Rebuild,
}

/// What a failed `EvtSubscribe` means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubscribeOutcome {
    /// Stop asking for this channel this generation.
    SkipChannel(SkipReason),
    /// The bookmark is dead. Advance the resume ladder rather than retrying the
    /// same position forever.
    BookmarkDead,
    /// Our generated ladder predicate is invalid. Advance one rung and never
    /// retry the same predicate.
    GeneratedQueryInvalid,
    /// Retry the same rung after backoff. Unknown codes land here.
    Retry,
}

/// What to do about an error from the render / size-probe path.
///
/// This type has **no rebuild arm on purpose**. `ERROR_INSUFFICIENT_BUFFER`
/// (122) is routine here, and making the return type unable to express
/// "rebuild the subscription" is what keeps buffer growth structurally
/// incapable of tearing down a subscription. A batch that read successfully but
/// contains one unprocessable event never costs more than that event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RenderDisposition {
    /// The buffer holds usable text despite the status (partial render).
    UseBuffer,
    /// Grow the buffer and retry the render.
    GrowBuffer,
    /// Give up on this one event, emit what we have, advance past it.
    DropEvent,
}

/// Classify an `EvtNext` failure.
///
/// `returned` is the count `EvtNext` wrote out. It is load-bearing:
/// `ERROR_INVALID_OPERATION` (4317) fires roughly 46 times per 3 minutes on a
/// perfectly healthy channel with a zero count and is benign there, but with a
/// nonzero count it is not. Winlogbeat (since Dec 2015), otel-contrib (since
/// the 2022 observIQ import), Telegraf via Promtail/Alloy, and pywin32 issue
/// #2377 all discriminate it exactly this way.
///
/// `EvtNext` can also return an error with handles populated. Every non-benign
/// outcome here therefore obliges the caller to close the returned handles
/// before rebuilding; retrying the same handle is not an option, because on
/// 1734 the API cursor advances even when the call fails (Winlogbeat #3076) and
/// retrying loses events.
pub(super) const fn classify_evt_next(
    code: u32,
    returned: u32,
    query_origin: QueryOrigin,
) -> DrainOutcome {
    match code {
        c if c == ERROR_NO_MORE_ITEMS.0 => DrainOutcome::Drained,

        // Benign only with a zero count. With handles populated it is a real
        // failure and the returned handles must be discarded.
        c if c == ERROR_INVALID_OPERATION.0 => {
            if returned == 0 {
                DrainOutcome::Drained
            } else {
                DrainOutcome::Rebuild
            }
        }

        // A cancel seen HERE is always someone else's. We never call
        // `EvtCancel`, and the subscription is moved into the blocking task by
        // ownership transfer, so no other thread can cancel a drain that is in
        // flight: shutdown signals a separate Windows event object instead. A
        // service-side cancel is a real interruption and must rebuild.
        //
        // The design allowed for a self-cancel flag to keep intentional teardown
        // from causing a reconnect storm. There is no call site that can set it
        // truthfully under ownership transfer, so it is not carried: a flag that
        // is provably always false reads like a live guard and is not one. If a
        // cross-thread `EvtCancel` is ever introduced, the flag comes back with
        // it.
        c if c == ERROR_CANCELLED.0 => DrainOutcome::Rebuild,

        c if c == ERROR_EVT_INVALID_CHANNEL_PATH.0 => {
            DrainOutcome::SkipChannel(SkipReason::InvalidChannelPath)
        }
        c if c == ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL.0 => {
            DrainOutcome::SkipChannel(SkipReason::DirectChannel)
        }
        c if c == ERROR_ACCESS_DENIED.0 => DrainOutcome::SkipChannel(SkipReason::AccessDenied),
        c if c == ERROR_EVT_INVALID_QUERY.0 => match query_origin {
            QueryOrigin::Operator => DrainOutcome::SkipChannel(SkipReason::OperatorQueryInvalid),
            // Our own predicate: rebuilding advances the ladder, which is what
            // gives the next attempt a different predicate.
            QueryOrigin::Generated => DrainOutcome::Rebuild,
        },

        // Oversized event: shrinking the batch is the targeted fix, and it is
        // what stops one oversized event permanently capping a channel.
        c if c == RPC_S_INVALID_BOUND.0 as u32 => DrainOutcome::ReduceBatch,

        // Everything else, named or not, rebuilds.
        _ => DrainOutcome::Rebuild,
    }
}

/// Classify an `EvtSubscribe` failure.
pub(super) const fn classify_subscribe(code: u32, query_origin: QueryOrigin) -> SubscribeOutcome {
    match code {
        c if c == ERROR_EVT_INVALID_CHANNEL_PATH.0 => {
            SubscribeOutcome::SkipChannel(SkipReason::InvalidChannelPath)
        }
        c if c == ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL.0 => {
            SubscribeOutcome::SkipChannel(SkipReason::DirectChannel)
        }
        c if c == ERROR_ACCESS_DENIED.0 => SubscribeOutcome::SkipChannel(SkipReason::AccessDenied),

        c if c == ERROR_EVT_INVALID_QUERY.0 => match query_origin {
            QueryOrigin::Operator => {
                SubscribeOutcome::SkipChannel(SkipReason::OperatorQueryInvalid)
            }
            QueryOrigin::Generated => SubscribeOutcome::GeneratedQueryInvalid,
        },

        // Bookmark-death codes. 1168 belongs here and is easy to miss: with
        // EvtSubscribeStrict, a dead bookmark reports ERROR_NOT_FOUND rather
        // than silently repositioning.
        c if c == ERROR_NOT_FOUND.0
            || c == ERROR_EVT_QUERY_RESULT_STALE.0
            || c == ERROR_EVT_QUERY_RESULT_INVALID_POSITION.0
            || c == INHERITED_UNDOCUMENTED_16953 =>
        {
            SubscribeOutcome::BookmarkDead
        }

        // Channel absent, RPC family, handle churn, unknown: retry with
        // backoff. Vector never gives up on its own; the agent stops asking by
        // dropping the binding.
        _ => SubscribeOutcome::Retry,
    }
}

/// Names for the codes we deliberately document, for log attribution.
///
/// Purely descriptive: no behavior keys off it. Returning `None` for an unknown
/// code is correct and expected, since unknown codes still rebuild.
pub(super) const fn describe(code: u32) -> Option<&'static str> {
    Some(match code {
        c if c == ERROR_ACCESS_DENIED.0 => "ERROR_ACCESS_DENIED",
        c if c == ERROR_INVALID_HANDLE.0 => "ERROR_INVALID_HANDLE",
        c if c == ERROR_INVALID_PARAMETER.0 => "ERROR_INVALID_PARAMETER",
        c if c == ERROR_NO_MORE_ITEMS.0 => "ERROR_NO_MORE_ITEMS",
        c if c == ERROR_CANCELLED.0 => "ERROR_CANCELLED",
        c if c == ERROR_NOT_FOUND.0 => "ERROR_NOT_FOUND",
        c if c == ERROR_INVALID_OPERATION.0 => "ERROR_INVALID_OPERATION",
        c if c == RPC_S_UNKNOWN_IF.0 as u32 => "RPC_S_UNKNOWN_IF",
        c if c == RPC_S_SERVER_UNAVAILABLE.0 as u32 => "RPC_S_SERVER_UNAVAILABLE",
        c if c == RPC_S_CALL_FAILED.0 as u32 => "RPC_S_CALL_FAILED",
        c if c == RPC_S_CALL_CANCELLED.0 as u32 => "RPC_S_CALL_CANCELLED",
        c if c == RPC_S_INVALID_BOUND.0 as u32 => "RPC_S_INVALID_BOUND",
        c if c == ERROR_EVT_INVALID_CHANNEL_PATH.0 => "ERROR_EVT_INVALID_CHANNEL_PATH",
        c if c == ERROR_EVT_INVALID_QUERY.0 => "ERROR_EVT_INVALID_QUERY",
        c if c == ERROR_EVT_CHANNEL_NOT_FOUND.0 => "ERROR_EVT_CHANNEL_NOT_FOUND",
        c if c == ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL.0 => {
            "ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL"
        }
        c if c == ERROR_EVT_QUERY_RESULT_STALE.0 => "ERROR_EVT_QUERY_RESULT_STALE",
        c if c == ERROR_EVT_QUERY_RESULT_INVALID_POSITION.0 => {
            "ERROR_EVT_QUERY_RESULT_INVALID_POSITION"
        }
        c if c == INHERITED_UNDOCUMENTED_16953 => "inherited-undocumented-16953",
        _ => return None,
    })
}

/// Classify an error from the render / size-probe path.
///
/// Kept next to the drain classifier so the contrast is visible: same numbers,
/// different call site, different and strictly narrower set of outcomes.
pub(super) const fn classify_render(code: u32) -> RenderDisposition {
    use windows::Win32::Foundation::{
        ERROR_EVT_MAX_INSERTS_REACHED, ERROR_EVT_UNRESOLVED_PARAMETER_INSERT,
        ERROR_EVT_UNRESOLVED_VALUE_INSERT, ERROR_INSUFFICIENT_BUFFER,
    };
    match code {
        c if c == ERROR_INSUFFICIENT_BUFFER.0 => RenderDisposition::GrowBuffer,
        c if c == ERROR_EVT_UNRESOLVED_VALUE_INSERT.0
            || c == ERROR_EVT_UNRESOLVED_PARAMETER_INSERT.0
            || c == ERROR_EVT_MAX_INSERTS_REACHED.0 =>
        {
            RenderDisposition::UseBuffer
        }
        _ => RenderDisposition::DropEvent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

    /// Pin every skip slug.
    ///
    /// These cross a wire: the source pack keys on them and the agent forwards
    /// them as the liveness `health_reason`. Renaming a Rust variant must not
    /// silently rename a wire value, so the mapping is asserted literally
    /// rather than derived.
    #[test]
    fn skip_reason_slugs_are_the_exact_wire_strings() {
        assert_eq!(
            SkipReason::InvalidChannelPath.as_str(),
            "invalid_channel_path"
        );
        assert_eq!(SkipReason::DirectChannel.as_str(), "direct_channel");
        assert_eq!(
            SkipReason::OperatorQueryInvalid.as_str(),
            "operator_query_invalid"
        );
        assert_eq!(SkipReason::AccessDenied.as_str(), "access_denied");
    }

    /// The four inherited constants were all wrong. Pin the real values so a
    /// future crate bump or edit cannot silently reintroduce the bug class.
    #[test]
    fn bound_constants_have_their_real_values() {
        assert_eq!(ERROR_EVT_INVALID_CHANNEL_PATH.0, 15000);
        assert_eq!(ERROR_EVT_INVALID_QUERY.0, 15001);
        assert_eq!(ERROR_EVT_CHANNEL_NOT_FOUND.0, 15007);
        assert_eq!(ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL.0, 15009);
        assert_eq!(ERROR_EVT_QUERY_RESULT_STALE.0, 15011);
        assert_eq!(ERROR_EVT_QUERY_RESULT_INVALID_POSITION.0, 15012);
        assert_eq!(ERROR_INVALID_OPERATION.0, 4317);
        assert_eq!(ERROR_NOT_FOUND.0, 1168);
        assert_eq!(RPC_S_INVALID_BOUND.0, 1734);
    }

    #[test]
    fn no_more_items_is_a_benign_drain_terminator() {
        assert_eq!(
            classify_evt_next(259, 0, QueryOrigin::Operator),
            DrainOutcome::Drained
        );
    }

    /// 4317 is `ERROR_INVALID_OPERATION`, not `ERROR_EVT_QUERY_RESULT_STALE`.
    /// It fires constantly on healthy channels with a zero count. Deleting its
    /// benign handler on documentation grounds regressed a healthy channel to
    /// 18 shipping ERROR events per three minutes, which is why the behavior is
    /// kept and only the name was corrected.
    #[test]
    fn invalid_operation_is_discriminated_on_the_returned_count() {
        assert_eq!(
            classify_evt_next(4317, 0, QueryOrigin::Operator),
            DrainOutcome::Drained
        );
        assert_eq!(
            classify_evt_next(4317, 3, QueryOrigin::Operator),
            DrainOutcome::Rebuild
        );
    }

    #[test]
    fn unknown_codes_rebuild_rather_than_retrying_the_same_handle() {
        for code in [6u32, 87, 1717, 1722, 1726, 1818, 15007, 15011, 15012, 60123] {
            assert_eq!(
                classify_evt_next(code, 0, QueryOrigin::Operator),
                DrainOutcome::Rebuild,
                "code {code} must rebuild"
            );
        }
    }

    #[test]
    fn oversized_batch_reduces_rather_than_rebuilding_blindly() {
        assert_eq!(
            classify_evt_next(1734, 0, QueryOrigin::Operator),
            DrainOutcome::ReduceBatch
        );
    }

    /// We never issue `EvtCancel`, and ownership transfer means no other thread
    /// can cancel a drain in flight, so a cancel seen at `EvtNext` is always a
    /// service-side interruption and rebuilding is the only correct response.
    #[test]
    fn a_cancel_at_evt_next_is_always_service_side_and_rebuilds() {
        assert_eq!(
            classify_evt_next(1223, 0, QueryOrigin::Operator),
            DrainOutcome::Rebuild
        );
    }

    #[test]
    fn invalid_query_splits_by_origin() {
        assert_eq!(
            classify_evt_next(15001, 0, QueryOrigin::Operator),
            DrainOutcome::SkipChannel(SkipReason::OperatorQueryInvalid)
        );
        assert_eq!(
            classify_subscribe(15001, QueryOrigin::Operator),
            SubscribeOutcome::SkipChannel(SkipReason::OperatorQueryInvalid)
        );
        assert_eq!(
            classify_subscribe(15001, QueryOrigin::Generated),
            SubscribeOutcome::GeneratedQueryInvalid
        );
    }

    #[test]
    fn access_denied_skips_the_generation_rather_than_looping() {
        assert_eq!(
            classify_evt_next(5, 0, QueryOrigin::Operator),
            DrainOutcome::SkipChannel(SkipReason::AccessDenied)
        );
        assert_eq!(
            classify_subscribe(5, QueryOrigin::Operator),
            SubscribeOutcome::SkipChannel(SkipReason::AccessDenied)
        );
    }

    #[test]
    fn bookmark_death_codes_advance_the_ladder() {
        for code in [1168u32, 15011, 15012, INHERITED_UNDOCUMENTED_16953] {
            assert_eq!(
                classify_subscribe(code, QueryOrigin::Operator),
                SubscribeOutcome::BookmarkDead,
                "code {code} must be treated as bookmark death"
            );
        }
    }

    /// Channel-not-found at subscribe must NOT be a permanent skip: that is the
    /// Defender wedge, where the channel provably existed and came back.
    #[test]
    fn channel_not_found_at_subscribe_retries() {
        assert_eq!(
            classify_subscribe(15007, QueryOrigin::Operator),
            SubscribeOutcome::Retry
        );
    }

    /// `ERROR_INSUFFICIENT_BUFFER` is routine on every render and size probe.
    /// The render classifier's return type has no rebuild arm, so buffer growth
    /// is structurally incapable of tearing down a subscription. This test
    /// documents that guarantee; the compiler enforces it.
    #[test]
    fn insufficient_buffer_cannot_express_a_rebuild() {
        let disposition = classify_render(ERROR_INSUFFICIENT_BUFFER.0);
        assert_eq!(disposition, RenderDisposition::GrowBuffer);
    }

    #[test]
    fn describe_is_descriptive_only() {
        assert_eq!(describe(15007), Some("ERROR_EVT_CHANNEL_NOT_FOUND"));
        assert_eq!(describe(60123), None);
    }
}
