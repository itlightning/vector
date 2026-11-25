use std::{collections::BTreeMap, num::NonZeroU64};

use vector_vrl_category::Category;
use vrl::prelude::*;

use crate::{Claim, ClaimOutcome, TableRegistry, TableSearch, vrl_util};

const PARAMETERS: &[Parameter] = &[
    Parameter::required(
        "table",
        kind::BYTES,
        "The [enrichment table](/docs/reference/glossary/#enrichment-tables) to claim the key in. Only `memory` tables support claims.",
    ),
    Parameter::required("key", kind::BYTES, "The key to check and mark."),
    Parameter::required(
        "window_secs",
        kind::INTEGER,
        "The length of the window this claim opens, in seconds. At least 1. A claim opens a window when the key has no row inside one: no row at all, or one in its carry period. A window already open keeps its own length.",
    ),
    Parameter::optional(
        "cap",
        kind::INTEGER,
        "How many claims in one window pass. At least 1.",
    )
    .default(&DEFAULT_CAP),
    Parameter::optional(
        "ttl_secs",
        kind::INTEGER,
        "How long the row lives from the start of the window this claim opens, in seconds. At least `window_secs`, which is the default. The time past the window is the carry period: a claim in it opens a new window, with its own `window_secs` and `ttl_secs`, and reports how many the previous window suppressed.",
    ),
    Parameter::optional(
        "value",
        kind::ANY,
        "A value stored by the claim that opens the window and returned to every claim in it.",
    ),
];

static DEFAULT_CAP: Value = Value::Integer(1);

fn positive(name: &'static str, value: Value) -> ExpressionResult<NonZeroU64> {
    let n = value.try_integer()?;
    u64::try_from(n)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| format!("{name} must be at least 1, got {n}").into())
}

fn outcome_value(outcome: ClaimOutcome) -> Value {
    Value::Object(ObjectMap::from([
        ("pass".into(), Value::Boolean(outcome.pass)),
        ("first".into(), Value::Boolean(outcome.first)),
        ("count".into(), saturating_integer(outcome.count)),
        (
            "suppressed_prev".into(),
            saturating_integer(outcome.suppressed_prev),
        ),
        (
            "window_secs".into(),
            saturating_integer(outcome.window_secs),
        ),
        ("value".into(), outcome.value),
    ]))
}

fn saturating_integer(n: u64) -> Value {
    Value::Integer(i64::try_from(n).unwrap_or(i64::MAX))
}

fn inner_kind() -> BTreeMap<Field, Kind> {
    BTreeMap::from([
        ("pass".into(), Kind::boolean()),
        ("first".into(), Kind::boolean()),
        ("count".into(), Kind::integer()),
        ("suppressed_prev".into(), Kind::integer()),
        ("window_secs".into(), Kind::integer()),
        ("value".into(), Kind::any()),
    ])
}

#[derive(Clone, Copy, Debug)]
pub struct ClaimEnrichmentTableRecord;
impl Function for ClaimEnrichmentTableRecord {
    fn identifier(&self) -> &'static str {
        "claim_enrichment_table_record"
    }

    fn usage(&self) -> &'static str {
        indoc! {"
            Checks and marks a key in a `memory` enrichment table in one step, so a burst of events
            with the same key counts every event even before the table publishes its writes to
            readers.

            A claim opens a window of `window_secs` when the key has no row inside a window: no
            row at all, or one in its carry period, the time between the end of its window and the
            end of its `ttl_secs`. The window stays fixed from then on. Each claim in the window
            counts; the first `cap` of them pass. The returned object has `pass`, `first` (this
            claim opened the window), `count` (this claim's position in the window, from 1),
            `suppressed_prev` (on a claim that opens a window over a row in its carry period, how
            many that row's window suppressed; otherwise 0), `window_secs` (the window in force)
            and `value` (what the opening claim stored).

            The row is written through the table's own write path, so its size cap, TTL scan and
            persistence apply to it. A claim the size cap refuses is an error, not a pass.
        "}
    }

    fn internal_failure_reasons(&self) -> &'static [&'static str] {
        &[
            "The table does not support claims.",
            "The table is full and refused the row.",
            "`window_secs` or `cap` is less than 1.",
            "`ttl_secs` is less than `window_secs`.",
        ]
    }

    fn category(&self) -> &'static str {
        Category::Enrichment.as_ref()
    }

    fn return_kind(&self) -> u16 {
        kind::OBJECT
    }

    fn parameters(&self) -> &'static [Parameter] {
        PARAMETERS
    }

    fn pure(&self) -> bool {
        false
    }

    fn examples(&self) -> &'static [Example] {
        &[example! {
            title: "Throttle a key to one event a minute",
            source: r#"claim_enrichment_table_record!("test", "4674:SeTcbPrivilege", window_secs: 60, ttl_secs: 120)"#,
            result: Ok(
                r#"{"pass": true, "first": true, "count": 1, "suppressed_prev": 0, "window_secs": 60, "value": null}"#
            ),
        }]
    }

    fn compile(
        &self,
        state: &TypeState,
        ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let registry = ctx
            .get_external_context_mut::<TableRegistry>()
            .ok_or(Box::new(vrl_util::Error::TablesNotLoaded) as Box<dyn DiagnosticMessage>)?;

        let tables = registry
            .table_ids()
            .into_iter()
            .map(Value::from)
            .collect::<Vec<_>>();

        let table = arguments
            .required_enum("table", &tables, state)?
            .try_bytes_utf8_lossy()
            .expect("table is not valid utf8")
            .into_owned();

        Ok(ClaimEnrichmentTableRecordFn {
            table,
            key: arguments.required("key"),
            window_secs: arguments.required("window_secs"),
            cap: arguments.optional("cap"),
            ttl_secs: arguments.optional("ttl_secs"),
            value: arguments.optional("value"),
            enrichment_tables: registry.as_readonly(),
        }
        .as_expr())
    }
}

#[derive(Debug, Clone)]
pub struct ClaimEnrichmentTableRecordFn {
    table: String,
    key: Box<dyn Expression>,
    window_secs: Box<dyn Expression>,
    cap: Option<Box<dyn Expression>>,
    ttl_secs: Option<Box<dyn Expression>>,
    value: Option<Box<dyn Expression>>,
    enrichment_tables: TableSearch,
}

impl FunctionExpression for ClaimEnrichmentTableRecordFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let key = self.key.resolve(ctx)?;
        let key = key.try_bytes_utf8_lossy()?;
        let window_secs = positive("window_secs", self.window_secs.resolve(ctx)?)?;
        let cap = match &self.cap {
            Some(cap) => positive("cap", cap.resolve(ctx)?)?,
            None => NonZeroU64::MIN,
        };
        let ttl_secs = match &self.ttl_secs {
            Some(ttl) => {
                let ttl = positive("ttl_secs", ttl.resolve(ctx)?)?.get();
                if ttl < window_secs.get() {
                    return Err(format!(
                        "ttl_secs must be at least window_secs ({window_secs}), got {ttl}"
                    )
                    .into());
                }
                ttl
            }
            None => window_secs.get(),
        };
        let value = self.value.as_ref().map(|v| v.resolve(ctx)).transpose()?;

        let outcome = self.enrichment_tables.claim(
            &self.table,
            &Claim {
                key: &key,
                window_secs,
                ttl_secs,
                cap,
                value: value.as_ref(),
            },
        )?;
        Ok(outcome_value(outcome))
    }

    fn type_def(&self, _: &TypeState) -> TypeDef {
        TypeDef::object(inner_kind()).fallible()
    }
}

#[cfg(test)]
mod tests {
    use vrl::{
        compiler::{TargetValue, prelude::TimeZone, state::RuntimeState},
        value,
        value::Secrets,
    };

    use super::*;
    use crate::test_util::get_table_registry;

    fn claim_fn(window_secs: i64, ttl_secs: Option<i64>) -> ClaimEnrichmentTableRecordFn {
        ClaimEnrichmentTableRecordFn {
            table: "dummy1".to_string(),
            key: expr!("k"),
            window_secs: expr!(window_secs),
            cap: None,
            ttl_secs: ttl_secs.map(|t| expr!(t)),
            value: Some(expr!({"first_seen_ts": "t0"})),
            enrichment_tables: get_table_registry().as_readonly(),
        }
    }

    fn resolve(func: &ClaimEnrichmentTableRecordFn) -> Resolved {
        let tz = TimeZone::default();
        let mut target = TargetValue {
            value: value!({}),
            metadata: value!({}),
            secrets: Secrets::new(),
        };
        let mut runtime_state = RuntimeState::default();
        let mut ctx = Context::new(&mut target, &mut runtime_state, &tz);
        func.resolve(&mut ctx)
    }

    #[test]
    fn returns_the_outcome_as_an_object() {
        let registry = get_table_registry();
        let mut func = claim_fn(60, Some(120));
        func.enrichment_tables = registry.as_readonly();
        registry.finish_load();

        assert_eq!(
            resolve(&func),
            Ok(value!({
                "pass": true,
                "first": true,
                "count": 1,
                "suppressed_prev": 0,
                "window_secs": 60,
                "value": {"first_seen_ts": "t0"},
            }))
        );
    }

    #[test]
    fn rejects_a_window_below_one() {
        let registry = get_table_registry();
        let mut func = claim_fn(0, None);
        func.enrichment_tables = registry.as_readonly();
        registry.finish_load();

        assert!(resolve(&func).is_err());
    }

    #[test]
    fn rejects_a_ttl_below_the_window() {
        let registry = get_table_registry();
        let mut func = claim_fn(60, Some(30));
        func.enrichment_tables = registry.as_readonly();
        registry.finish_load();

        assert!(resolve(&func).is_err());
    }
}
