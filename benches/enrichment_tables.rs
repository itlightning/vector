use std::{num::NonZeroU64, time::SystemTime};

use chrono::prelude::*;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use vector::enrichment_tables::{
    Condition, Table,
    file::{File, FileData},
    geoip::{Geoip, GeoipConfig},
    memory::{Memory, MemoryConfig},
    mmdb::{Mmdb, MmdbConfig},
};
use vector_lib::enrichment::{Case, Claim};
use vrl::value::{ObjectMap, Value};

criterion_group!(
    name = benches;
    config = Criterion::default().noise_threshold(0.02).sample_size(10);
    targets = benchmark_enrichment_tables_file, benchmark_enrichment_tables_geoip, benchmark_enrichment_tables_mmdb, benchmark_enrichment_tables_memory
);
criterion_main!(benches);

/// Returns the text of the column at the given position.
fn column(col: usize, row: usize) -> Value {
    if col == 0 {
        // A column that is duplicated across 10 rows.
        Value::from(format!("data-0-{}", row / 10 * 10))
    } else if col == 1 {
        // And a final column with a date, each of the above duplicated row should have
        // a unique date.
        Value::Timestamp(
            Utc.with_ymd_and_hms(2013, row as u32 % 10 + 1, 15, 0, 0, 0)
                .unwrap(),
        )
    } else {
        Value::from(format!("data-{col}-{row}"))
    }
}

fn benchmark_enrichment_tables_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("enrichment_tables_file");

    let setup = |size, date_range, case| {
        let data = (0..size)
            .map(|row| {
                // Add 8 columns.
                (0..10).map(|col| column(col, row)).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut file = File::new(
            Default::default(),
            FileData {
                data,
                headers: (0..10)
                    .map(|header| format!("field-{header}"))
                    .collect::<Vec<_>>(),
                modified: SystemTime::now(),
            },
        );

        let (condition, index, result_offset) = if date_range {
            // Search on the first and last field.
            (
                vec![
                    Condition::Equals {
                        field: "field-0",
                        value: Value::from(format!("data-0-{}", (size - 1) / 10 * 10)),
                    },
                    Condition::BetweenDates {
                        field: "field-1",
                        from: Utc.with_ymd_and_hms(2013, 6, 1, 0, 0, 0).unwrap(),
                        to: Utc.with_ymd_and_hms(2013, 7, 1, 0, 0, 0).unwrap(),
                    },
                ],
                file.add_index(case, &["field-0"]).unwrap(),
                5,
            )
        } else {
            (
                vec![
                    Condition::Equals {
                        field: "field-2",
                        value: Value::from(format!("data-2-{}", size - 1)),
                    },
                    Condition::Equals {
                        field: "field-9",
                        value: Value::from(format!("data-9-{}", size - 1)),
                    },
                ],
                file.add_index(case, &["field-2", "field-9"]).unwrap(),
                1,
            )
        };

        let result = (0..10)
            .map(|idx| {
                (
                    format!("field-{idx}").into(),
                    column(idx, size - result_offset),
                )
            })
            .collect::<ObjectMap>();

        (file, index, condition, result)
    };

    group.bench_function("enrichment_tables/file_date_10", |b| {
        let (file, index, condition, expected) = setup(10, true, Case::Sensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Sensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_hashindex_sensitive_10", |b| {
        let (file, index, condition, expected) = setup(10, false, Case::Sensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Sensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_hashindex_insensitive_10", |b| {
        let (file, index, condition, expected) = setup(10, false, Case::Insensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Insensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_date_1_000", |b| {
        let (file, index, condition, expected) = setup(1_000, true, Case::Sensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Sensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_hashindex_sensitive_1_000", |b| {
        let (file, index, condition, expected) = setup(1_000, false, Case::Sensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Sensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_hashindex_insensitive_1_000", |b| {
        let (file, index, condition, expected) = setup(1_000, false, Case::Insensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Insensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/file_date_1_000_000", |b| {
        let (file, index, condition, expected) = setup(1_000_000, true, Case::Sensitive);
        b.iter_batched(
            || (&file, &condition, expected.clone(), Some(index)),
            |(file, condition, expected, index)| {
                assert_eq!(
                    Ok(expected),
                    file.find_table_row(Case::Sensitive, condition, None, None, index)
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(
        "enrichment_tables/file_hashindex_sensitive_1_000_000",
        |b| {
            let (file, index, condition, expected) = setup(1_000_000, false, Case::Sensitive);
            b.iter_batched(
                || (&file, &condition, expected.clone(), Some(index)),
                |(file, condition, expected, index)| {
                    assert_eq!(
                        Ok(expected),
                        file.find_table_row(Case::Sensitive, condition, None, None, index)
                    )
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.bench_function(
        "enrichment_tables/file_hashindex_insensitive_1_000_000",
        |b| {
            let (file, index, condition, expected) = setup(1_000_000, false, Case::Insensitive);
            b.iter_batched(
                || (&file, &condition, expected.clone(), Some(index)),
                |(file, condition, expected, index)| {
                    assert_eq!(
                        Ok(expected),
                        file.find_table_row(Case::Insensitive, condition, None, None, index)
                    )
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_enrichment_tables_geoip(c: &mut Criterion) {
    let mut group = c.benchmark_group("enrichment_tables_geoip");
    let build = |path: &str| {
        Geoip::new(GeoipConfig {
            path: path.into(),
            locale: "en".to_string(),
        })
        .unwrap()
    };

    group.bench_function("enrichment_tables/geoip_isp", |b| {
        let table = build("tests/data/GeoIP2-ISP-Test.mmdb");
        let ip = "208.192.1.2";
        let mut expected = ObjectMap::new();
        expected.insert("autonomous_system_number".into(), 701i64.into());
        expected.insert(
            "autonomous_system_organization".into(),
            "MCI Communications Services, Inc. d/b/a Verizon Business".into(),
        );
        expected.insert("isp".into(), "Verizon Business".into());
        expected.insert("organization".into(), "Verizon Business".into());

        b.iter_batched(
            || (&table, ip, &expected),
            |(table, ip, expected)| {
                assert_eq!(
                    Ok(expected.clone()),
                    table.find_table_row(
                        Case::Insensitive,
                        &[Condition::Equals {
                            field: "ip",
                            value: ip.into(),
                        }],
                        None,
                        None,
                        None,
                    )
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/geoip_city", |b| {
        let table = build("tests/data/GeoIP2-City-Test.mmdb");
        let ip = "67.43.156.9";
        let mut expected = ObjectMap::new();
        expected.insert("city_name".into(), Value::Null);
        expected.insert("country_code".into(), "BT".into());
        expected.insert("country_name".into(), "Bhutan".into());
        expected.insert("continent_code".into(), "AS".into());
        expected.insert("region_code".into(), Value::Null);
        expected.insert("region_name".into(), Value::Null);
        expected.insert("timezone".into(), "Asia/Thimphu".into());
        expected.insert("latitude".into(), Value::from(27.5));
        expected.insert("longitude".into(), Value::from(90.5));
        expected.insert("postal_code".into(), Value::Null);
        expected.insert("metro_code".into(), Value::Null);

        b.iter_batched(
            || (&table, ip, &expected),
            |(table, ip, expected)| {
                assert_eq!(
                    Ok(expected.clone()),
                    table.find_table_row(
                        Case::Insensitive,
                        &[Condition::Equals {
                            field: "ip",
                            value: ip.into(),
                        }],
                        None,
                        None,
                        None,
                    )
                )
            },
            BatchSize::SmallInput,
        );
    });
}

fn benchmark_enrichment_tables_mmdb(c: &mut Criterion) {
    let mut group = c.benchmark_group("enrichment_tables_mmdb");
    let build = |path: &str| Mmdb::new(MmdbConfig { path: path.into() }).unwrap();

    group.bench_function("enrichment_tables/mmdb_isp", |b| {
        let table = build("tests/data/GeoIP2-ISP-Test.mmdb");
        let ip = "208.192.1.2";
        let mut expected = ObjectMap::new();
        expected.insert("autonomous_system_number".into(), 701i64.into());
        expected.insert(
            "autonomous_system_organization".into(),
            "MCI Communications Services, Inc. d/b/a Verizon Business".into(),
        );
        expected.insert("isp".into(), "Verizon Business".into());
        expected.insert("organization".into(), "Verizon Business".into());

        b.iter_batched(
            || (&table, ip, &expected),
            |(table, ip, expected)| {
                assert_eq!(
                    Ok(expected.clone()),
                    table.find_table_row(
                        Case::Insensitive,
                        &[Condition::Equals {
                            field: "ip",
                            value: ip.into(),
                        }],
                        None,
                        None,
                        None,
                    )
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("enrichment_tables/mmdb_city", |b| {
        let table = build("tests/data/GeoIP2-City-Test.mmdb");
        let ip = "67.43.156.9";
        let mut expected = ObjectMap::new();
        expected.insert(
            "location".into(),
            ObjectMap::from([
                ("latitude".into(), Value::from(27.5)),
                ("longitude".into(), Value::from(90.5)),
            ])
            .into(),
        );

        b.iter_batched(
            || (&table, ip, &expected),
            |(table, ip, expected)| {
                assert_eq!(
                    Ok(expected.clone()),
                    table.find_table_row(
                        Case::Insensitive,
                        &[Condition::Equals {
                            field: "ip",
                            value: ip.into(),
                        }],
                        Some(&[
                            "location.latitude".to_string(),
                            "location.longitude".to_string(),
                        ]),
                        None,
                        None,
                    )
                )
            },
            BatchSize::SmallInput,
        );
    });
}

/// Claims on one key and on many. Every `TICK` claims the table flushes, as a 1 s flush
/// interval would at 5000 claims a second, which also keeps the pending write log at a
/// realistic length.
fn benchmark_enrichment_tables_memory(c: &mut Criterion) {
    const TICK: u64 = 5000;
    let mut group = c.benchmark_group("enrichment_tables_memory");
    let build = || {
        let mut config = MemoryConfig::default();
        config.ttl = 7200;
        config.flush_interval = Some(1);
        Memory::new(config)
    };
    let window = NonZeroU64::new(60).unwrap();

    let bench_claims =
        |b: &mut criterion::Bencher, key_of: &dyn Fn(u64) -> String, value: Option<&Value>| {
            let table = build();
            let keys: Vec<String> = (0..100_000).map(key_of).collect();
            let mut n = 0u64;
            b.iter(|| {
                n += 1;
                if n.is_multiple_of(TICK) {
                    // Flushes and publishes, as the sink's interval does.
                    drop(table.extract_state());
                }
                table
                    .claim(&Claim {
                        key: &keys[(n % 100_000) as usize],
                        window_secs: window,
                        ttl_secs: 120,
                        cap: NonZeroU64::MIN,
                        value,
                    })
                    .unwrap()
            });
        };

    group.bench_function("enrichment_tables/memory_claim_same_key", |b| {
        bench_claims(b, &|_| "4674:SeTcbPrivilege".to_string(), None)
    });
    group.bench_function("enrichment_tables/memory_claim_distinct_keys", |b| {
        bench_claims(b, &|i| format!("4674:key-{i}"), None)
    });
    group.bench_function("enrichment_tables/memory_claim_same_key_with_value", |b| {
        let value = Value::from(ObjectMap::from([
            ("first_seen_ts".into(), Value::from("2026-10-04T00:00:00Z")),
            ("first_seen_record_id".into(), Value::from("123456789")),
        ]));
        bench_claims(b, &|_| "4104:block-hash".to_string(), Some(&value))
    });

    // A plain lookup of a claimed row, for comparison.
    group.bench_function("enrichment_tables/memory_find_row", |b| {
        let table = build();
        let key = Value::from("4674:SeTcbPrivilege");
        table
            .claim(&Claim {
                key: "4674:SeTcbPrivilege",
                window_secs: window,
                ttl_secs: 120,
                cap: NonZeroU64::MIN,
                value: None,
            })
            .unwrap();
        drop(table.extract_state());
        b.iter(|| {
            table
                .find_table_row(
                    Case::Sensitive,
                    &[Condition::Equals {
                        field: "key",
                        value: key.clone(),
                    }],
                    None,
                    None,
                    None,
                )
                .unwrap()
        });
    });
}
