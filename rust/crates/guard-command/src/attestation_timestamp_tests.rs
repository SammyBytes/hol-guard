//! The rules this parser inherits from `datetime.fromisoformat`.

use super::attestation_timestamp::parse_attestation_timestamp;

const NOON: i64 = 1_792_756_800_000_000;

#[test]
fn a_trailing_zulu_is_an_utc_instant() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00Z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23t12:00:00z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("  2026-10-23T12:00:00Z  "),
        Some(NOON)
    );
}

#[test]
fn a_naive_instant_is_rejected() {
    // Nothing says which instant this names, so the claim has no capture time.
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23"), None);
    assert_eq!(parse_attestation_timestamp(""), None);
    assert_eq!(parse_attestation_timestamp("   "), None);
}

#[test]
fn the_date_and_time_may_drop_their_separators() {
    assert_eq!(parse_attestation_timestamp("20261023T120000Z"), Some(NOON));
    assert_eq!(parse_attestation_timestamp("2026-10-23T1200Z"), Some(NOON));
    assert_eq!(parse_attestation_timestamp("2026-10-23T12Z"), Some(NOON));
}

#[test]
fn any_single_character_separates_the_date_from_the_time() {
    // The separator is found by the shape of the date, not by looking for `T`.
    assert_eq!(
        parse_attestation_timestamp("2026-10-23 12:00:00Z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23X12:00:00Z"),
        Some(NOON)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23_12:00:00Z"),
        Some(NOON)
    );
}

#[test]
fn a_week_date_names_the_same_day() {
    assert_eq!(
        parse_attestation_timestamp("2026-W43-5T12:00:00Z"),
        Some(NOON)
    );
    assert_eq!(parse_attestation_timestamp("2026W435T120000Z"), Some(NOON));
    // Week 53 exists only in a long ISO year.
    assert!(parse_attestation_timestamp("2026-W53-1T12:00:00Z").is_some());
    assert_eq!(parse_attestation_timestamp("2026-W43-8T12:00:00Z"), None);
}

#[test]
fn a_fraction_may_use_either_separator_and_is_truncated() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00,5Z"),
        Some(NOON + 500_000)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00.1Z"),
        Some(NOON + 100_000)
    );
    // Digits past the sixth are dropped, not rounded.
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00.123456789Z"),
        Some(NOON + 123_456)
    );
    // A separator with nothing after it is a zero fraction.
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00.Z"),
        Some(NOON)
    );
}

#[test]
fn an_offset_may_carry_seconds() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+00:00:30"),
        Some(NOON - 30_000_000)
    );
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+0530"),
        Some(NOON - 19_800_000_000)
    );
    // A whole day of offset is not an offset.
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T12:00:00+24:00"),
        None
    );
}

#[test]
fn midnight_at_the_end_of_the_day_is_the_next_one() {
    assert_eq!(
        parse_attestation_timestamp("2026-10-23T24:00:00Z"),
        Some(NOON + 12 * 3_600 * 1_000_000)
    );
    // Only exactly midnight wraps.
    assert_eq!(parse_attestation_timestamp("2026-10-23T24:00:01Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T24:00:00.1Z"), None);
}

#[test]
fn a_date_that_does_not_exist_is_rejected() {
    assert_eq!(parse_attestation_timestamp("2026-02-30T00:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-13-01T00:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:60Z"), None);
    assert!(parse_attestation_timestamp("2024-02-29T00:00:00Z").is_some());
}

#[test]
fn a_non_ascii_digit_is_not_a_digit() {
    assert_eq!(parse_attestation_timestamp("٢٠٢٦-10-23T12:00:00Z"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00ğ"), None);
    assert_eq!(parse_attestation_timestamp("2026-10-23T12:00:00ZZ"), None);
    assert_eq!(parse_attestation_timestamp("not-a-time"), None);
}

#[test]
fn an_instant_outside_the_calendar_is_refused() {
    // Python raises `OverflowError` shifting this to UTC; neither side yields
    // an instant, so neither side names a claim.
    assert_eq!(
        parse_attestation_timestamp("0001-01-01T00:00:00+01:00"),
        None
    );
    assert!(parse_attestation_timestamp("0001-01-01T00:00:00+00:00").is_some());
    assert!(parse_attestation_timestamp("9999-12-31T23:59:59.999999Z").is_some());
}
