//! Human-readable durations for CLI flags and operator config.

use std::{fmt, iter::Peekable, str::CharIndices, time::Duration};

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
const MONTH: u64 = 2_630_016; // 30.44 days
const YEAR: u64 = 31_557_600; // 365.25 days

/// A malformed or unrepresentable operator duration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseDurationError {
    /// Expected a decimal number or a unit suffix at this byte offset.
    InvalidSyntax(usize),
    /// Unrecognized unit suffix.
    UnknownUnit(String),
    /// The number exceeds the supported range or precision.
    OutOfRange,
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSyntax(offset) => {
                write!(f, "expected a number and time unit at byte {offset} (for example 1h 30m)")
            }
            Self::UnknownUnit(unit) => write!(
                f,
                "unknown time unit {unit:?} (use ns, us/µs, ms, s, m, h, d, w, month or year)"
            ),
            Self::OutOfRange => f.write_str("duration exceeds the supported range or precision"),
        }
    }
}

impl std::error::Error for ParseDurationError {}

/// Parse the legacy duration syntax used by reth configs and CLI flags.
///
/// Terms such as `1h30m`, `4.2s` and `20 µs` are additive. Unit suffixes are case
/// sensitive, including `M` for the fixed-length month. The bare value `0` is also accepted.
pub fn parse_duration(input: &str) -> Result<Duration, ParseDurationError> {
    use ParseDurationError::{InvalidSyntax, OutOfRange, UnknownUnit};

    if input == "0" {
        return Ok(Duration::ZERO);
    }
    let mut chars = input.char_indices().peekable();
    let mut duration = Duration::ZERO;
    loop {
        let (value, _) = digits(&mut chars)?;
        let fraction = if chars.next_if(|&(_, c)| c == '.').is_some() {
            let (numerator, width) = digits(&mut chars)?;
            Some((numerator, 10u64.checked_pow(width).ok_or(OutOfRange)?))
        } else {
            None
        };
        let start = chars.peek().map(|&(i, _)| i).ok_or(InvalidSyntax(input.len()))?;
        while chars.next_if(|&(_, c)| c.is_ascii_alphabetic() || c == 'µ').is_some() {}
        let end = chars.peek().map_or(input.len(), |&(i, _)| i);
        if start == end {
            return Err(InvalidSyntax(start));
        }
        let suffix = &input[start..end];
        let unit = match suffix {
            "ns" | "nsec" | "nanos" => Unit::Nanos(1),
            "us" | "µs" | "usec" => Unit::Nanos(1_000),
            "ms" | "msec" | "millis" => Unit::Nanos(1_000_000),
            "s" | "sec" | "secs" | "second" | "seconds" => Unit::Seconds(1),
            "m" | "min" | "mins" | "minute" | "minutes" => Unit::Seconds(MINUTE),
            "h" | "hr" | "hrs" | "hour" | "hours" => Unit::Seconds(HOUR),
            "d" | "day" | "days" => Unit::Seconds(DAY),
            "w" | "wk" | "wks" | "week" | "weeks" => Unit::Seconds(WEEK),
            "M" | "month" | "months" => Unit::Seconds(MONTH),
            "y" | "yr" | "yrs" | "year" | "years" => Unit::Seconds(YEAR),
            _ => return Err(UnknownUnit(suffix.to_owned())),
        };
        duration = unit.add(duration, value, 1)?;
        if let Some((numerator, denominator)) = fraction {
            let fraction_unit = match unit {
                Unit::Nanos(1) => return Err(OutOfRange),
                Unit::Seconds(seconds @ (1 | MINUTE)) => Unit::Nanos(seconds * NANOS_PER_SECOND),
                unit => unit,
            };
            duration = fraction_unit.add(duration, numerator, denominator)?;
        }
        while chars.next_if(|&(_, c)| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            return Ok(duration);
        }
    }
}

fn digits(chars: &mut Peekable<CharIndices<'_>>) -> Result<(u64, u32), ParseDurationError> {
    let mut value = 0u64;
    let mut width = 0u32;
    while let Some((_, c)) = chars.next_if(|&(_, c)| c.is_ascii_digit() || c.is_whitespace()) {
        if let Some(digit) = c.to_digit(10) {
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(digit.into()))
                .ok_or(ParseDurationError::OutOfRange)?;
            width = width.saturating_add(1);
        }
    }
    if width == 0 {
        return Err(ParseDurationError::InvalidSyntax(chars.peek().map_or(0, |&(i, _)| i)));
    }
    Ok((value, width))
}

#[derive(Clone, Copy)]
enum Unit {
    Nanos(u64),
    Seconds(u64),
}

impl Unit {
    fn add(
        self,
        duration: Duration,
        value: u64,
        divisor: u64,
    ) -> Result<Duration, ParseDurationError> {
        use ParseDurationError::OutOfRange;

        let (Self::Nanos(scale) | Self::Seconds(scale)) = self;
        let value = value.checked_mul(scale).ok_or(OutOfRange)?;
        if !value.is_multiple_of(divisor) {
            return Err(OutOfRange);
        }
        let value = value / divisor;
        let term = match self {
            Self::Nanos(_) => {
                value.checked_add(duration.subsec_nanos().into()).ok_or(OutOfRange)?;
                Duration::from_nanos(value)
            }
            Self::Seconds(_) => Duration::from_secs(value),
        };
        duration.checked_add(term).ok_or(OutOfRange)
    }
}

/// Display a duration using the same units and spellings as the operator config.
pub fn format_duration(duration: Duration) -> impl fmt::Display {
    OperatorDuration(duration)
}

struct OperatorDuration(Duration);

impl fmt::Display for OperatorDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_zero() {
            return f.write_str("0s");
        }
        let mut seconds = self.0.as_secs();
        let nanos = self.0.subsec_nanos();
        let mut separator = "";
        for (scale, suffix, plural) in [
            (YEAR, "year", true),
            (MONTH, "month", true),
            (DAY, "day", true),
            (HOUR, "h", false),
            (MINUTE, "m", false),
            (1, "s", false),
        ] {
            let count = seconds / scale;
            seconds %= scale;
            if count > 0 {
                let plural = if plural && count > 1 { "s" } else { "" };
                write!(f, "{separator}{count}{suffix}{plural}")?;
                separator = " ";
            }
        }
        for (count, suffix) in
            [(nanos / 1_000_000, "ms"), (nanos / 1_000 % 1_000, "us"), (nanos % 1_000, "ns")]
        {
            if count > 0 {
                write!(f, "{separator}{count}{suffix}")?;
                separator = " ";
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
pub mod duration_serde;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_duration_strings() {
        for (text, expected) in [
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("1h30m", Duration::from_secs(5_400)),
            ("1hour 12min 5sec", Duration::from_secs(4_325)),
            ("4.2s 7µs", Duration::new(4, 200_007_000)),
            ("1 . 2 5 ms", Duration::from_micros(1_250)),
            ("\u{2003}1 m\t2secs\n", Duration::from_secs(62)),
            ("1s2s1s", Duration::from_secs(4)),
            ("2nanos 3nsec 1ns", Duration::from_nanos(6)),
            ("1M 1month", Duration::from_secs(2 * MONTH)),
            ("1.5years 1.5weeks", Duration::from_secs(3 * (YEAR + WEEK) / 2)),
            ("18446744073709551615s999999999ns", Duration::MAX),
        ] {
            assert_eq!(parse_duration(text), Ok(expected), "{text:?}");
            assert_eq!(parse_duration(&format_duration(expected).to_string()), Ok(expected));
        }
    }

    #[test]
    fn invalid_or_unrepresentable_values() {
        for text in [
            "",
            " 0 ",
            "12",
            "-1s",
            "+1s",
            "1e3s",
            "1S",
            "1 m sec",
            "1,5s",
            ".5s",
            "1.s",
            "1μs",
            "0.5ns",
            "1.0ns",
            "0.0000000001s",
            "0.0001h",
            "18446744073709551615s1s",
            "1ns18446744073709551615ns",
        ] {
            assert!(parse_duration(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn legacy_display() {
        let duration =
            Duration::new(YEAR + 2 * MONTH + 3 * DAY + 4 * HOUR + 5 * MINUTE + 6, 7_008_009);
        assert_eq!(
            format_duration(duration).to_string(),
            "1year 2months 3days 4h 5m 6s 7ms 8us 9ns"
        );
        assert_eq!(format_duration(Duration::ZERO).to_string(), "0s");
    }
}
