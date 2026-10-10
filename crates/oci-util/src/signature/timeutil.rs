//! RFC 3339 timestamps without fractional seconds.

use super::error::{ErrorKind, SignatureError};

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn format_rfc3339(epoch: i64) -> Result<String, SignatureError> {
    if epoch < 0 {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is before the Unix epoch",
        ));
    }
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days)?;
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Parse an RFC 3339 date-time. Fractional seconds are rejected.
pub(crate) fn parse_rfc3339(text: &str) -> Result<i64, SignatureError> {
    if text.contains('.') {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "fractional seconds are not allowed in Notary timestamps",
        ));
    }
    let bytes = text.as_bytes();
    let marker = bytes.get(10).copied();
    if bytes.len() < 20 || (marker != Some(b'T') && marker != Some(b't')) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is not RFC 3339",
        ));
    }
    let year = parse_n(&bytes[0..4])?;
    let month = parse_n(&bytes[5..7])?;
    let day = parse_n(&bytes[8..10])?;
    let hour = parse_n(&bytes[11..13])?;
    let minute = parse_n(&bytes[14..16])?;
    let second = parse_n(&bytes[17..19])?;
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || day == 0
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is not RFC 3339",
        ));
    }
    let offset = parse_offset(&text[19..])?;
    let days = days_from_civil(year, month, day)?;
    let local = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour) * 3600))
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second)))
        .ok_or_else(|| SignatureError::new(ErrorKind::Encoding, "timestamp overflow"))?;
    local
        .checked_sub(offset)
        .ok_or_else(|| SignatureError::new(ErrorKind::Encoding, "timestamp overflow"))
}

fn parse_offset(text: &str) -> Result<i64, SignatureError> {
    if text == "Z" || text == "z" {
        return Ok(0);
    }
    let bytes = text.as_bytes();
    if bytes.len() != 6 || bytes.get(3) != Some(&b':') {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp offset is not RFC 3339",
        ));
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "timestamp offset is not RFC 3339",
            ));
        }
    };
    let hour = parse_n(&bytes[1..3])?;
    let minute = parse_n(&bytes[4..6])?;
    if hour > 23 || minute > 59 {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp offset is not RFC 3339",
        ));
    }
    Ok(sign * (i64::from(hour) * 3600 + i64::from(minute) * 60))
}

fn parse_n(bytes: &[u8]) -> Result<u32, SignatureError> {
    if bytes.is_empty() || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is not RFC 3339",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "timestamp is not RFC 3339"))?;
    text.parse()
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "timestamp is not RFC 3339"))
}

fn civil_from_days(days: i64) -> Result<(i32, u32, u32), SignatureError> {
    let shifted = days
        .checked_add(719_468)
        .ok_or_else(|| SignatureError::new(ErrorKind::Encoding, "timestamp is out of range"))?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted
            .checked_sub(146_096)
            .ok_or_else(|| SignatureError::new(ErrorKind::Encoding, "timestamp is out of range"))?
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = i64::from(year_of_era as i32) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    let year = i32::try_from(year)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "timestamp year is out of range"))?;
    if !(0..=9999).contains(&year) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp year is out of range",
        ));
    }
    Ok((year, month as u32, day as u32))
}

fn days_from_civil(year: u32, month: u32, day: u32) -> Result<i64, SignatureError> {
    let year = i32::try_from(year)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "timestamp year is out of range"))?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is not RFC 3339",
        ));
    }
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u32;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468)
}
