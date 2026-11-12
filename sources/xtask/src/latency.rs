//! Shared benchmark histogram framing: 1-us bins below 65.536 ms, then 1024-us
//! bins up to 16.777216 seconds. Overflow remains explicit rather than clipped.

pub const FINE_BUCKETS: usize = 65_536;
pub const OVERFLOW: usize = 81_856;
pub const BUCKETS: usize = OVERFLOW + 1;

/// Quantize elapsed microseconds, saturating only into the explicit overflow bin.
///
/// # Errors
/// Returns a narrowing error on a platform unable to represent the histogram index.
pub fn bucket(microseconds: u128) -> Result<usize, std::num::TryFromIntError> {
    let index = if microseconds < 65_536 {
        microseconds
    } else {
        (65_536 + (microseconds - 65_536) / 1024).min(81_856)
    };
    usize::try_from(index)
}

/// Lower inclusive and upper exclusive microsecond bounds. Overflow has no finite bounds.
pub fn bounds(index: usize) -> Option<(u64, u64)> {
    if index >= OVERFLOW {
        return None;
    }
    let index = u64::try_from(index).ok()?;
    let (lower, width) = if index < 65_536 {
        (index, 1)
    } else {
        (65_536 + (index - 65_536) * 1024, 1024)
    };
    Some((lower, lower + width))
}

/// Compute a nearest-rank percentile without losing the histogram's quantization.
/// The upper bound is exclusive; overflow has no finite interval.
///
/// # Errors
/// Refuses an incompatible histogram, invalid percentile, zero/mismatched count,
/// overflowing arithmetic or a percentile in the explicit overflow bucket.
pub fn percentile_bounds(
    histogram: &[u64],
    count: u64,
    percent: u8,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    if histogram.len() != BUCKETS || count == 0 || !(1..=100).contains(&percent) {
        return Err("invalid histogram dimensions, count or percentile".into());
    }
    let sum = histogram.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value).ok_or("histogram count overflow")
    })?;
    if sum != count {
        return Err("histogram and declared sample count disagree".into());
    }
    let threshold = count
        .checked_mul(u64::from(percent))
        .and_then(|value| value.checked_add(99))
        .ok_or("histogram percentile rank overflow")?
        / 100;
    let mut cumulative = 0_u64;
    for (index, samples) in histogram.iter().enumerate() {
        cumulative = cumulative
            .checked_add(*samples)
            .ok_or("histogram cumulative count overflow")?;
        if cumulative >= threshold {
            return bounds(index)
                .ok_or_else(|| "percentile lies in the unbounded overflow bucket".into());
        }
    }
    Err("histogram does not contain its declared percentile".into())
}

/// Persist this schema with raw counts so percentile quantization is reviewable.
pub fn schema() -> serde_json::Value {
    serde_json::json!({"buckets":BUCKETS,"fine_buckets":FINE_BUCKETS,"fine_width_microseconds":1,
        "tail_width_microseconds":1024,"overflow_index":OVERFLOW,"overflow_lower_bound_microseconds":16_777_216})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r087_latency_histogram_keeps_fine_resolution_and_bounds_slow_samples_without_clipping()
    -> Result<(), Box<dyn std::error::Error>> {
        for (elapsed, expected) in [
            (65_535, (65_535, 65_536)),
            (65_536, (65_536, 66_560)),
            (66_560, (66_560, 67_584)),
            (100_000, (99_328, 100_352)),
            (16_777_215, (16_776_192, 16_777_216)),
        ] {
            assert_eq!(bounds(bucket(elapsed)?), Some(expected));
        }
        assert_eq!(bucket(16_777_216)?, OVERFLOW);
        assert_eq!(bucket(u128::MAX)?, OVERFLOW);
        assert_eq!(bounds(OVERFLOW), None);
        let mut histogram = vec![0; BUCKETS];
        histogram[1] = 50;
        histogram[10] = 45;
        histogram[100] = 4;
        histogram[OVERFLOW] = 1;
        assert_eq!(percentile_bounds(&histogram, 100, 50)?, (1, 2));
        assert_eq!(percentile_bounds(&histogram, 100, 95)?, (10, 11));
        assert_eq!(percentile_bounds(&histogram, 100, 99)?, (100, 101));
        assert!(percentile_bounds(&histogram, 100, 100).is_err());
        assert!(percentile_bounds(&histogram, 99, 95).is_err());
        assert!(percentile_bounds(&histogram, 100, 0).is_err());
        assert!(percentile_bounds(&histogram, 100, 101).is_err());
        assert!(percentile_bounds(&[], 0, 50).is_err());
        histogram[1] = u64::MAX;
        assert!(percentile_bounds(&histogram, u64::MAX, 50).is_err());
        Ok(())
    }
}
