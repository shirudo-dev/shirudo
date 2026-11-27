// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The upatches-loaded table of `shirudo status` and `upatch list`:
//! printed, or as JSON.

use core::ffi::{c_char, c_long};

use crate::sys::libc::Zeroed;
use crate::sys::libc::{Tm, printf, strptime, timegm};
use crate::util::format::name_column_width;
use crate::util::json::JsonEmit;
use crate::util::timefmt::format_duration;

/// `struct upatch_table_row`.
pub struct UpatchTableRow {
    pub(crate) name: [c_char; 257],
    pub(crate) location: [c_char; 160],
    pub(crate) loaded_at: [c_char; 32],
    pub(crate) status: [c_char; 64],
    pub(crate) n_maps: u32,
    pub(crate) missed_ret: i32,
    pub(crate) missed_counted: u32,
    pub(crate) missed_runs: u64,
    pub(crate) age_sec: i64,
    pub(crate) payload_sha256: [c_char; 65],
}

impl UpatchTableRow {
    /// An empty row before its fields are filled.
    pub(crate) const fn empty() -> Self {
        Self {
            name: [0; 257],
            location: [0; 160],
            loaded_at: [0; 32],
            status: [0; 64],
            n_maps: 0,
            missed_ret: 0,
            missed_counted: 0,
            missed_runs: 0,
            age_sec: 0,
            payload_sha256: [0; 65],
        }
    }
}

/// The string in a fixed array, up to its NUL.
fn in_array(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    let bytes = unsafe { core::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len()) };

    &bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len())]
}

/// The seconds since an ISO-8601 UTC time, `YYYY-MM-DDTHH:MM:SSZ` with
/// anything after it; -1 for none or one that does not parse.
///
/// # Safety
///
/// `ts` is NULL or a C string.
pub(crate) unsafe fn age_sec(ts: *const c_char) -> i64 {
    let mut tm = Tm::zeroed();

    // SAFETY: the caller passes NULL or a C string.
    if ts.is_null() || unsafe { *ts } == 0 {
        return -1;
    }
    // SAFETY: a C string, a format and a struct tm to fill.
    if unsafe { strptime(ts, c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) }.is_null() {
        return -1;
    }
    // SAFETY: the struct tm filled.
    let then = unsafe { timegm(&mut tm) };
    let now = crate::util::timefmt::now();

    now.wrapping_sub(then)
}

/// The age as it appears in the table, with ? when unknown or too long.
fn display_age(age_sec: i64) -> [u8; 16] {
    let mut age = [0u8; 16];
    age[0] = b'?';
    if age_sec >= 0 && format_duration(age_sec as c_long, &mut age) != 0 {
        age[0] = b'?';
        age[1] = 0;
    }
    age
}

/// The rows as `shirudo status` prints them.
pub(crate) fn print(rows: &[UpatchTableRow]) {
    let row = c"  %-*s  %-28s  %5u  %6s  %-28s  %s\n";
    let width = name_column_width(rows.iter().map(|r| in_array(&r.name)));
    let width = i32::try_from(width).unwrap_or(257);

    // SAFETY: a format of an unsigned long, and its count.
    unsafe { printf(c"\nLoaded upatches (%zu):\n".as_ptr(), rows.len()) };
    if rows.is_empty() {
        // SAFETY: a format of nothing.
        unsafe { printf(c"  none\n".as_ptr()) };
        return;
    }
    // SAFETY: a format of five C strings, and those.
    unsafe {
        printf(
            c"  %-*s  %-28s  %5s  %6s  %-28s  %s\n".as_ptr(),
            width,
            c"NAME".as_ptr(),
            c"LOCATION".as_ptr(),
            c"MAPS".as_ptr(),
            c"MISSED".as_ptr(),
            c"STATUS".as_ptr(),
            c"AGE".as_ptr(),
        )
    };
    for r in rows {
        let age = display_age(r.age_sec);
        let status = if r.status[0] != 0 {
            r.status.as_ptr()
        } else {
            c"success".as_ptr()
        };
        let mut missed = [0u8; 24];
        let missed_text = if r.missed_ret != 0 {
            c"?".as_ptr()
        } else if r.missed_counted == 0 {
            c"-".as_ptr()
        } else {
            let digits = r.missed_runs.to_string();
            missed[..digits.len()].copy_from_slice(digits.as_bytes());
            missed.as_ptr().cast()
        };

        // SAFETY: the format, the row's strings, which its arrays end,
        // its count of maps, and the age.
        unsafe {
            printf(
                row.as_ptr(),
                width,
                r.name.as_ptr(),
                r.location.as_ptr(),
                r.n_maps,
                missed_text,
                status,
                age.as_ptr(),
            )
        };
    }
}

/// The rows as the `upatches_loaded` array of the status JSON.
pub(crate) fn emit_json(e: &mut JsonEmit, rows: &[UpatchTableRow]) {
    e.arr_open(b"upatches_loaded");
    for r in rows {
        let status: &[u8] = if r.status[0] != 0 {
            in_array(&r.status)
        } else {
            b"success"
        };

        e.obj_open();
        e.kv_string(b"name", in_array(&r.name));
        e.kv_string(b"location", in_array(&r.location));
        e.kv_string(b"status", status);
        e.kv_int(b"n_maps", i64::from(r.n_maps));
        if r.missed_ret == 0 && r.missed_counted != 0 {
            e.kv_u64(b"missed_runs", r.missed_runs);
        } else {
            e.kv_null(b"missed_runs");
        }
        e.kv_string(b"loaded_at", in_array(&r.loaded_at));
        if r.age_sec >= 0 {
            e.kv_int(b"age_sec", r.age_sec);
        } else {
            e.kv_null(b"age_sec");
        }
        if r.payload_sha256[0] != 0 {
            e.kv_string(b"payload_sha256", in_array(&r.payload_sha256));
        } else {
            e.kv_null(b"payload_sha256");
        }
        e.obj_close();
    }
    e.arr_close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_distinguishes_counted_misses_from_unavailable_counters() {
        let mut rows: [UpatchTableRow; 3] = std::array::from_fn(|_| {
            let mut r = UpatchTableRow::empty();
            r.age_sec = -1;
            r
        });
        rows[0].name[0] = b'a' as c_char;
        rows[0].missed_counted = 1;
        rows[0].missed_runs = u64::MAX;
        rows[1].name[0] = b'b' as c_char;
        rows[2].name[0] = b'c' as c_char;
        rows[2].missed_ret = -5;

        let mut e = JsonEmit::growing(4096);
        e.obj_open();
        emit_json(&mut e, &rows);
        e.obj_close();
        let output = e.finish().unwrap_or_default();
        assert!(
            output
                .windows(b"\"name\":\"a\"".len())
                .any(|w| w == b"\"name\":\"a\"")
        );
        assert_eq!(
            output
                .windows(b"\"missed_runs\":18446744073709551615".len())
                .filter(|w| *w == b"\"missed_runs\":18446744073709551615")
                .count(),
            1
        );
        assert_eq!(
            output
                .windows(b"\"missed_runs\":null".len())
                .filter(|w| *w == b"\"missed_runs\":null")
                .count(),
            2
        );
    }

    #[test]
    fn a_time_too_long_to_print_is_unknown() {
        assert_eq!(&display_age(-1)[..2], b"?\0");
        assert_eq!(&display_age(i64::MAX)[..2], b"?\0");
        assert_eq!(&display_age(45)[..4], b"45s\0");
    }
}
