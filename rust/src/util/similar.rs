// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Levenshtein distance and the did-you-mean helpers of the dispatchers,
//! allocation-free.

use core::ffi::c_int;

/// `SIMILAR_MAX_LEN`: a longer string matches nothing rather than costing
/// a larger table.
pub(crate) const MAX_LEN: usize = 64;

/// `struct suggestion`: a candidate and its distance from the input.
#[derive(Clone, Copy)]
pub struct Suggestion<T> {
    pub name: T,
    pub dist: c_int,
}

/// The edit distance between `s` and `t`, or `max + 1` as soon as it is
/// known to exceed `max`.
fn edit_distance(s: &[u8], t: &[u8], max: i32) -> i32 {
    let mut prev = [0i32; MAX_LEN + 1];
    let mut curr = [0i32; MAX_LEN + 1];
    let (m, n) = (s.len(), t.len());

    if m > MAX_LEN || n > MAX_LEN {
        return max.wrapping_add(1);
    }
    if m == 0 {
        return n as i32;
    }
    if n == 0 {
        return m as i32;
    }
    // Any common edit must close at least the length gap.
    if m.abs_diff(n) as i32 > max {
        return max.wrapping_add(1);
    }
    for (j, cell) in prev[..=n].iter_mut().enumerate() {
        *cell = j as i32;
    }
    for i in 1..=m {
        let mut row_min = i as i32;

        curr[0] = row_min;
        for j in 1..=n {
            let cost = i32::from(s[i - 1] != t[j - 1]);
            let v = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);

            curr[j] = v;
            row_min = row_min.min(v);
        }
        // Every later row stays at or above the minimum of this one.
        if row_min > max {
            return max.wrapping_add(1);
        }
        prev[..=n].copy_from_slice(&curr[..=n]);
    }
    prev[n]
}

/// The candidates within `max_dist` of `name`, nearest first and in
/// candidate order among equals, as many as `out` holds; returns how many
/// it wrote.
pub fn suggest<'a, T: Copy>(
    name: &[u8],
    candidates: impl IntoIterator<Item = (T, &'a [u8])>,
    max_dist: i32,
    out: &mut [Suggestion<T>],
) -> usize {
    let cap = out.len();
    let mut n_out = 0;

    if cap == 0 {
        return 0;
    }
    for (handle, candidate) in candidates {
        let dist = edit_distance(name, candidate, max_dist);
        let mut pos = n_out;

        if dist > max_dist {
            continue;
        }
        // Insertion sort: the farther ones move right, the last falls off.
        while pos > 0 && out[pos - 1].dist > dist {
            if pos < cap {
                out[pos] = out[pos - 1];
            }
            pos -= 1;
        }
        if pos < cap {
            out[pos] = Suggestion { name: handle, dist };
            if n_out < cap {
                n_out += 1;
            }
        }
    }
    n_out
}

/// Resolves `input` against `n` candidates in three tiers, the first that
/// hits winning: exact, `input` a prefix of a candidate, a candidate a
/// prefix of `input`. Stores the indices found, as many as `matches`
/// holds, and returns how many it stored, or 1 for an exact match even
/// into an empty `matches`.
pub fn resolve<'a>(
    input: &[u8],
    n: usize,
    candidate: impl Fn(usize) -> &'a [u8],
    matches: &mut [usize],
) -> usize {
    let mut found = 0;

    if let Some(i) = (0..n).find(|&i| candidate(i) == input) {
        if let Some(first) = matches.first_mut() {
            *first = i;
        }
        return 1;
    }
    for i in 0..n {
        let c = candidate(i);

        if c.len() > input.len() && c.starts_with(input) && found < matches.len() {
            matches[found] = i;
            found += 1;
        }
    }
    if found != 0 {
        return found;
    }
    for i in 0..n {
        let c = candidate(i);

        if c.len() < input.len() && input.starts_with(c) && found < matches.len() {
            matches[found] = i;
            found += 1;
        }
    }
    found
}
