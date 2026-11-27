// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed index of a repository: the packages it offers.

use core::ffi::c_int;

use super::IndexEntry;
use crate::errno::{E2BIG, EINVAL};
use crate::text::cstr;
use crate::util::bpm_oci::{name_ok, version_ok};
use crate::util::json::{JsonField, parse_schema};

/// What an index's schema fills: its schema version, where the entries
/// go, and the scratch entry the schema fills for each before
/// `take_entry()` takes it.
struct IndexParse<'e> {
    schema: i64,
    items: &'e mut [IndexEntry],
    n: usize,
    scratch: IndexEntry,
}

impl IndexParse<'_> {
    fn take_entry(&mut self) -> Result<(), c_int> {
        let Some(item) = self.items.get_mut(self.n) else {
            return Err(-E2BIG);
        };
        let e = self.scratch;

        if !name_ok(cstr(&e.name))
            || !version_ok(cstr(&e.version))
            || e.repository[0] == 0
            || e.manifest_digest[0] == 0
            || e.package_digest[0] == 0
            || e.package_size <= 0
        {
            return Err(-EINVAL);
        }
        *item = e;
        self.n += 1;
        // A field the next entry leaves out is not this entry's.
        self.scratch = IndexEntry::new();
        self.scratch.package_size = -1;
        Ok(())
    }
}

/// The entries of an index of schema 1, as many as `entries` has room
/// for, into it, and how many there are.
pub(super) fn index_parse(body: &[u8], entries: &mut [IndexEntry]) -> Result<usize, c_int> {
    let mut index = IndexParse {
        schema: 0,
        items: entries,
        n: 0,
        scratch: IndexEntry::new(),
    };

    // Missing from the first entry as from any other, not 0.
    index.scratch.package_size = -1;
    let sub = [
        JsonField::string(c"name", |p: &mut IndexParse| &mut p.scratch.name),
        JsonField::string(c"version", |p| &mut p.scratch.version),
        JsonField::string(c"repository", |p| &mut p.scratch.repository),
        JsonField::string(c"manifest_digest", |p| &mut p.scratch.manifest_digest),
        JsonField::string(c"package_digest", |p| &mut p.scratch.package_digest),
        JsonField::string(c"signer_fingerprint", |p| &mut p.scratch.signer),
        JsonField::int(c"package_size", |p| &mut p.scratch.package_size),
    ];
    let root = [
        JsonField::int(c"schema", |p: &mut IndexParse| &mut p.schema),
        JsonField::array(c"packages", &sub, &IndexParse::take_entry),
    ];
    parse_schema(body, &root, &mut index).map_err(|_| -EINVAL)?;
    if index.schema != 1 || !root[1].seen() {
        return Err(-EINVAL);
    }
    Ok(index.n)
}
