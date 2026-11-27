// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Manifests: the layers of one as a registry wrote them, and a
//! descriptor as shirudo writes one.

use core::ffi::c_int;

use super::{Descriptor, MAX_NAME, copy_string, cstr};
use crate::errno::{E2BIG, EINVAL};
use crate::util::hex::decode_sha256_digest;
use crate::util::json::{JsonEmit, JsonField, parse_schema};

/// What a manifest's schema fills: its schema version, where the layers
/// go, the scratch descriptor the schema fills for each before
/// `take_descriptor()` takes it, and the package name.
struct DescSink<'l> {
    schema: i64,
    items: &'l mut [Descriptor],
    n: c_int,
    max: c_int,
    scratch: Descriptor,
    package_name: [u8; MAX_NAME],
}

impl DescSink<'_> {
    fn take_descriptor(&mut self) -> Result<(), c_int> {
        if self.n >= self.max {
            return Err(-E2BIG);
        }
        // The registry wrote this: a layer is all three or none.
        if self.scratch.media[0] == 0
            || self.scratch.size < 0
            || decode_sha256_digest(cstr(&self.scratch.digest)).is_err()
        {
            return Err(-EINVAL);
        }
        // n is below max, which the layers hold.
        self.items[self.n as usize] = self.scratch;
        self.n += 1;
        self.scratch = Descriptor::new();
        self.scratch.size = -1;
        Ok(())
    }
}

/// The layers of an image manifest of schema 2, as many as `layers`
/// has room for, into it, and the package name its annotations give.
pub(crate) fn parse_manifest(
    body: &[u8],
    layers: &mut [Descriptor],
    n_layers: &mut c_int,
    package_name: Option<&mut [u8]>,
) -> c_int {
    let mut sink = DescSink {
        schema: 0,
        max: c_int::try_from(layers.len()).unwrap_or(c_int::MAX),
        items: layers,
        n: 0,
        scratch: Descriptor::new(),
        package_name: [0; MAX_NAME],
    };

    sink.scratch.size = -1;
    let layer_annotations = [JsonField::string(
        c"org.opencontainers.image.title",
        |s: &mut DescSink| &mut s.scratch.title,
    )];
    let sub = [
        JsonField::string(c"mediaType", |s: &mut DescSink| &mut s.scratch.media),
        JsonField::string(c"digest", |s| &mut s.scratch.digest),
        JsonField::int(c"size", |s| &mut s.scratch.size),
        JsonField::object(c"annotations", &layer_annotations),
    ];
    let manifest_annotations = [JsonField::string(
        c"dev.shirudo.bpm.package.name",
        |s: &mut DescSink| &mut s.package_name,
    )];
    let root = [
        JsonField::int(c"schemaVersion", |s: &mut DescSink| &mut s.schema),
        JsonField::array(c"layers", &sub, &DescSink::take_descriptor),
        JsonField::object(c"annotations", &manifest_annotations),
    ];
    let ret = parse_schema(body, &root, &mut sink);

    if ret.is_err() || !root[0].seen() || sink.schema != 2 || !root[1].seen() {
        return -EINVAL;
    }
    *n_layers = sink.n;
    if let Some(name) = package_name {
        copy_string(name, cstr(&sink.package_name));
    }
    0
}

pub(crate) fn emit_descriptor(
    e: &mut JsonEmit,
    key: Option<&[u8]>,
    d: &Descriptor,
    title: Option<&[u8]>,
) {
    match key {
        Some(key) => e.obj_open_key(key),
        None => e.obj_open(),
    }
    e.kv_string(b"mediaType", cstr(&d.media));
    e.kv_string(b"digest", cstr(&d.digest));
    e.kv_int(b"size", d.size);
    if let Some(title) = title {
        e.obj_open_key(b"annotations");
        e.kv_string(b"org.opencontainers.image.title", title);
        e.obj_close();
    }
    e.obj_close();
}
