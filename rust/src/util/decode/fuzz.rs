// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-decoder: the map data a signed Lua decoder reads through the
//! host API, a page at a cursor and array entries made of the input,
//! under the kernel-obs decoders and the fixture that reads fixed
//! records, which it reads from the tree the library was built from.
//!
//! The input is the decoder's index, the page's cursor, eight bytes,
//! then the page.

use std::sync::OnceLock;

use crate::fuzzing::fuzz_target;
use crate::util::json::MAX_BYTES;
use crate::util::map_read::{MapEntry, MapView, SerialPage};
use crate::util::serializer::SERIAL_CHUNK_PAYLOAD;
use crate::util::upatch::DecoderView;

const SOURCES: [&str; 9] = [
    "upatches/kernel-obs/decoders/dns.lua",
    "upatches/kernel-obs/decoders/exec.lua",
    "upatches/kernel-obs/decoders/file.lua",
    "upatches/kernel-obs/decoders/listen.lua",
    "upatches/kernel-obs/decoders/net.lua",
    "upatches/kernel-obs/decoders/priv.lua",
    "upatches/kernel-obs/decoders/watch.lua",
    "upatches/kernel-obs/decoders/watch_stat.lua",
    "testing/fixtures/decoders/counters.lua",
];

/// The decoders, each over its source, which the process keeps.
struct Views(Vec<DecoderView<'static>>);

static VIEWS: OnceLock<Views> = OnceLock::new();

/// The array entries the page's first bytes make, twelve bytes each.
const MAX_ENTRIES: usize = 32;

fn init() {
    let tree = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let views = SOURCES
        .iter()
        .map(|rel| {
            let Ok(source) = std::fs::read(tree.join(rel)) else {
                std::process::abort();
            };
            let source: &'static [u8] = Box::leak(source.into_boxed_slice());
            let mut d = DecoderView {
                language: 0,
                api_version: 0,
                input_format: 0,
                export_signal: 0,
                map: [0; 16],
                source_name: [0; 64],
                entrypoint: [0; 32],
                source,
            };
            let name = rel.rsplit('/').next().unwrap_or(rel).as_bytes();
            let n = name.len().min(d.source_name.len() - 1);
            d.source_name[..n].copy_from_slice(&name[..n]);
            d.entrypoint[..6].copy_from_slice(b"decode");
            d
        })
        .collect();
    let _ = VIEWS.set(Views(views));
}

fuzz_target!(
    shirudo_fuzz_decoder,
    shirudo_fuzz_decoder_init,
    |data| {
        let (Some(views), [index, cursor @ ..]) = (VIEWS.get(), data) else {
            return;
        };
        if data.len() < 9 {
            return;
        }
        let d = &views.0[usize::from(*index) % views.0.len()];
        let page_data = &data[9..];
        let size = page_data.len();
        let page = SerialPage {
            page_index: 0,
            cursor: u64::from_ne_bytes(cursor[..8].try_into().unwrap_or_default()),
            next_cursor: 0,
            flags: 0,
            chunks: if size == 0 {
                1
            } else {
                ((size - 1) / SERIAL_CHUNK_PAYLOAD as usize + 1) as u32
            },
            done: true,
            data: page_data.to_vec(),
        };
        let entries = page_data
            .as_chunks::<12>()
            .0
            .iter()
            .take(MAX_ENTRIES)
            .map(|entry| {
                let (key, value) = entry.split_at(4);
                MapEntry {
                    key: key.to_vec(),
                    value: value.to_vec(),
                }
            })
            .collect();
        let mut v = MapView {
            type_name: Some(c"array"),
            key_size: 4,
            value_size: 8,
            value_stride: 8,
            n_cpus: 1,
            max_entries: MAX_ENTRIES as u32,
            serialized: true,
            serial_bytes_total: size as u64,
            serial_pages: vec![page],
            entries,
            ..MapView::default()
        };
        // The longest valid name, which the decoder gets in its input.
        v.upatch[..crate::util::upatch::NAME_MAX - 1].fill(b'u');
        v.name[..8].copy_from_slice(b"fuzz_map");
        for otel in [false, true] {
            let _ = super::run(d, &v, otel, MAX_BYTES);
        }
    },
    init
);
