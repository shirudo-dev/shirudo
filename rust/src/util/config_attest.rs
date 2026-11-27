// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config's history as attestation evidence:
//! collected from the update records, emitted
//! with a quote, parsed back by a verifier, and checked there against
//! the quoted PCR, the TPM boot and the root an operator approved.

use core::ffi::{CStr, c_int};

use crate::errno::{E2BIG, EINVAL, EKEYREJECTED, ENOMEM, EOVERFLOW, EUCLEAN};
use crate::text::cstr;
use crate::util::chain;
use crate::util::config_measure::{
    EVENT_BOOT, EVENT_UPDATE, event as measure_event, nvpcr, nvpcr_initial, pcr_valid,
};
use crate::util::config_update::{ConfigUpdate, ConfigUpdateRecord};
use crate::util::hex;
use crate::util::json::{JsonEmit, JsonField, parse_schema};

/// `CONFIG_EVIDENCE_EVENTS_MAX`.
const EVENTS_MAX: usize = 4096;

/// An event of the config's history.
struct EvidenceEvent {
    root_hash: [u8; 32],
    sequence: u64,
    kind: c_int,
}

/// The config's history as the evidence carries it: the events of the
/// active config in one TPM boot and the PCR value they fold to, or
/// nothing when `present` is not set.
#[derive(Default)]
pub(crate) struct Evidence {
    events: Vec<EvidenceEvent>,
    initial_pcr: [u8; 32],
    pub(crate) value: [u8; 32],
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) pcr: u32,
    pub(crate) present: bool,
}

impl Evidence {
    /// How many events the history holds.
    pub(crate) fn n_events(&self) -> usize {
        self.events.len()
    }

    fn append_event(&mut self, root_hash: &[u8; 32], sequence: u64, kind: c_int) -> c_int {
        if self.events.len() >= EVENTS_MAX {
            return -E2BIG;
        }
        if self.events.try_reserve(1).is_err() {
            return -ENOMEM;
        }
        self.events.push(EvidenceEvent {
            root_hash: *root_hash,
            sequence,
            kind,
        });
        0
    }
}

/// The PCR the events fold to from the initial value: 0, -EINVAL for no
/// events, -EKEYREJECTED for a history out of order.
fn replay(view: &Evidence, out: &mut [u8; 32]) -> c_int {
    let mut sequence = 0u64;

    if view.events.is_empty() || view.events.len() > EVENTS_MAX {
        return -EINVAL;
    }
    *out = view.initial_pcr;
    for (i, event) in view.events.iter().enumerate() {
        let kind = if i != 0 { EVENT_UPDATE } else { EVENT_BOOT };

        if event.sequence == 0
            || event.sequence > i64::MAX as u64
            || (i != 0 && event.sequence != sequence.wrapping_add(1))
            || event.kind != kind
        {
            return -EKEYREJECTED;
        }
        let digest = match measure_event(event.kind, &event.root_hash) {
            Ok(digest) => digest,
            Err(err) => return err,
        };
        if let Err(ret) = chain::fold(out, &digest) {
            return ret;
        }
        sequence = event.sequence;
    }
    0
}

/// The event `r` added to the view when it is of the view's TPM boot:
/// -EUCLEAN for one of another PCR or initial value.
fn collect_event(r: &ConfigUpdateRecord, view: &mut Evidence) -> Result<(), c_int> {
    if r.reset_count != view.reset_count {
        return Ok(());
    }
    if r.pcr != view.pcr || r.sequence > i64::MAX as u64 || r.initial_pcr != view.initial_pcr {
        return Err(-EUCLEAN);
    }
    match view.append_event(&r.target.root_hash, r.sequence, r.kind) {
        0 => Ok(()),
        err => Err(err),
    }
}

/// The evidence of the active config from the journal, or none without
/// one.
pub(crate) fn collect(update: Option<&ConfigUpdate<'_>>) -> Result<Evidence, c_int> {
    let mut view = Evidence::default();

    let Some(update) = update else {
        return Ok(view);
    };
    let active = update.check()?;
    view.pcr = active.pcr;
    view.reset_count = active.reset_count;
    view.restart_count = active.restart_count;
    view.initial_pcr = active.initial_pcr;
    let mut ret = update
        .events(|r| collect_event(r, &mut view))
        .err()
        .unwrap_or(0);
    if ret == 0 {
        let mut value = [0u8; 32];

        ret = replay(&view, &mut value);
        if ret == 0 {
            view.value = value;
        }
    }
    if ret == 0
        && view.events.last().is_none_or(|last| {
            last.sequence != active.sequence || last.root_hash != active.target.root_hash
        })
    {
        ret = -EUCLEAN;
    }
    if ret != 0 {
        return Err(ret);
    }
    view.present = true;
    Ok(view)
}

/// The view as the `config` object of the evidence: -EOVERFLOW for a
/// sequence past an int64, or the emitter's error.
pub(crate) fn emit(e: &mut JsonEmit, view: &Evidence) -> Result<(), c_int> {
    if !view.present {
        return Ok(());
    }
    e.obj_open_key(b"config");
    e.kv_int(b"schema", 1);
    e.kv_int(b"pcr", i64::from(view.pcr));
    e.kv_int(b"reset_count", i64::from(view.reset_count));
    e.kv_int(b"restart_count", i64::from(view.restart_count));
    e.kv_string(b"initial_pcr", &hex::encode(&view.initial_pcr));
    e.arr_open(b"events");
    for event in &view.events {
        let Ok(sequence) = i64::try_from(event.sequence) else {
            return Err(-EOVERFLOW);
        };
        e.obj_open();
        e.kv_int(b"sequence", sequence);
        e.kv_int(b"kind", i64::from(event.kind));
        e.kv_string(b"root_hash", &hex::encode(&event.root_hash));
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    match e.err() {
        0 => Ok(()),
        err => Err(err),
    }
}

/// What the schema of the `config` object fills, and the view its
/// events go to.
struct ConfigParser {
    view: Evidence,
    schema: i64,
    pcr: i64,
    reset: i64,
    restart: i64,
    initial: [u8; 65],
    sequence: i64,
    kind: i64,
    root_hash: [u8; 65],
}

/// Adds the event the parser holds to its view; `fields` are the
/// event's, every one of which it must give.
fn on_event(p: &mut ConfigParser, fields: &[JsonField<'_, ConfigParser>]) -> Result<(), c_int> {
    let mut root_hash = [0u8; 32];

    if !fields.iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    let (sequence, kind) = (p.sequence, p.kind);

    if sequence <= 0
        || (kind != i64::from(EVENT_BOOT) && kind != i64::from(EVENT_UPDATE))
        || hex::decode(cstr(&p.root_hash), &mut root_hash).is_err()
    {
        return Err(-EINVAL);
    }
    // Both in range, checked above.
    let (Ok(sequence), Ok(kind)) = (u64::try_from(sequence), c_int::try_from(kind)) else {
        return Err(-EINVAL);
    };
    match p.view.append_event(&root_hash, sequence, kind) {
        0 => Ok(()),
        err => Err(err),
    }
}

/// The view the fields of a `config` object the parser read make, which
/// it must give whole and in range.
fn config_view(p: ConfigParser) -> Result<Evidence, c_int> {
    let ConfigParser {
        mut view,
        schema,
        pcr,
        reset,
        restart,
        initial,
        ..
    } = p;
    let (Ok(pcr), Ok(reset), Ok(restart)) = (
        u32::try_from(pcr),
        u32::try_from(reset),
        u32::try_from(restart),
    ) else {
        return Err(-EINVAL);
    };

    if schema != 1
        || pcr_valid(pcr) != 0
        || hex::decode(cstr(&initial), &mut view.initial_pcr).is_err()
    {
        return Err(-EINVAL);
    }
    view.pcr = pcr;
    view.reset_count = reset;
    view.restart_count = restart;
    let mut value = [0u8; 32];
    let ret = replay(&view, &mut value);
    if ret != 0 {
        return Err(ret);
    }
    view.value = value;
    view.present = true;
    Ok(view)
}

/// The `config` object of evidence a verifier received, or a view not
/// present when there is none.
pub(crate) fn parse(evidence: &[u8]) -> Result<Evidence, c_int> {
    let mut parser = ConfigParser {
        view: Evidence::default(),
        schema: 0,
        pcr: 0,
        reset: 0,
        restart: 0,
        initial: [0; 65],
        sequence: 0,
        kind: 0,
        root_hash: [0; 65],
    };
    let event_fields = [
        JsonField::int(c"sequence", |p: &mut ConfigParser| &mut p.sequence),
        JsonField::int(c"kind", |p| &mut p.kind),
        JsonField::string(c"root_hash", |p| &mut p.root_hash),
    ];
    let take_event = |p: &mut ConfigParser| on_event(p, &event_fields);
    let config_fields = [
        JsonField::int(c"schema", |p: &mut ConfigParser| &mut p.schema),
        JsonField::int(c"pcr", |p| &mut p.pcr),
        JsonField::int(c"reset_count", |p| &mut p.reset),
        JsonField::int(c"restart_count", |p| &mut p.restart),
        JsonField::string(c"initial_pcr", |p| &mut p.initial),
        JsonField::array(c"events", &event_fields, &take_event),
    ];
    let top = [JsonField::object(c"config", &config_fields)];

    parse_schema(evidence, &top, &mut parser)?;
    if !top[0].seen() {
        return Ok(Evidence::default());
    }
    if !config_fields.iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    config_view(parser)
}

/// What a quote says: the PCRs it covers, the TPM boot it was made in,
/// and the PCR values.
pub(crate) struct Quote<'a> {
    pub(crate) mask: u32,
    pub(crate) reset: u32,
    pub(crate) pcrs: &'a [[u8; 32]; 24],
    pub(crate) nvpcr: Option<&'a [u8; 32]>,
}

/// Whether the evidence is the history of the quoted config PCR, in the
/// quote's TPM boot, ending in the root an operator approved: 0 or
/// -EKEYREJECTED, and the reason.
pub(crate) fn verify(
    view: &Evidence,
    quote: &Quote,
    expected_root: Option<&[u8; 32]>,
    expected_pcr: Option<u32>,
) -> (c_int, &'static CStr) {
    let mut value = [0u8; 32];

    if !view.present {
        let ret = if expected_root.is_some() || expected_pcr.is_some() {
            -EKEYREJECTED
        } else {
            0
        };

        return (ret, c"configuration evidence is missing");
    }
    if pcr_valid(view.pcr) != 0 || expected_pcr.is_some_and(|pcr| view.pcr != pcr) {
        return (-EKEYREJECTED, c"config PCR is unquoted or unexpected");
    }
    let live = if nvpcr(view.pcr) {
        let Some(certified) = quote.nvpcr else {
            return (-EKEYREJECTED, c"config NvPCR is not certified");
        };
        let mut initial = [0u8; 32];
        let ret = nvpcr_initial(&mut initial);
        if ret != 0 {
            return (ret, c"config root history matches the certified NvPCR");
        }
        if view.initial_pcr != initial {
            return (
                -EKEYREJECTED,
                c"config history does not start at the NvPCR's initial value",
            );
        }
        certified
    } else {
        if quote.mask & (1u32 << view.pcr) == 0 {
            return (-EKEYREJECTED, c"config PCR is unquoted or unexpected");
        }
        &quote.pcrs[view.pcr as usize]
    };
    if view.reset_count != quote.reset {
        return (-EKEYREJECTED, c"config history belongs to another TPM boot");
    }
    if expected_root.is_some() && expected_pcr.is_none() {
        return (-EKEYREJECTED, c"expected config root needs an expected PCR");
    }
    let ret = replay(view, &mut value);
    if ret != 0 || value != *live {
        let reason = if nvpcr(view.pcr) {
            c"config history does not match the certified NvPCR"
        } else {
            c"config history does not match the quoted PCR"
        };
        return (if ret != 0 { ret } else { -EKEYREJECTED }, reason);
    }
    if let Some(root) = expected_root
        && view
            .events
            .last()
            .is_none_or(|last| last.root_hash != *root)
    {
        return (
            -EKEYREJECTED,
            c"config root was not approved by the operator",
        );
    }
    (
        0,
        if nvpcr(view.pcr) {
            c"config root history matches the certified NvPCR"
        } else {
            c"config root history matches the quoted PCR"
        },
    )
}

#[cfg(test)]
mod tests;
