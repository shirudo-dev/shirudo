// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo bpm tree sync`: the signed upatch tree applied on a target,
//! each operation measured into the register and logged in the tree
//! eventlog before the cursor moves past it, and its outcome recorded
//! with the history root after it. A node behind the segment the tag
//! names walks back through the sealed segments to the one its cursor
//! lies in, and then forwards through them, oldest first.

use core::ffi::c_int;

use super::{
    Result, TREE_PENDING_PATH, TREE_STATUS_DIR, curl_ready, error, fail, finish, lock, message,
    path, print, remove, status, warn,
};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOMEM, ERANGE};
use crate::sys::upatch::UPATCH_INSTALL_TARGET_MISSING;
use crate::text::{cstr, strscpy};
use crate::util::bpm_oci::Client;
use crate::util::bpm_package::fetch_publication;
use crate::util::bpm_tree::{
    MAX_JOIN_OPS, MAX_WALK_OPS, TreeOperation, TreePublication, TreeState, digest_bytes,
    history_at, publication_follows, publication_verify, segment_precedes, walk_within,
};
use crate::util::bpm_tree_state::{
    OUTCOME_APPLIED, OUTCOME_MODULE_ABSENT, OUTCOME_UNMATCHED, configured, event_append,
    event_replay, outcome_append, outcome_roots, outcomes_resume, pending_read, pending_write,
    selector_matches, state_read, state_write,
};
use crate::util::chain::{self, history_step, memneq_explicit, sha256_parts};
use crate::util::eventlog;
use crate::util::hex::sha256_digest_encode;
use crate::util::json::JsonEmit;
use crate::util::keys::{TrustedSet, load_image_root};
use crate::util::seal::{self, Output};
use crate::util::{image_config, image_keys, initrd, java_agent, upatch, upatch_pins};

/// The lowercase hex of `bytes` into `out`, NUL-terminated.
fn hex_into(bytes: &[u8; 32], out: &mut [u8; 65]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    out[64] = 0;
}

/// The 32 bytes 64 hex digits of either case spell.
fn hex32(text: &[u8]) -> Option<[u8; 32]> {
    let hex = cstr(text);
    let mut out = [0; 32];

    if hex.len() != 64 {
        return None;
    }
    for (b, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0.iter()) {
        let digit = |c: u8| char::from(c).to_digit(16);
        *b = (digit(pair[0])? << 4 | digit(pair[1])?) as u8;
    }
    Some(out)
}

/// SHA-256 over `a` and then `b`.
fn hash2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    sha256_parts(a, b)
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A sync's failure in its log, with the operation it was at.
fn report_error(phase: &[u8], op: Option<&TreeOperation>, ret: c_int) {
    let rc = ret.to_string();
    let at = op.map_or_else(Vec::new, |op| {
        [
            b" seq=",
            op.seq.to_string().as_bytes(),
            b" id=",
            cstr(&op.id),
        ]
        .concat()
    });

    if ret > 0 {
        error(&[
            b"bpm tree sync: phase=",
            phase,
            &at,
            b" rc=",
            rc.as_bytes(),
            b" (command status)",
        ]);
        return;
    }
    let why: &[u8] = if ret < 0 {
        super::strerr(-ret)
    } else {
        b"success"
    };
    error(&[
        b"bpm tree sync: phase=",
        phase,
        &at,
        b" rc=",
        rc.as_bytes(),
        b" (",
        why,
        b")",
    ]);
}

/// A failure in the log, said in words, then by phase.
fn refuse(text: String, phase: &[u8], ret: c_int) -> c_int {
    error(&[b"bpm tree sync: ", text.as_bytes()]);
    report_error(phase, None, ret);
    ret
}

/// Event = SHA256("shirudo-tree\0" || seq || operation_digest), extended
/// into the register and recorded in the eventlog with the chain. The
/// tree's own projection stays a file chain; the register is what an
/// operator attests.
fn measure(op: &TreeOperation, digest: &[u8; 32]) -> Result {
    let _lock = eventlog::lock()?;
    measure_locked(op, digest)
}

/// Format the whole record with space reserved for the register value.
/// The value is always 64 hex digits, so it can be filled in after the
/// irreversible extend without another encoding step.
fn prepare_tree_record(
    op: &TreeOperation,
    event: &[u8; 32],
    line: &mut [u8; 4096],
) -> Result<(usize, usize)> {
    let mut e = JsonEmit::fixed(line);
    eventlog::record_open(&mut e, b"tree_op", event);
    e.obj_open_key(b"tree");
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"op", cstr(&op.op));
    e.kv_string(b"id", cstr(&op.id));
    e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    e.obj_close();
    e.key(b"chain");
    let chain_at = e.written() + 1; // after the opening quote
    e.str_value(&[b'0'; 64]);
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    Ok((e.written(), chain_at))
}

fn measure_locked(op: &TreeOperation, digest: &[u8; 32]) -> Result {
    let mut chain = [0; 32];
    let mut chain_hex = [0; 65];
    let mut line = [0u8; 4096];

    let event = chain::tree_event(op.seq, digest)?;
    let (len, chain_at) = prepare_tree_record(op, &event, &mut line)?;
    status(chain::extend(&event, Some(&mut chain)))?;
    hex_into(&chain, &mut chain_hex);
    line[chain_at..chain_at + 64].copy_from_slice(&chain_hex[..64]);
    status(eventlog::append(&line[..len]))
}

fn status_write(id: &[u8], text: &[u8]) -> Result {
    if !upatch::name_valid(Some(id)) || text.is_empty() {
        return Err(-EINVAL);
    }
    seal::mkdir_p(TREE_STATUS_DIR.as_bytes(), 0o700)?;
    let p = path(&[TREE_STATUS_DIR.as_bytes(), b"/", id])?;
    seal::write_file(p.to_bytes(), text, 0o600)
}

fn status_clear(id: &[u8]) {
    if upatch::name_valid(Some(id))
        && let Ok(p) = path(&[TREE_STATUS_DIR.as_bytes(), b"/", id])
    {
        remove(&p);
    }
}

/// The status file of an operation: one whose module was absent says
/// so, any other has none.
fn status_update(id: &[u8], module_absent: bool) -> Result {
    if module_absent {
        return status_write(id, b"skipped: module not loaded");
    }
    status_clear(id);
    Ok(())
}

/// The outcome of the operation at `seq` recorded, with the history
/// root moved past it.
fn outcome_record(
    seq: i64,
    digest: &[u8; 32],
    outcome: i64,
    projection_root: &[u8; 32],
    history_root: &mut [u8; 32],
) -> Result {
    *history_root = history_step(history_root, digest)?;
    status(outcome_append(seq, outcome, projection_root, history_root))
}

fn outcome_unmatched(
    op: &TreeOperation,
    projection_root: &[u8; 32],
    history_root: &mut [u8; 32],
) -> Result {
    let digest = digest_bytes(&op.operation_digest).ok_or(-EINVAL)?;
    outcome_record(
        op.seq,
        &digest,
        OUTCOME_UNMATCHED,
        projection_root,
        history_root,
    )
}

/// Completes the only non-idempotent window: the process may have
/// measured the operation, or appended its tree event too, before the
/// sealed cursor was committed. Applying it again would extend the
/// register with it a second time this boot. The install's answer went
/// with the process, so an add whose upatch is not loaded is one whose
/// module was absent.
fn recover_pending(
    p: &TreePublication,
    state: &mut TreeState,
    history_root: &mut [u8; 32],
) -> Result {
    let pending = match pending_read() {
        Err(err) if err == -ENOENT => return Ok(()),
        pending => pending?,
    };
    // The segment containing the pending operation may already be gone.
    if pending.seq <= state.last_seq {
        remove(TREE_PENDING_PATH);
        return Ok(());
    }
    let ops = &p.operations;
    let Some(op) = ops.iter().find(|op| {
        op.seq == pending.seq
            && cstr(&op.id) == cstr(&pending.id)
            && cstr(&op.operation_digest) == cstr(&pending.operation_digest)
    }) else {
        return Err(-ERANGE);
    };
    let (Some(digest), Some(previous)) = (
        digest_bytes(&pending.operation_digest),
        hex32(&state.projection_root),
    ) else {
        return Err(-EINVAL);
    };
    let next = hash2(&previous, &digest)?;
    let (mut applied, mut event_present) = (false, false);
    match event_replay() {
        Ok(replay) if !memneq_explicit(&replay, &next) => {
            applied = true;
            event_present = true;
        }
        Ok(replay) if memneq_explicit(&replay, &previous) => return Err(-EKEYREJECTED),
        Ok(_) => {}
        Err(err) if err == -ENOENT => {}
        Err(_) => return Err(-EKEYREJECTED),
    }
    if !applied {
        match eventlog::tree_op_measured(op.seq, cstr(&op.operation_digest)) {
            r if r < 0 => return Err(-EKEYREJECTED),
            // Still pre-operation; retry normally.
            0 => return Ok(()),
            _ => {}
        }
    }
    if !event_present {
        event_append(op.seq, cstr(&op.operation_digest), &next)?;
    }
    // The operations between the cursor and the pending one had no
    // match in the sync that stopped: it would have committed the cursor
    // at one that had.
    for passed in ops
        .iter()
        .filter(|o| o.seq > state.last_seq && o.seq < op.seq)
    {
        outcome_unmatched(passed, &previous, history_root)?;
    }
    let absent = if cstr(&op.op) == b"add" {
        !upatch_pins::loaded_pins(cstr(&op.id))? && !java_agent::loaded(cstr(&op.id))
    } else {
        false
    };
    let outcome = if absent {
        OUTCOME_MODULE_ABSENT
    } else {
        OUTCOME_APPLIED
    };
    outcome_record(op.seq, &digest, outcome, &next, history_root)?;
    hex_into(&next, &mut state.projection_root);
    hex_into(&next, &mut state.projection_root_tpm);
    state.last_seq = op.seq;
    state_write(state)?;
    status_update(cstr(&op.id), absent)?;
    remove(TREE_PENDING_PATH);
    Ok(())
}

/// Where the tree is published, and what its publications are checked
/// against: the config image's signing set, loaded once for every
/// segment a walk fetches, or the node's certificate without an image.
struct Source {
    c: Client,
    repository: Vec<u8>,
    trusted: Option<TrustedSet>,
}

impl Source {
    fn open(cfg: &super::source::TreeConfig) -> Result<Self> {
        let mut c = Client::new();
        let repository = c.parse_tree_repo(cstr(&cfg.endpoint))?;
        let mut src = Source {
            c,
            repository,
            trusted: None,
        };

        if !image_config::active() {
            return Ok(src);
        }
        let set = match load_image_root(initrd::cert_path(), image_config::root_fd(), true) {
            Ok(set) => set,
            Err(ret) => {
                let why = String::from_utf8_lossy(super::strerr(-ret));
                return Err(refuse(
                    format!("the config image's keys cannot be read: {why}"),
                    b"trusted_set",
                    ret,
                ));
            }
        };
        if set.len() == 0 || set.n_unvouched() != 0 {
            return Err(refuse(
                format!(
                    "the config image trusts {} keys, {} of them not vouched for by the node's certificate",
                    set.len(),
                    set.n_unvouched()
                ),
                b"trusted_set",
                -EKEYREJECTED,
            ));
        }
        let ret = image_keys::check_set(&set);
        if ret != 0 {
            let why = String::from_utf8_lossy(super::strerr(-ret));
            return Err(refuse(
                format!("the kernel's BPF keyring does not hold the config image's keys: {why}"),
                b"trusted_set",
                ret,
            ));
        }
        src.trusted = Some(set);
        Ok(src)
    }

    /// The publication `reference` names, a tag or a manifest digest,
    /// signed and with what tree sync checks before it applies anything,
    /// and its manifest's digest.
    fn fetch_checked(&mut self, reference: &[u8]) -> Result<(TreePublication, Vec<u8>)> {
        let (p, digest) = fetch_publication(
            &mut self.c,
            &self.repository,
            reference,
            initrd::cert_path(),
            self.trusted.as_ref(),
        )?;
        match publication_verify(&p) {
            Ok(()) => Ok((p, digest)),
            Err((ret, bad)) => {
                if let Some(op) = bad.and_then(|i| p.operations.get(i)) {
                    report_error(b"operation_validate", Some(op), ret);
                }
                Err(ret)
            }
        }
    }
}

/// A segment the walk back passed: the forward pass fetches it again by
/// its manifest digest, which names the same bytes, so only this is
/// kept and not the document.
struct Segment {
    manifest_digest: [u8; 32],
    head_seq: i64,
}

fn segment(p: &TreePublication, manifest_digest: &[u8]) -> Result<Segment> {
    Ok(Segment {
        manifest_digest: digest_bytes(manifest_digest).ok_or(-EINVAL)?,
        head_seq: p.head_seq,
    })
}

/// Back from the publication the tag names to the segment the cursor
/// `last_seq` lies in, each sealed segment fetched by the digest its
/// successor names and checked as the one it names: the segments,
/// newest first. Nothing is applied before the whole chain is known,
/// and a gap, a fork or a walk past its limit refuses the sync.
fn walk_back(
    src: &mut Source,
    tag: &TreePublication,
    tag_digest: &[u8],
    last_seq: i64,
) -> Result<Vec<Segment>> {
    let mut walk = Vec::new();
    let mut fetched: Option<TreePublication> = None;

    walk.try_reserve(1).map_err(|_| -ENOMEM)?;
    walk.push(segment(tag, tag_digest)?);
    loop {
        let succ = fetched.as_ref().unwrap_or(tag);
        if succ.base_seq <= last_seq {
            return Ok(walk);
        }
        let within = walk_within(succ.base_seq, last_seq);
        if within != 0 {
            let limit = if last_seq != 0 {
                MAX_WALK_OPS
            } else {
                MAX_JOIN_OPS
            };
            return Err(refuse(
                format!(
                    "the segment that starts after seq {} is more than {limit} operations past seq {last_seq}, where this node is",
                    succ.base_seq
                ),
                b"segment_walk",
                within,
            ));
        }
        let named = lossy(cstr(&succ.segment_manifest_digest));
        let (pred, digest) = match src.fetch_checked(cstr(&succ.segment_manifest_digest)) {
            Ok(fetched) => fetched,
            Err(err) => {
                return Err(refuse(
                    format!(
                        "the sealed segment {named}, which ends at seq {}, cannot be fetched or does not verify",
                        succ.base_seq
                    ),
                    b"segment_fetch",
                    err,
                ));
            }
        };
        match segment_precedes(&pred, &digest, succ) {
            0 => {}
            err => {
                return Err(refuse(
                    format!(
                        "the sealed segment {named} is not the one before the segment that starts after seq {}",
                        succ.base_seq
                    ),
                    b"segment_chain",
                    err,
                ));
            }
        }
        walk.try_reserve(1).map_err(|_| -ENOMEM)?;
        walk.push(segment(&pred, &digest)?);
        fetched = Some(pred);
    }
}

/// What a sync counts.
#[derive(Default)]
struct Counts {
    selected: i64,
    skipped: i64,
    applied: i64,
    module_skipped: i64,
}

/// One sync: the node's state as it goes, and the history root at its
/// cursor.
struct Sync {
    state: TreeState,
    have_state: bool,
    history_root: [u8; 32],
    dry_run: bool,
    /// The cursor a dry run reports, which it moves in memory alone.
    dry_seq: i64,
    counts: Counts,
}

impl Sync {
    /// Acceptance steps 4 and 5: the segment starts where this node's
    /// history was at its base, and its operations up to the cursor are
    /// the ones the node processed, so a registry that serves another
    /// history than the one the node went through is refused, inside a
    /// segment as at its base.
    fn history_check(&self, p: &TreePublication) -> Result {
        let last_seq = self.state.last_seq;
        let node = if p.base_seq == last_seq {
            Ok(self.history_root)
        } else {
            outcome_roots(p.base_seq).map(|(_, history)| history)
        };
        let ret = match node.and_then(|node| history_at(p, p.base_seq).map(|doc| (node, doc))) {
            Ok((node, doc)) if memneq_explicit(&node, &doc) => -EKEYREJECTED,
            Ok(_) => 0,
            Err(err) => err,
        };
        if ret != 0 {
            return Err(refuse(
                format!(
                    "the segment that starts after seq {} does not start from this node's history there",
                    p.base_seq
                ),
                b"history_base",
                ret,
            ));
        }
        let ret = match history_at(p, last_seq) {
            Ok(doc) if memneq_explicit(&self.history_root, &doc) => -EKEYREJECTED,
            Ok(_) => 0,
            Err(err) => err,
        };
        if ret != 0 {
            return Err(refuse(
                format!(
                    "the operations of the publication up to seq {last_seq} are not the ones this node processed"
                ),
                b"history_prefix",
                ret,
            ));
        }
        Ok(())
    }

    /// Recorded before its first operation is processed, so that a sync
    /// that stops among them leaves the cursor within the publication
    /// the state names.
    fn record(&mut self, p: &TreePublication, manifest_digest: &[u8]) -> Result {
        let st = &mut self.state;

        st.generation = p.generation;
        let _ = strscpy(&mut st.manifest_digest, manifest_digest);
        st.head_seq = p.head_seq;
        st.segment_base_seq = p.base_seq;
        self.have_state = true;
        if self.dry_run {
            return Ok(());
        }
        state_write(st).inspect_err(|&ret| {
            report_error(b"tree_state_commit_accept", None, ret);
        })
    }

    /// Applies one selected operation: recorded as pending, its artifact
    /// fetched and checked, installed or removed, measured, logged in
    /// the tree eventlog, its outcome recorded, and the cursor committed
    /// past it. `root` is the projection root at the cursor.
    fn apply(&mut self, op: &TreeOperation, root: &mut [u8; 32]) -> Result {
        let failed = |phase: &[u8], ret: c_int| {
            report_error(phase, Some(op), ret);
            Err(ret)
        };
        let id = cstr(&op.id);

        let Some(digest) = digest_bytes(&op.operation_digest) else {
            return failed(b"operation_digest_parse", -EINVAL);
        };
        if let Err(ret) = pending_write(op) {
            return failed(b"pending_write", ret);
        }
        let artifact = match super::fetch::tree_artifact(op) {
            Ok(artifact) => artifact,
            Err(err) => return failed(b"artifact_fetch_or_verify", err),
        };
        let add = cstr(&op.op) == b"add";
        let mut ret = match cstr(&op.op) {
            b"add" => crate::builtin::upatch::install(&artifact),
            b"delete" => crate::builtin::upatch::remove(&artifact),
            _ => return Err(-EINVAL),
        };
        let skipped_module = add && ret == UPATCH_INSTALL_TARGET_MISSING;
        if skipped_module {
            ret = 0;
            self.counts.module_skipped += 1;
            warn(&[b"bpm tree: skipped ", id, b": module not loaded"]);
        }
        if ret != 0 {
            return failed(b"upatch_install", ret);
        }
        let next = match hash2(root, &digest) {
            Ok(next) => next,
            Err(err) => return failed(b"projection_root_hash", err),
        };
        if let Err(err) = measure(op, &digest) {
            return failed(b"register_extend", err);
        }
        *root = next;
        let st = &mut self.state;
        hex_into(&next, &mut st.projection_root);
        hex_into(&next, &mut st.projection_root_tpm);
        if let Err(ret) = event_append(op.seq, cstr(&op.operation_digest), &next) {
            return failed(b"tree_event_append", ret);
        }
        let outcome = if skipped_module {
            OUTCOME_MODULE_ABSENT
        } else {
            OUTCOME_APPLIED
        };
        if let Err(err) = outcome_record(op.seq, &digest, outcome, &next, &mut self.history_root) {
            return failed(b"tree_outcome_append", err);
        }
        st.last_seq = op.seq;
        self.counts.applied += 1;
        if let Err(ret) = state_write(st) {
            return failed(b"tree_state_commit", ret);
        }
        if let Err(err) = status_update(id, skipped_module) {
            return failed(b"tree_status_write", err);
        }
        remove(TREE_PENDING_PATH);
        Ok(())
    }

    fn apply_operations(&mut self, p: &TreePublication) -> Result {
        let Some(mut root) = hex32(&self.state.projection_root) else {
            report_error(b"projection_root_decode", None, -EINVAL);
            return Err(-EINVAL);
        };

        for op in &p.operations {
            if op.seq <= self.state.last_seq {
                continue;
            }
            let matched = selector_matches(&op.selector).inspect_err(|&err| {
                report_error(b"selector_evaluate", Some(op), err);
            })?;
            if matched {
                self.counts.selected += 1;
            } else {
                self.counts.skipped += 1;
            }
            if self.dry_run {
                // A dry run moves its cursor in memory alone, for a
                // walk to go on.
                let digest = digest_bytes(&op.operation_digest).ok_or(-EINVAL)?;
                self.state.last_seq = op.seq;
                self.history_root = history_step(&self.history_root, &digest)?;
                continue;
            }
            if !matched {
                if let Err(err) = outcome_unmatched(op, &root, &mut self.history_root) {
                    report_error(b"tree_outcome_append", Some(op), err);
                    return Err(err);
                }
                self.state.last_seq = op.seq;
                continue;
            }
            self.apply(op, &mut root)?;
        }
        Ok(())
    }

    /// Acceptance steps 4 to 6 and the operations of one segment, the
    /// oldest of a walk first, or of the one publication without a walk.
    /// Only the oldest has an operation left pending: the node records a
    /// segment before it processes any, so the state names the segment
    /// that operation is in, and the walk starts from that one.
    fn apply_segment(
        &mut self,
        p: &TreePublication,
        manifest_digest: &[u8],
        oldest: bool,
    ) -> Result {
        let follows =
            publication_follows(p, self.have_state.then_some(&self.state), manifest_digest);
        if follows != 0 {
            return Err(refuse(
                format!(
                    "the segment {} does not follow seq {}, where this node is",
                    lossy(manifest_digest),
                    self.state.last_seq
                ),
                b"segment_chain",
                if follows < 0 { follows } else { -ERANGE },
            ));
        }
        self.history_check(p)?;
        if oldest {
            if let Err(err) = recover_pending(p, &mut self.state, &mut self.history_root) {
                report_error(b"pending_recovery", None, err);
                return Err(err);
            }
            self.dry_seq = self.state.last_seq;
        }
        self.record(p, manifest_digest)?;
        self.apply_operations(p)
    }

    /// The walk forwards, oldest segment first: each sealed one fetched
    /// again by its digest and checked as before, and the tag's
    /// document, which the walk holds, last.
    fn walk_forward(
        &mut self,
        src: &mut Source,
        walk: &[Segment],
        tag: &TreePublication,
        tag_digest: &[u8],
    ) -> Result {
        let n = walk.len();

        for (i, seg) in walk.iter().enumerate().skip(1).rev() {
            let want = sha256_digest_encode(&seg.manifest_digest);
            let want = cstr(&want);
            let fetched = src
                .fetch_checked(want)
                .and_then(|(p, d)| match digest_bytes(&d) {
                    Some(got) if got == seg.manifest_digest => Ok((p, d)),
                    _ => Err(-ERANGE),
                });
            let (p, digest) = fetched.map_err(|err| {
                refuse(
                    format!(
                        "the sealed segment {}, which ends at seq {}, cannot be fetched again or has changed",
                        lossy(want),
                        seg.head_seq
                    ),
                    b"segment_fetch",
                    err,
                )
            })?;
            self.apply_segment(&p, &digest, i == n - 1)?;
        }
        self.apply_segment(tag, tag_digest, n == 1)
    }
}

/// The sync's report: to `path`, sealed, or else to stdout.
fn write_report(path: Option<&[u8]>, sync: &Sync, tpm: bool) -> Result {
    let (s, counts) = (&sync.state, &sync.counts);
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_bool(b"dry_run", sync.dry_run);
    e.kv_int(b"selected", counts.selected);
    e.kv_int(b"skipped", counts.skipped);
    e.kv_int(b"applied", counts.applied);
    e.kv_int(b"module_skipped", counts.module_skipped);
    e.kv_bool(b"tpm_available", tpm);
    e.kv_int(b"last_seq", s.last_seq);
    if tpm {
        e.kv_string(b"projection_root_tpm", cstr(&s.projection_root_tpm));
    } else {
        e.kv_null(b"projection_root_tpm");
    }
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    let body = e.output();
    let Some(path) = path else {
        print(&[body, b"\n"].concat());
        return Ok(());
    };
    Output::create(message(&[path]).to_bytes(), 0o600)?.commit(body)
}

/// The sync, a dry run that changes nothing or one that applies, and
/// its report to `report`, standard output for none or "-".
fn sync(dry_run: bool, report: Option<&[u8]>) -> Result {
    if report.is_some_and(|r| r.len() >= crate::sys::libc::PATH_MAX) {
        return Err(-ENAMETOOLONG);
    }
    // Optional integration: manual `shirudo upatch` remains valid.
    let cfg = match super::source::load_tree() {
        Err(err) if err == -ENOENT => return Ok(()),
        cfg => cfg?,
    };
    let mut sync = Sync {
        state: TreeState::default(),
        have_state: false,
        history_root: [0; 32],
        dry_run,
        dry_seq: 0,
        counts: Counts::default(),
    };
    match state_read() {
        Ok(state) => {
            sync.state = state;
            sync.have_state = true;
        }
        Err(err) if err == -ENOENT => {}
        Err(err) => return Err(err),
    }
    let mut src = Source::open(&cfg)?;
    let against = if src.trusted.is_some() {
        "the config image's keys"
    } else {
        "the node's certificate"
    };
    let (tag, tag_digest) = src.fetch_checked(cstr(&cfg.reference)).map_err(|err| {
        let named = String::from_utf8_lossy(cstr(&cfg.reference));
        let what = if err == -EKEYREJECTED {
            format!("the publication {named} does not verify against {against}")
        } else {
            format!("the publication {named} cannot be fetched")
        };
        refuse(what, b"publication_fetch", err)
    })?;
    let p = &tag;
    let follows = publication_follows(p, sync.have_state.then_some(&sync.state), &tag_digest);
    if follows < 0 {
        return Err(follows);
    }
    if !sync.have_state {
        let st = &mut sync.state;
        st.schema = 1;
        let _ = strscpy(&mut st.tree_id, cstr(&p.tree_id));
        st.projection_root[..64].fill(b'0');
        st.projection_root[64] = 0;
        st.projection_root_tpm[..64].fill(b'0');
        st.projection_root_tpm[64] = 0;
    }
    sync.history_root = outcomes_resume(sync.state.last_seq).inspect_err(|&err| {
        report_error(b"outcomes_check", None, err);
    })?;
    let walk = walk_back(&mut src, p, &tag_digest, sync.state.last_seq)?;
    sync.walk_forward(&mut src, &walk, p, &tag_digest)?;
    // A run of operations without a match at the end moved the cursor.
    if !dry_run {
        state_write(&sync.state).inspect_err(|&ret| {
            report_error(b"tree_state_commit_final", None, ret);
        })?;
    } else {
        sync.state.last_seq = sync.dry_seq;
    }
    // "-" is standard output, where the report goes without --report.
    let to = report.filter(|r| !r.is_empty() && *r != b"-");
    write_report(to, &sync, chain::bound())
}

/// `shirudo bpm tree sync`, which takes the bpm lock only once a tree is
/// configured, so that a node without one needs no writable state.
pub(super) fn sync_cmd(dry_run: bool, report: Option<&[u8]>) -> c_int {
    if !configured() {
        return 0;
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    finish(Some(held), sync(dry_run, report), b"tree sync")
}

#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "gmtime_r is a foreign call")]
    fn prepared_tree_record_has_room_for_the_register_value() {
        let op = TreeOperation {
            seq: 1,
            ..TreeOperation::default()
        };
        let mut line = [0u8; 4096];
        let (len, at) = prepare_tree_record(&op, &[0x42; 32], &mut line).unwrap();
        assert_eq!(&line[at..at + 64], &[b'0'; 64]);
        line[at..at + 64].copy_from_slice(&[b'a'; 64]);
        assert!(crate::util::json::parse_schema(&line[..len], &[], &mut ()).is_ok());
        assert!(line[..len].windows(74).any(|part| part
            == b"\"chain\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
    }
}
