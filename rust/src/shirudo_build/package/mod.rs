// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The packager: a BPF object into a signed `.upatch`. The object is
//! read as libbpf reads it and its loader program and data generated as
//! libbpf's gen_loader generates them (crate::bpf); the
//! attach metadata, the decoders, the policy labels and the name are
//! signed with the data, past the end the loader addresses; CMS signs
//! the loader and the data; and the container puts a header in front.
//! An unload directive is the embedded unload template so packaged,
//! naming the upatch and the payload it unloads. Setting .rodata writes
//! values into named symbols of a signed package, each found and its
//! size checked through the package's BTF, and signs it anew.

mod decoders;
mod meta;

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use super::{KeyFiles, error, info, strerr};
use crate::bpf::object::{self, GenOpts, Object};
use crate::errno::{E2BIG, EBADMSG, EFBIG, EINVAL, ENAMETOOLONG, ENOENT, EOPNOTSUPP, EOVERFLOW};
use crate::util::bpm_package::verify_cms;
use crate::util::crypto_openssl::sha256;
use crate::util::help::{Help, HelpSection, print_help};
use crate::util::io;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::upatch::{
    self, DIRECTIVE_UNLOAD, FILE_MAX, HEADER_SIZE, MAGIC, MAPS_MAX, NAME_MAX, PAYLOAD_HASH_LEN,
    POLICY_LABEL_ENTRY, POLICY_LABEL_HEADER, POLICY_LABELS_MAGIC, POLICY_LABELS_VERSION,
    SECTION_ATTACH, SECTION_DECODERS, SECTION_JAR, SECTION_NAME, SECTION_POLICY_LABELS,
    SECTION_TYPE, SECTION_UNLOAD, SIGNED_SECTION, SIGNED_SECTIONS_MAX, SIGNED_TRAILER,
    SIGNED_TRAILER_MAGIC, SIGNED_VERSION, TYPE_BPF, TYPE_JAVA, Upatch, VERSION,
};
use crate::util::upatch_rodata::{self, RodataRange};

/// A detached CMS over an ML-DSA-87 signature is about 5 KiB (a
/// 4627-byte signature and its SignerInfo); the kernel caps
/// attr.signature_size at 64 KiB.
const MAX_SIG_SIZE: usize = 16384;
/// The verifier log the target gives a load.
const LOG_BUF_SZ: u32 = 1024 * 1024;
/// The symbols one `upatch set` sets at most.
const SET_MAX: usize = 16;
const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
const BPF_MAP_TYPE_TASK_STORAGE: u32 = 29;
const BPF_F_NO_PREALLOC: u32 = 1;
const BPF_F_CLONE: u32 = 1 << 9;
/// `NAME_MAX` of `<limits.h>`, which the name rule's message quotes.
const PIN_NAME_MAX: usize = 255;

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// The fields of a container's header.
struct Header<'a> {
    name: &'a [u8],
    ty: u32,
    flags: u32,
    payload_sha256: &'a [u8; 32],
    loader: (u32, u32),
    signature: (u32, u32),
    data: (u32, u32),
    log_buf_sz: u32,
    rodata_data_off: u32,
    nr_maps: u32,
    nr_progs: u32,
}

impl Header<'_> {
    /// `struct upatch_header`, little-endian.
    fn bytes(&self) -> [u8; HEADER_SIZE] {
        let mut h = [0u8; HEADER_SIZE];
        let name = &self.name[..self.name.len().min(NAME_MAX - 1)];

        h[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        put32(&mut h, 8, VERSION);
        put32(&mut h, 12, self.flags);
        h[16..16 + name.len()].copy_from_slice(name);
        h[272..304].copy_from_slice(self.payload_sha256);
        let fields = [
            self.loader.0,
            self.loader.1,
            self.signature.0,
            self.signature.1,
            0, // reserved2
            0, // reserved3
            self.data.0,
            self.data.1,
            self.log_buf_sz,
            self.nr_maps,
            self.nr_progs,
            self.rodata_data_off,
            self.ty,
        ];
        for (i, v) in fields.into_iter().enumerate() {
            put32(&mut h, 304 + 4 * i, v);
        }
        h
    }
}

/// A signed section: its tag and its bytes.
struct Section<'a>(u32, &'a [u8]);

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// data || sections, each at an 8-byte boundary || directory || trailer.
/// The loader addresses nothing past its own data, so the sections are
/// invisible to it and the kernel signs them with the rest.
fn compose_signed_data(data: &[u8], sections: &[Section]) -> Result<Vec<u8>, c_int> {
    let n = sections.len();

    if n == 0 || n > SIGNED_SECTIONS_MAX as usize {
        return Err(-EINVAL);
    }
    let mut end = data.len();
    for s in sections {
        end = align8(end) + s.1.len();
    }
    let dir_off = align8(end);
    let total = dir_off + n * SIGNED_SECTION + SIGNED_TRAILER;
    if total > u32::MAX as usize {
        return Err(-EOVERFLOW);
    }
    let mut buf = vec![0u8; total];
    buf[..data.len()].copy_from_slice(data);
    let mut at = data.len();
    for (i, s) in sections.iter().enumerate() {
        at = align8(at);
        buf[at..at + s.1.len()].copy_from_slice(s.1);
        let d = dir_off + i * SIGNED_SECTION;
        put32(&mut buf, d, s.0);
        put32(&mut buf, d + 8, at as u32);
        put32(&mut buf, d + 12, s.1.len() as u32);
        at += s.1.len();
    }
    let t = dir_off + n * SIGNED_SECTION;
    put32(&mut buf, t, SIGNED_TRAILER_MAGIC);
    put32(&mut buf, t + 4, SIGNED_VERSION);
    put32(&mut buf, t + 8, dir_off as u32);
    put32(&mut buf, t + 12, n as u32);
    Ok(buf)
}

/// CMS over `insns` and `data`: the signature, and the SHA-256 of the
/// two the header carries.
fn sign(insns: &[u8], data: &[u8], keys: (&CStr, &CStr)) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    super::sign::cms_sign(insns, data, MAX_SIG_SIZE, keys.0, keys.1)
}

/// Where the variable `symbol` lies in the .rodata of the container `u`.
fn symbol_range(u: &Upatch, symbol: &CStr) -> Result<RodataRange, c_int> {
    let mut range = RodataRange { offset: 0, size: 0 };
    match upatch_rodata::symbol_range(u, symbol, &mut range) {
        0 => Ok(range),
        err => Err(err),
    }
}

/// The CMS covers the loader and data. The payload digest in the
/// unsigned header must also match those bytes.
fn verify_payload(u: &Upatch, cert: &CStr) -> Result<(), c_int> {
    let payload = [u.loader(), u.data()].concat();
    let ret = verify_cms(&payload, u.signature(), cert);
    if ret != 0 {
        return Err(ret);
    }
    if sha256(&payload).map_err(|_| -EBADMSG)? != u.hdr.payload_sha256 {
        return Err(-EBADMSG);
    }
    Ok(())
}

/// An output that is the input, under whatever name, is refused before
/// it is truncated, so that a write that fails cannot take the input
/// with it.
fn output_is_input(out: &std::fs::File, input: &CStr) -> bool {
    let Ok(o) = out.metadata() else {
        return true;
    };
    std::fs::metadata(super::path(input.to_bytes()))
        .is_ok_and(|i| i.dev() == o.dev() && i.ino() == o.ino())
}

/// Signs `data` with the loader of `src` into `output`, a package with
/// the header of `src` but for where its parts lie and its digest.
fn write_signed(
    src: &Upatch,
    input: &CStr,
    data: &[u8],
    output: &CStr,
    keys: &KeyFiles,
) -> Result<(), SetFailed> {
    let (sig, digest) =
        sign(src.loader(), data, (&keys.pkey, &keys.cert)).map_err(SetFailed::Output)?;
    let (sh, insns_len) = (&src.hdr, src.loader().len());
    let loader_off = HEADER_SIZE;
    let sig_off = loader_off + insns_len;
    let data_off = sig_off + sig.len();
    let end = data_off + data.len();
    if end > u32::MAX as usize {
        return Err(SetFailed::Output(-EOVERFLOW));
    }
    if end > FILE_MAX {
        return Err(SetFailed::Output(-E2BIG));
    }
    let hdr = Header {
        name: src.name(),
        ty: sh.ty,
        flags: sh.flags,
        payload_sha256: &digest,
        loader: (loader_off as u32, insns_len as u32),
        signature: (sig_off as u32, sig.len() as u32),
        data: (
            if data.is_empty() { 0 } else { data_off as u32 },
            data.len() as u32,
        ),
        log_buf_sz: sh.log_buf_sz,
        rodata_data_off: sh.rodata_data_off,
        nr_maps: sh.nr_maps,
        nr_progs: sh.nr_progs,
    };
    let out_path = super::path(output.to_bytes());
    // Truncated only once it is known not to be the input.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(out_path);
    let mut file = file.map_err(|e| SetFailed::Output(io::errno_of(&e)))?;
    if output_is_input(&file, input) {
        return Err(SetFailed::OutputIsInput);
    }
    let written = file
        .set_len(0)
        .and_then(|()| {
            [&hdr.bytes()[..], src.loader(), &sig, data]
                .iter()
                .try_for_each(|b| file.write_all(b))
        })
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(out_path);
        return Err(SetFailed::Output(io::errno_of(&e)));
    }
    Ok(())
}

/// Why setting .rodata failed.
pub(super) enum SetFailed {
    /// The input does not open, or is an unload directive.
    Package(c_int),
    /// The input does not verify against the certificate.
    Unverified(c_int),
    /// Symbol `i` of the values is not one variable of the .rodata.
    Symbol(usize, c_int),
    /// Symbol `i` is given a second time.
    Twice(usize),
    /// The value of symbol `i` is not the symbol's size, which it gives.
    Size(usize, u32),
    /// The output is the input, under whatever name.
    OutputIsInput,
    /// Signing or writing the output.
    Output(c_int),
}

impl SetFailed {
    pub(super) fn errno(&self) -> c_int {
        match *self {
            SetFailed::Package(err)
            | SetFailed::Unverified(err)
            | SetFailed::Symbol(_, err)
            | SetFailed::Output(err) => err,
            SetFailed::Twice(_) | SetFailed::Size(..) | SetFailed::OutputIsInput => -EINVAL,
        }
    }
}

/// Sets each symbol of `values` in the .rodata of the package at
/// `input` to its value, the symbol found and its size checked through
/// the package's BTF: where each lies in the loader data. With
/// `output`, the package must verify against the certificate, and the
/// result is signed there; without, nothing is written.
pub(super) fn set_rodata(
    input: &CStr,
    output: Option<(&CStr, &KeyFiles)>,
    values: &[(&CStr, &[u8])],
) -> Result<Vec<RodataRange>, SetFailed> {
    if values.is_empty() || values.len() > SET_MAX {
        return Err(SetFailed::Package(-EINVAL));
    }
    let twice = (1..values.len()).find(|&i| values[..i].iter().any(|(s, _)| *s == values[i].0));
    if let Some(i) = twice {
        return Err(SetFailed::Twice(i));
    }
    let src = upatch::Upatch::open(input).map_err(SetFailed::Package)?;
    if src.is_unload() {
        return Err(SetFailed::Package(-EINVAL));
    }
    if let Some((_, keys)) = output {
        verify_payload(&src, &keys.cert).map_err(SetFailed::Unverified)?;
    }
    let mut data = src.data().to_vec();
    let mut placed = Vec::with_capacity(values.len());
    for (i, &(symbol, value)) in values.iter().enumerate() {
        let r = symbol_range(&src, symbol).map_err(|e| SetFailed::Symbol(i, e))?;
        if value.is_empty() || Some(value.len()) != usize::try_from(r.size).ok() {
            return Err(SetFailed::Size(i, r.size));
        }
        let at = usize::try_from(r.offset).map_err(|_| SetFailed::Symbol(i, -EINVAL))?;
        data.get_mut(at..)
            .and_then(|tail| tail.get_mut(..value.len()))
            .ok_or(SetFailed::Symbol(i, -EINVAL))?
            .copy_from_slice(value);
        placed.push(r);
    }
    if let Some((output, keys)) = output {
        write_signed(&src, input, &data, output, keys)?;
    }
    Ok(placed)
}

/// Sets `symbol` in the .rodata of the package at `input` to `value` and
/// signs the result into `output`.
pub(super) fn patch_rodata(
    input: &CStr,
    output: &CStr,
    symbol: &CStr,
    value: &[u8],
    keys: &KeyFiles,
) -> Result<(), c_int> {
    set_rodata(input, Some((output, keys)), &[(symbol, value)])
        .map(|_| ())
        .map_err(|e| e.errno())
}

pub(super) fn verify_package(input: &CStr, cert: &CStr) -> Result<(), c_int> {
    let u = upatch::Upatch::open(input)?;
    if u.is_unload() {
        return Err(-EINVAL);
    }
    verify_payload(&u, cert)
}

const SET_OUTPUT: c_int = 0;
const SET_DRY_RUN: c_int = 1;
const SET_KEYS_DIR: c_int = 2;
const SET_KEY: c_int = 3;
const SET_CERT: c_int = 4;

static SET_OPTS: [OptSpec; 5] = [
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<output.upatch>"),
        c"where to write the re-signed upatch",
    ),
    OptSpec::new(
        c"--dry-run",
        0,
        0,
        None,
        c"check the variables and their values, without keys, and write nothing",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--key",
        0,
        0,
        Some(c"<signing_key.pem>"),
        c"the signing key, over --keys-dir",
    ),
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate, over --keys-dir",
    ),
];

static SET_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &SET_OPTS)];

static SET_HELP: Help = Help::new(
    c"shirudo-build upatch set <input.upatch> <symbol>=@<file>...\n              \
      (-o <output.upatch> | --dry-run) [options]",
    Some(
        c"Write each file's bytes into the .rodata variable of the upatch it names,\n\
          found through the upatch's BTF, and sign the upatch anew. A value is as\n\
          large as its variable.",
    ),
    &SET_SECTIONS,
    None,
);

/// `<symbol>=@<file>`: the symbol, and the bytes the file holds.
fn parse_value(arg: &CStr) -> Result<(CString, Vec<u8>), Vec<u8>> {
    let a = arg.to_bytes();
    let Some(eq) = a.iter().position(|&c| c == b'=') else {
        return Err([b"expected <symbol>=@<file>, not ", a].concat());
    };
    let (symbol, file) = (&a[..eq], &a[eq + 1..]);
    let Some(file) = file
        .strip_prefix(b"@")
        .filter(|f| !f.is_empty() && !symbol.is_empty())
    else {
        return Err([b"expected <symbol>=@<file>, not ", a].concat());
    };
    let value = match std::fs::read(super::path(file)) {
        Ok(v) if v.len() <= FILE_MAX => v,
        Ok(_) => return Err([file, b": ", strerr(EOVERFLOW)].concat()),
        Err(e) => return Err([file, b": ", strerr(-io::errno_of(&e))].concat()),
    };
    Ok((CString::new(symbol).unwrap_or_default(), value))
}

/// `shirudo-build upatch set`, from `upatch` on: each symbol's value
/// written into a signed package's .rodata, signed anew into the
/// output, or with --dry-run checked alone.
pub(super) fn upatch_cli(args: &[&CStr]) -> c_int {
    let mut keys = KeyFiles::default();
    let (mut input, mut output, mut keys_dir, mut dry_run) = (None, None, None, false);
    let mut sets: Vec<(CString, Vec<u8>)> = Vec::new();

    if args.get(1).map(|a| a.to_bytes()) != Some(b"set") {
        print_help(&SET_HELP);
        return EXIT_USAGE;
    }
    let mut p = OptParser::new(c"upatch set", &SET_OPTS, Some(&SET_HELP), args, 2);
    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            SET_OUTPUT => output = value,
            SET_DRY_RUN => dry_run = true,
            SET_KEYS_DIR => keys_dir = value,
            SET_KEY => keys.set_pkey(value.unwrap_or_default()),
            SET_CERT => keys.set_cert(value.unwrap_or_default()),
            OPT_ARG if input.is_none() => input = value,
            OPT_ARG => {
                if sets.len() == SET_MAX {
                    p.usage(format!("more than {SET_MAX} symbols").as_bytes());
                    return EXIT_USAGE;
                }
                match parse_value(value.unwrap_or_default()) {
                    Ok(v) => sets.push(v),
                    Err(msg) => {
                        p.usage(&msg);
                        return EXIT_USAGE;
                    }
                }
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(input), false) = (input, sets.is_empty()) else {
        p.usage(b"takes <input.upatch> and <symbol>=@<file>");
        return EXIT_USAGE;
    };
    if output.is_none() && !dry_run {
        p.usage(b"takes -o <output.upatch> or --dry-run");
        return EXIT_USAGE;
    }
    if !dry_run && keys.resolve(keys_dir).is_err() {
        return EXIT_USAGE;
    }
    let values: Vec<(&CStr, &[u8])> = sets.iter().map(|(s, v)| (s.as_c_str(), &v[..])).collect();
    let output = output.filter(|_| !dry_run);
    let placed = match set_rodata(input, output.map(|o| (o, &keys)), &values) {
        Ok(p) => p,
        Err(f) => {
            let (input, symbol) = (input.to_bytes(), |i: usize| values[i].0.to_bytes());
            let msg = match f {
                SetFailed::Package(err) => [input, b": ", strerr(-err)].concat(),
                SetFailed::Unverified(err) => {
                    let cert = keys.cert.to_bytes();
                    [
                        input,
                        b": does not verify against ",
                        cert,
                        b": ",
                        strerr(-err),
                    ]
                    .concat()
                }
                SetFailed::Symbol(i, err) if err == -ENOENT => {
                    [b"no .rodata variable ", symbol(i), b" in ", input].concat()
                }
                SetFailed::Symbol(i, err) => [symbol(i), b": ", strerr(-err)].concat(),
                SetFailed::Twice(i) => [symbol(i), b" given twice"].concat(),
                SetFailed::Size(i, size) => format!(
                    "{}: the value is {} bytes, the variable {size}",
                    String::from_utf8_lossy(symbol(i)),
                    values[i].1.len()
                )
                .into_bytes(),
                SetFailed::OutputIsInput => b"the output is the input".to_vec(),
                SetFailed::Output(err) => {
                    let out = output.map_or(&b""[..], CStr::to_bytes);
                    [out, b": ", strerr(-err)].concat()
                }
            };
            error(&[b"upatch set: ", &msg[..]].concat());
            return 1;
        }
    };
    let mut out = String::new();
    for ((symbol, _), r) in values.iter().zip(&placed) {
        out += &format!(
            "{}: {} bytes at data offset {}\n",
            String::from_utf8_lossy(symbol.to_bytes()),
            r.size,
            r.offset
        );
    }
    if dry_run {
        out += "dry run: nothing written\n";
    }
    super::print(true, out.as_bytes());
    0
}

/// Every target refuses a name upatch_name_valid() does not take.
fn check_name(name: &[u8]) -> Result<(), c_int> {
    if upatch::name_valid(Some(name)) {
        return Ok(());
    }
    error(
        format!(
            "upatch name '{}' is not 1 to {PIN_NAME_MAX} characters of [A-Za-z0-9._-], each '.' counting as two, not starting with '.'",
            String::from_utf8_lossy(name)
        )
        .as_bytes(),
    );
    Err(-EINVAL)
}

/// What a package is made of besides its object.
struct Contents<'a> {
    name: &'a CStr,
    flags: u32,
    unload_payload: &'a [u8; 32],
    src_path: Option<&'a CStr>,
    policy_labels: &'a [u8],
}

/// The object as a signed package at `out`.
fn finalize(mut obj: Object, out: &CStr, c: &Contents, keys: (&CStr, &CStr)) -> Result<(), c_int> {
    // The loader writes map_fd/prog_fd back into descriptor arrays past
    // its ctx, in the order libbpf iterates the object; the target finds
    // prog_fd[] after BPF_PROG_TEST_RUN by these counts. The attach
    // metadata comes before the loader so that an unsupported section
    // fails with shirudo's diagnostic, not the generator's.
    let nr_maps = u32::try_from(obj.maps.len()).map_err(|_| -E2BIG)?;
    let nr_progs = u32::try_from(obj.programs().count()).map_err(|_| -E2BIG)?;
    let unloading = c.flags & DIRECTIVE_UNLOAD != 0;
    let name = c.name.to_bytes();
    let (mut attach_meta, mut decoder_blob, mut nr_decoders) = (Vec::new(), Vec::new(), 0);

    if !unloading {
        attach_meta = meta::prog_metadata(&obj, nr_maps, nr_progs)?;
        (decoder_blob, nr_decoders) = decoders::blob(&obj, c.src_path.map(CStr::to_bytes), name)?;
    }
    let mut opts = GenOpts {
        gen_hash: true,
        reuse_map_mask: 0,
    };
    if !c.policy_labels.is_empty() {
        let le = |off: usize| {
            c.policy_labels
                .get(off..off + 4)?
                .try_into()
                .ok()
                .map(u32::from_le_bytes)
        };
        let (map_idx, socket_idx) = le(12).zip(le(16)).ok_or(-EINVAL)?;
        if map_idx >= nr_maps
            || map_idx >= MAPS_MAX
            || socket_idx >= nr_maps
            || socket_idx >= MAPS_MAX
            || map_idx == socket_idx
        {
            return Err(-EINVAL);
        }
        opts.reuse_map_mask = (1u64 << map_idx) | (1u64 << socket_idx);
    }
    let (insns, data) = match obj.gen_loader(&opts) {
        Ok(l) => l,
        Err(err) => {
            error(format!("generate loader: {err}").as_bytes());
            return Err(err);
        }
    };
    // The name the pin, the archive and the register event carry, the
    // attach sites, the unload target: signed with the data, since the
    // header is not.
    if name.len() >= NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut signed_name = [0u8; NAME_MAX];
    signed_name[..name.len()].copy_from_slice(name);
    let mut sections = vec![Section(SECTION_NAME, &signed_name)];
    if unloading {
        sections.push(Section(SECTION_UNLOAD, c.unload_payload));
    } else {
        sections.push(Section(SECTION_ATTACH, &attach_meta));
        if !decoder_blob.is_empty() {
            sections.push(Section(SECTION_DECODERS, &decoder_blob));
        }
        if !c.policy_labels.is_empty() {
            sections.push(Section(SECTION_POLICY_LABELS, c.policy_labels));
        }
    }
    let insns = &insns[..];
    let signed = compose_signed_data(&data, &sections)?;
    if u32::try_from(insns.len()).is_err() || u32::try_from(signed.len()).is_err() {
        return Err(-E2BIG);
    }
    let rodata_data_off = match upatch_rodata::loader_data_offset(insns, &signed) {
        Ok(off) => off,
        Err(err) if err == -ENOENT => 0,
        Err(err) => return Err(err),
    };
    let (sig, digest) = match sign(insns, &signed, keys) {
        Ok(s) => s,
        Err(err) => {
            error(format!("cms_sign: {err}").as_bytes());
            return Err(err);
        }
    };
    let sig_off = HEADER_SIZE + insns.len();
    let data_off = sig_off + sig.len();
    if data_off > FILE_MAX || signed.len() > FILE_MAX - data_off {
        return Err(-E2BIG);
    }
    let hdr = Header {
        name,
        ty: TYPE_BPF,
        flags: c.flags,
        payload_sha256: &digest,
        loader: (HEADER_SIZE as u32, insns.len() as u32),
        signature: (sig_off as u32, sig.len() as u32),
        data: (data_off as u32, signed.len() as u32),
        log_buf_sz: LOG_BUF_SZ,
        rodata_data_off,
        nr_maps,
        nr_progs,
    };
    let out_path = super::path(out.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(out_path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            let err = io::errno_of(&e);
            error(&[b"open ", out.to_bytes(), b": ", strerr(-err)].concat());
            return Err(err);
        }
    };
    let written = [&hdr.bytes()[..], insns, &sig, &signed]
        .iter()
        .try_for_each(|b| file.write_all(b))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(out_path);
        return Err(io::errno_of(&e));
    }
    let directive = if unloading { " UNLOAD" } else { "" };
    let msg = format!(
        "wrote {} (insns={} sig={} data={} sections={} maps={nr_maps} progs={nr_progs} decoders={nr_decoders} name={}{directive})",
        String::from_utf8_lossy(out.to_bytes()),
        insns.len(),
        sig.len(),
        signed.len(),
        sections.len(),
        String::from_utf8_lossy(name),
    );
    info(msg.as_bytes());
    Ok(())
}

/// A Java upatch has no loader: its data is the signed sections alone,
/// NAME and PTYP, then the jar of a load or the digest an unload expects.
/// The target verifies the signature over that data in userspace.
fn finalize_java(
    out: &CStr,
    name: &CStr,
    flags: u32,
    payload: Section<'_>,
    keys: (&CStr, &CStr),
) -> Result<(), c_int> {
    let n = name.to_bytes();
    if n.len() >= NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut signed_name = [0u8; NAME_MAX];
    signed_name[..n.len()].copy_from_slice(n);
    let ty = TYPE_JAVA.to_le_bytes();
    let sections = [
        Section(SECTION_NAME, &signed_name),
        Section(SECTION_TYPE, &ty),
        payload,
    ];
    let signed = compose_signed_data(&[], &sections)?;
    let (sig, digest) = match sign(&[], &signed, keys) {
        Ok(s) => s,
        Err(err) => {
            error(format!("cms_sign: {err}").as_bytes());
            return Err(err);
        }
    };
    let data_off = HEADER_SIZE.checked_add(sig.len()).ok_or(-E2BIG)?;
    if data_off > FILE_MAX || signed.len() > FILE_MAX - data_off {
        error(
            format!(
                "{}: the jar and its signature do not fit a upatch of {FILE_MAX} bytes",
                String::from_utf8_lossy(n)
            )
            .as_bytes(),
        );
        return Err(-E2BIG);
    }
    let hdr = Header {
        name: n,
        ty: TYPE_JAVA,
        flags,
        payload_sha256: &digest,
        loader: (0, 0),
        signature: (HEADER_SIZE as u32, sig.len() as u32),
        data: (data_off as u32, signed.len() as u32),
        log_buf_sz: 0,
        rodata_data_off: 0,
        nr_maps: 0,
        nr_progs: 0,
    };
    let out_path = super::path(out.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(out_path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            let err = io::errno_of(&e);
            error(&[b"open ", out.to_bytes(), b": ", strerr(-err)].concat());
            return Err(err);
        }
    };
    let written = [&hdr.bytes()[..], &sig, &signed]
        .iter()
        .try_for_each(|b| file.write_all(b))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(out_path);
        return Err(io::errno_of(&e));
    }
    let directive = if flags & DIRECTIVE_UNLOAD != 0 {
        " UNLOAD"
    } else {
        ""
    };
    info(
        format!(
            "wrote {} (java sig={} data={} name={}{directive})",
            String::from_utf8_lossy(out.to_bytes()),
            sig.len(),
            signed.len(),
            String::from_utf8_lossy(n),
        )
        .as_bytes(),
    );
    Ok(())
}

/// Refused where the operator sees it: a jar without Premain-Class stops
/// every JVM that receives it as `-javaagent`.
fn check_agent_jar(path: &CStr, jar: &[u8]) -> Result<(), c_int> {
    let err = match super::jar::premain_class(jar) {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };
    let p = path.to_bytes();
    if err == -ENOENT {
        error(
            &[
                p,
                b" has no Premain-Class in its manifest: a JVM does not start with it as -javaagent",
            ]
            .concat(),
        );
    } else if err == -EOPNOTSUPP {
        error(
            &[
                p,
                b": a zip64 jar or a manifest neither stored nor deflated is not supported",
            ]
            .concat(),
        );
    } else if err == -EFBIG {
        error(&[p, b": the manifest is too large"].concat());
    } else {
        error(&[p, b" is not a jar"].concat());
    }
    Err(err)
}

/// Packages a Java agent jar as upatch `name` at `out`.
pub(super) fn java_load(
    jar_path: &CStr,
    out: &CStr,
    name: &CStr,
    keys: (&CStr, &CStr),
) -> Result<(), c_int> {
    check_name(name.to_bytes())?;
    let jar = match crate::util::io::read(jar_path, FILE_MAX) {
        Ok(jar) => jar,
        Err(err) => {
            error(&[b"read ", jar_path.to_bytes(), b": ", strerr(-err)].concat());
            return Err(err);
        }
    };
    check_agent_jar(jar_path, &jar)?;
    finalize_java(out, name, 0, Section(SECTION_JAR, &jar), keys)
}

/// Signs the Java directive that unloads upatch `name`, whose payload has
/// digest `payload`, at `out`.
pub(super) fn java_unload(
    name: &CStr,
    payload: &[u8; 32],
    out: &CStr,
    keys: (&CStr, &CStr),
) -> Result<(), c_int> {
    check_name(name.to_bytes())?;
    finalize_java(
        out,
        name,
        DIRECTIVE_UNLOAD,
        Section(SECTION_UNLOAD, payload),
        keys,
    )
}

/// The policy labels a package signs: their header and the entries,
/// with the maps that hold the policy found in the object.
fn policy_labels(obj: &Object, policies: &[u8], nr: u32) -> Result<Vec<u8>, c_int> {
    let index = |name: &[u8]| obj.maps.iter().position(|m| m.name == name);
    let (task, sock) = (index(b"shirudo_task_policy"), index(b"shirudo_sock_policy"));
    let task_ok = task.is_some_and(|i| {
        let m = &obj.maps[i];
        m.map_type() == BPF_MAP_TYPE_TASK_STORAGE
            && m.key_size() == 4
            && m.value_size() == 16
            && m.map_flags() == BPF_F_NO_PREALLOC
    });
    if !task_ok {
        error(b"policy labels require a compatible shirudo_task_policy map");
        return Err(-EINVAL);
    }
    let sock_ok = sock.is_some_and(|i| {
        let m = &obj.maps[i];
        m.map_type() == BPF_MAP_TYPE_SK_STORAGE
            && m.key_size() == 4
            && m.value_size() == 8
            && m.map_flags() == (BPF_F_NO_PREALLOC | BPF_F_CLONE)
    });
    if !sock_ok {
        error(b"policy labels require a compatible shirudo_sock_policy map");
        return Err(-EINVAL);
    }
    let policy_idx = task.filter(|&i| i < MAPS_MAX as usize).ok_or(-E2BIG)?;
    let socket_idx = sock
        .filter(|&i| i < MAPS_MAX as usize && i != policy_idx)
        .ok_or(-E2BIG)?;
    let total = (nr as usize)
        .checked_mul(POLICY_LABEL_ENTRY)
        .and_then(|n| n.checked_add(POLICY_LABEL_HEADER));
    let Some(total) = total.filter(|&t| t <= u32::MAX as usize) else {
        return Err(-EOVERFLOW);
    };
    let mut blob = vec![0u8; POLICY_LABEL_HEADER];
    put32(&mut blob, 0, POLICY_LABELS_MAGIC);
    put32(&mut blob, 4, POLICY_LABELS_VERSION);
    put32(&mut blob, 8, nr);
    put32(&mut blob, 12, policy_idx as u32);
    put32(&mut blob, 16, socket_idx as u32);
    blob.extend_from_slice(policies);
    debug_assert_eq!(blob.len(), total);
    Ok(blob)
}

/// Packages the object at `bpf_o` as upatch `name` at `out`.
pub(super) fn load(
    bpf_o: &CStr,
    src_path: Option<&CStr>,
    out: &CStr,
    name: &CStr,
    policies: &[u8],
    nr: u32,
    keys: (&CStr, &CStr),
) -> Result<(), c_int> {
    check_name(name.to_bytes())?;
    let path = bpf_o.to_bytes();
    let obj = std::fs::read(super::path(path))
        .map_err(|e| io::errno_of(&e))
        .and_then(|data| Object::open(&data, object::object_name(path)));
    let obj = match obj {
        Ok(o) => o,
        Err(err) => {
            error(format!("open {}: {err}", String::from_utf8_lossy(bpf_o.to_bytes())).as_bytes());
            return Err(err);
        }
    };
    let labels = if nr != 0 {
        policy_labels(&obj, policies, nr)?
    } else {
        Vec::new()
    };
    let contents = Contents {
        name,
        flags: 0,
        unload_payload: &[0; 32],
        src_path,
        policy_labels: &labels,
    };
    finalize(obj, out, &contents, keys)
}

/// `struct unload_params` of the unload template: the name and the
/// payload it unloads.
const UNLOAD_PARAMS: usize = NAME_MAX + PAYLOAD_HASH_LEN;

/// The unload template, bpf/unload.bpf.o, which a directive is packaged
/// from.
static UNLOAD_TEMPLATE: &[u8] = include_bytes!("../../../../bpf/unload.bpf.o");

/// Signs the directive that unloads upatch `name`, whose payload has
/// the digest `payload`, at `out`.
pub(super) fn unload(
    name: &CStr,
    payload: &[u8; 32],
    out: &CStr,
    keys: (&CStr, &CStr),
) -> Result<(), c_int> {
    check_name(name.to_bytes())?;
    let data = UNLOAD_TEMPLATE;
    // Named as libbpf names it opened from unload.bpf.o: from memory,
    // libbpf would name it from its address, and its .rodata map so.
    let mut obj = match Object::open(data, b"unload") {
        Ok(o) => o,
        Err(err) => {
            error(format!("open embedded unload template: {err}").as_bytes());
            return Err(err);
        }
    };
    let Some(rodata) = obj.rodata_mut() else {
        error(b"unload template has no .rodata map");
        return Err(-EINVAL);
    };
    let n = name.to_bytes();
    if n.len() >= NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut params = [0u8; UNLOAD_PARAMS];
    params[..n.len()].copy_from_slice(n);
    params[NAME_MAX..].copy_from_slice(payload);
    if let Err(err) = rodata.set_initial_value(&params) {
        error(format!("set_initial_value(.rodata): {err}").as_bytes());
        return Err(err);
    }
    // The target reads the name and the expected payload from the signed
    // sections, not from the loader's .rodata, which it has no portable
    // way to locate in the data blob.
    let contents = Contents {
        name,
        flags: DIRECTIVE_UNLOAD,
        unload_payload: payload,
        src_path: None,
        policy_labels: &[],
    };
    finalize(obj, out, &contents, keys)
}

/// Packages the object at `bpf_o` as upatch `name` at `out`, with no
/// policy labels, signed with the key and certificate at `pkey` and
/// `cert`.
pub(super) fn load_object(
    bpf_o: &CStr,
    src_path: Option<&CStr>,
    out: &CStr,
    name: &CStr,
    pkey: &CStr,
    cert: &CStr,
) -> Result<(), c_int> {
    load(bpf_o, src_path, out, name, &[], 0, (pkey, cert))
}

/// Signs the directive that unloads upatch `name` at `out`.
pub(super) fn unload_directive(
    name: &CStr,
    payload: &[u8; 32],
    out: &CStr,
    pkey: &CStr,
    cert: &CStr,
    java: bool,
) -> Result<(), c_int> {
    if java {
        java_unload(name, payload, out, (pkey, cert))
    } else {
        unload(name, payload, out, (pkey, cert))
    }
}
