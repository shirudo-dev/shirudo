// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo status`: the verdict on this host, the conditions behind it,
//! the tamper counters and the loaded upatches; below them, unfolded when
//! their condition is not OK or on request, the keyrings, the TPM
//! register, the assets, the system and the eventlog. As JSON it is also
//! the keepalive a target sends its collector.

mod keepalive;

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::{CString, OsStr};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{EINPROGRESS, ENAMETOOLONG, ENODEV, ENOENT, ENOKEY};
use crate::ffi;
use crate::sys::identity::Identity;
use crate::sys::libc::{
    access, close, explicit_bzero, fwrite, gethostname, stderr, stdout, strerror,
};
use crate::sys::version::shirudo_version_id;
use crate::text::{cstr, name_has_suffix, strscpy, strsprintf};
use crate::util::bpf_sys::bpf_obj_get;
use crate::util::bpm_tree_state;
use crate::util::chain::{self, ChainStatus};
use crate::util::conditions::{self, CONDITIONS_MAX, Condition, ConditionsInput};
use crate::util::config::{self, Config};
use crate::util::crypto_openssl::{
    Cert, cert_key_algorithm, cert_not_before, cert_read_der, cert_subject,
};
use crate::util::eventlog;
use crate::util::format::{fputs_sanitized, human_size};
use crate::util::help::{Help, HelpSection};
use crate::util::identity;
use crate::util::image_bootstrap::{self, ImageBootstrap};
use crate::util::image_runtime;
use crate::util::initrd;
use crate::util::integrity::{self, IntegrityCounts};
use crate::util::io::{self, bpffs_mounted_at};
use crate::util::java_agent;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
use crate::util::kernel_btf;
use crate::util::keyring;
use crate::util::keys::{self, TrustedSet};
use crate::util::map_read;
use crate::util::measured::MeasuredSet;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::otel::OtelOpts;
use crate::util::sysinfo::{self, Sysinfo};
use crate::util::tamper::{self, Counters, TamperCounts};
use crate::util::tpm;
use crate::util::upatch::name_from_pin;
use crate::util::upatch_resolve;
use crate::util::upatch_table::{self, UpatchTableRow};
use crate::util::upatch_verify::{Checks, checks_run, unpinned};

const VAR_LIB: &[u8] = b"/var/lib/shirudo";
const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const SIGNING_KEY_PATH: &CStr = c"/var/lib/shirudo/keys/signing_key.pem";
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const BPFFS_DIR: &CStr = c"/run/shirudo/bpffs";
const BPFFS_UPATCHES_DIR: &str = "/run/shirudo/bpffs/upatches";
const LSM_LINK_PIN: &CStr = c"/run/shirudo/bpffs/lsm_link";
const RUNTIME_CONF_PATH: &CStr = c"/run/shirudo/runtime/etc/shirudo/shirudo.conf";
/// The register's NV index, as `0x%08X` prints it.
const NV_INDEX: &CStr = c"0x01818E00";
const CHAIN_PCR: u32 = 9;
const CHAIN_PHASE_PCR: u32 = 11;
const IDENTITY_KEYS_MAX: usize = 16;
const UNMEASURED_NAMES: usize = 256;
const SUBJECT_MAX: usize = 256;

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn eprint(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// `s` padded with spaces to `width` bytes, as `%-<width>s` prints it.
fn pad(s: &[u8], width: usize) -> Vec<u8> {
    let mut out = s.to_vec();

    out.resize(width.max(s.len()), b' ');
    out
}

/// At most `n` bytes of `s`, as `%.<n>s` prints it.
fn trunc(s: &[u8], n: usize) -> &[u8] {
    &s[..s.len().min(n)]
}

/// `<indent><label, to 22 columns> <value>`, a line of the report.
fn row(indent: &[u8], label: &[u8], value: &[u8]) {
    print(&[indent, &pad(label, 22), b" ", value, b"\n"].concat());
}

fn exists(path: &CStr) -> bool {
    // SAFETY: a C string.
    unsafe { access(path.as_ptr(), 0) == 0 }
}

/// The names in `dir` but `.` and `..`, in the C locale's alphasort()
/// order; None when it cannot be listed.
fn list_dir(dir: &str) -> Option<Vec<Vec<u8>>> {
    let mut names = std::fs::read_dir(dir)
        .ok()?
        .map(|e| e.map(|e| e.file_name().as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    names.sort();
    Some(names)
}

fn is_upatch(name: &[u8]) -> bool {
    name_has_suffix(cstr(name), b".upatch")
}

fn count_dir(dir: &str, upatch_only: bool) -> Option<usize> {
    let names = list_dir(dir)?;

    Some(
        names
            .iter()
            .filter(|n| !upatch_only || is_upatch(n))
            .count(),
    )
}

fn eventlog() -> &'static [u8] {
    eventlog::path().to_bytes()
}

/// The eventlog's complete lines and size from the same open file.
fn count_eventlog() -> Option<(i64, i64)> {
    let path = OsStr::from_bytes(eventlog());
    let mut f = std::fs::File::open(path).ok()?;
    let bytes = i64::try_from(f.metadata().ok()?.len()).ok()?;
    let mut buf = [0u8; 65536];
    let mut lines = 0i64;

    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                lines += i64::try_from(buf[..n].iter().filter(|&&c| c == b'\n').count()).ok()?
            }
            Err(_) => return None,
        }
    }
    Some((lines, bytes))
}

/// Read all bytes. A NUL makes its line unparseable, but later lines remain.
fn read_eventlog() -> Option<Vec<u8>> {
    io::read(eventlog::path(), MAX_BYTES).ok()
}

/// Complete lines only. An unfinished final append is not a record.
fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|&c| c == b'\n')
        .filter_map(|line| line.strip_suffix(b"\n"))
}

/// Enough of an eventlog record for the table and events[]; the log
/// itself stays the authoritative copy.
struct Event {
    ts: [u8; 40],
    ty: [u8; 24],
    digest: [u8; 65],
    set_digest: [u8; 65],
    up_name: [u8; 257],
    up_payload: [u8; 65],
}

fn parse_event(line: &[u8]) -> Option<Event> {
    let mut ev = Event {
        ts: [0; 40],
        ty: [0; 24],
        digest: [0; 65],
        set_digest: [0; 65],
        up_name: [0; 257],
        up_payload: [0; 65],
    };
    let up = [
        JsonField::string(c"name", |ev: &mut Event| &mut ev.up_name),
        JsonField::string(c"payload_sha256", |ev| &mut ev.up_payload),
    ];
    let f = [
        JsonField::string(c"ts", |ev: &mut Event| &mut ev.ts),
        JsonField::string(c"type", |ev| &mut ev.ty),
        JsonField::string(c"digest", |ev| &mut ev.digest),
        JsonField::string(c"set_digest", |ev| &mut ev.set_digest),
        JsonField::object(c"upatch", &up),
    ];

    parse_schema(line, &f, &mut ev).is_ok().then_some(ev)
}

impl Event {
    /// The table's detail column; empty when it would not fit 256 bytes.
    fn detail(&self) -> Vec<u8> {
        let name = cstr(&self.up_name);
        let set_digest = cstr(&self.set_digest);

        if !name.is_empty() {
            let d = [name, b" payload=", trunc(cstr(&self.up_payload), 12), b".."].concat();
            return if d.len() < 256 { d } else { Vec::new() };
        }
        if !set_digest.is_empty() {
            return [b"set_digest=", trunc(set_digest, 12), b".."].concat();
        }
        Vec::new()
    }
}

fn emit_events(e: &mut JsonEmit) {
    e.arr_open(b"events");
    for line in read_eventlog().iter().flat_map(|t| lines(t)) {
        e.obj_open();
        let Some(ev) = parse_event(line) else {
            e.kv_string(b"type", b"unparseable");
            e.obj_close();
            continue;
        };
        e.kv_string(b"ts", cstr(&ev.ts));
        e.kv_string(b"type", cstr(&ev.ty));
        e.kv_string(b"digest", cstr(&ev.digest));
        if ev.set_digest[0] != 0 {
            e.kv_string(b"set_digest", cstr(&ev.set_digest));
        }
        if ev.up_name[0] != 0 {
            e.obj_open_key(b"upatch");
            e.kv_string(b"name", cstr(&ev.up_name));
            e.kv_string(b"payload_sha256", cstr(&ev.up_payload));
            e.obj_close();
        }
        e.obj_close();
    }
    e.arr_close();
}

fn print_events() {
    let Some(text) = read_eventlog() else {
        return;
    };

    print(b"\nEventlog:\n");
    print(
        &[
            &b"  "[..],
            &pad(b"TIME", 20),
            b" ",
            &pad(b"TYPE", 13),
            b" ",
            &pad(b"DIGEST", 13),
            b" DETAIL\n",
        ]
        .concat(),
    );
    for line in lines(&text) {
        let Some(ev) = parse_event(line) else {
            print(
                &[
                    &b"  "[..],
                    &pad(b"?", 20),
                    b" ",
                    &pad(b"unparseable", 13),
                    b" ",
                    &pad(b"", 13),
                    b"\n",
                ]
                .concat(),
            );
            continue;
        };
        let digest = if ev.digest[0] != 0 {
            cstr(&ev.digest)
        } else {
            b"-"
        };
        print(
            &[
                &b"  "[..],
                &pad(cstr(&ev.ts), 20),
                b" ",
                &pad(cstr(&ev.ty), 13),
                b" ",
                &pad(trunc(digest, 12), 13),
                b" ",
                &ev.detail(),
                b"\n",
            ]
            .concat(),
        );
    }
}

fn size(bytes: u64) -> Vec<u8> {
    let mut out = [0u8; 16];

    human_size(bytes, &mut out);
    cstr(&out).to_vec()
}

fn system_row(indent: &[u8], label: &[u8], value: &[u8]) {
    print(&[indent, &pad(label, 22), b" "].concat());
    // SAFETY: value is a byte slice and stdout is an open stream.
    unsafe { fputs_sanitized(value, stdout) };
    print(b"\n");
}

fn print_system(si: &Sysinfo) {
    let field = |label: &[u8], value: &[u8]| row(b"  ", label, value);

    print(b"\nSystem:\n");
    system_row(b"  ", b"OS:", &si.os_pretty);
    system_row(b"  ", b"Kernel:", &si.kernel_release);
    if !si.kernel_version.is_empty() {
        system_row(b"  ", b"Kernel version:", &si.kernel_version);
    }
    if !si.kernel_build_id.is_empty() {
        field(b"Kernel build ID:", &si.kernel_build_id);
    }
    system_row(b"  ", b"Architecture:", &si.machine);
    if si.nproc > 0 {
        field(b"CPUs:", si.nproc.to_string().as_bytes());
    }
    if si.mem_total_kb > 0 {
        let total = size((si.mem_total_kb as u64).wrapping_mul(1024));
        if si.mem_avail_kb >= 0 && si.mem_avail_kb <= si.mem_total_kb {
            let used = size(((si.mem_total_kb - si.mem_avail_kb) as u64).wrapping_mul(1024));
            field(b"Memory:", &[&used[..], b"/", &total].concat());
        } else {
            field(b"Memory:", &total);
        }
    }
    if si.disk_total_kb > 0 {
        let total = size((si.disk_total_kb as u64).wrapping_mul(1024));
        let used = size((si.disk_used_kb as u64).wrapping_mul(1024));
        field(b"Disk:", &[&used[..], b"/", &total].concat());
    }
    if si.uptime_sec >= 0 {
        let s = si.uptime_sec;
        let up = format!(
            "{}d {}h {}m",
            s / 86400,
            (s % 86400) / 3600,
            (s % 3600) / 60
        );
        field(b"Uptime:", up.as_bytes());
    }
    if !si.machine_id.is_empty() {
        system_row(b"  ", b"Machine ID:", &si.machine_id);
    }
    if !si.boot_id.is_empty() {
        system_row(b"  ", b"Boot ID:", &si.boot_id);
    }
}

const STATUS_JSON: c_int = 0;
const STATUS_OTEL: c_int = 1;
const STATUS_KEEPALIVE: c_int = 2;
const STATUS_CHECK: c_int = 3;
const STATUS_SHOW_FULL: c_int = 4;
const STATUS_INCLUDE_SYSTEM: c_int = 5;
const STATUS_INCLUDE_EVENTLOG: c_int = 6;

static OPTS: [OptSpec; 7] = [
    OptSpec::new(
        c"--json",
        0,
        0,
        None,
        c"print the report as one JSON document",
    ),
    OptSpec::new(
        c"--otel",
        0,
        0,
        None,
        c"quote the keepalive body with the TPM and send it as an OTLP log",
    ),
    OptSpec::new(
        c"--keepalive",
        0,
        0,
        None,
        c"print the keepalive body, unquoted and unsent",
    ),
    OptSpec::new(
        c"--check",
        0,
        0,
        None,
        c"exit 1 when the verdict is tampered",
    ),
    OptSpec::new(
        c"--show-full",
        0,
        0,
        None,
        c"print every section, folded or not, and the system and eventlog sections",
    ),
    OptSpec::new(
        c"--include-system",
        0,
        0,
        None,
        c"add the system section: OS, kernel, machine, memory, disk, uptime",
    ),
    OptSpec::new(
        c"--include-eventlog",
        0,
        0,
        None,
        c"add the eventlog records, all boots",
    ),
];

static SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OPTS)];

static HELP: Help = Help::new(
    c"shirudo status [--json | --otel | --keepalive] [--check]\n                       [--show-full] [--include-system] [--include-eventlog]",
    Some(
        c"Report the state of this host: the verdict, the conditions behind it, the\n\
          tamper counters and the loaded upatches. A section whose condition is not OK\n\
          unfolds below them. Safe to run before init, on a target or an operator host.",
    ),
    &SECTIONS,
    None,
);

fn row_field(dst: &mut [c_char], src: &[u8]) {
    let n = src.len().min(dst.len().saturating_sub(1));

    for (d, &s) in dst.iter_mut().zip(&src[..n]) {
        *d = s as c_char;
    }
    if let Some(end) = dst.get_mut(n) {
        *end = 0;
    }
}

/// A Java agent has no pin: its jar's change time is when it was loaded.
struct JavaAgent {
    name: Vec<u8>,
    payload: [u8; 32],
    loaded_at: Option<i64>,
}

impl JavaAgent {
    fn row(&self) -> UpatchTableRow {
        let mut r = UpatchTableRow::empty();

        row_field(&mut r.name, &self.name);
        row_field(&mut r.location, b"java");
        row_field(&mut r.payload_sha256, &hex(&self.payload));
        if let Some(t) = self.loaded_at {
            let mut stamp = [0u8; 32];

            if crate::util::timefmt::iso8601(t, &mut stamp) == 0 {
                row_field(&mut r.loaded_at, cstr(&stamp));
            }
        }
        // SAFETY: the row's fixed array ends in NUL.
        r.age_sec = unsafe { upatch_table::age_sec(r.loaded_at.as_ptr()) };
        r
    }
}

fn java_agents() -> Vec<JavaAgent> {
    let mut agents = Vec::new();
    let mut add = |name: &[u8], payload: &[u8; 32]| {
        let loaded_at = java_agent::agent_path(name)
            .ok()
            .and_then(|path| std::fs::metadata(OsStr::from_bytes(path.to_bytes())).ok())
            .map(|st| st.ctime());

        agents.push(JavaAgent {
            name: name.to_vec(),
            payload: *payload,
            loaded_at,
        });
        0
    };
    if java_agent::each_loaded(&mut add) != 0 {
        crate::log::warn(b"status: the Java agents could not all be read");
    }
    agents
}

/// The rows of the pinned upatches, then those of the Java agents.
fn upatch_rows(pins: &[Vec<u8>], java: &[JavaAgent]) -> Vec<UpatchTableRow> {
    let mut rows = Vec::with_capacity(pins.len() + java.len());

    if !pins.is_empty() {
        // vmlinux BTF loaded once; every BPF upatch attaches to vmlinux.
        let vbtf = kernel_btf::vmlinux();
        rows.extend(pins.iter().map(|pin| {
            let mut r = UpatchTableRow::empty();
            let name = message(&[&name_from_pin(pin).unwrap_or_else(|| pin.clone())]);

            row_field(&mut r.name, name.to_bytes());
            let upatch = name.to_bytes();
            let location =
                upatch_resolve::resolve_location(vbtf, upatch).unwrap_or_else(|_| b"?".to_vec());
            row_field(&mut r.location, &location);
            row_field(&mut r.loaded_at, &upatch_resolve::loaded_at(upatch));
            row_field(
                &mut r.payload_sha256,
                &upatch_resolve::payload_sha256(upatch),
            );
            // SAFETY: row_field terminated the timestamp in the fixed row field.
            r.age_sec = unsafe { upatch_table::age_sec(r.loaded_at.as_ptr()) };
            r.n_maps =
                u32::try_from(map_read::list(Some(name.to_bytes())).len()).unwrap_or(u32::MAX);
            match upatch_resolve::missed_runs(name.to_bytes()) {
                Ok((counted, missed)) => {
                    r.missed_counted = counted;
                    r.missed_runs = missed;
                }
                Err(e) => r.missed_ret = e,
            }
            r
        }));
    }
    rows.extend(java.iter().map(JavaAgent::row));
    rows
}

/// A link of a keyring: what it is and whether init froze it.
struct Link {
    serial: i32,
    err: c_int,
    ty: Vec<u8>,
    description: Vec<u8>,
    frozen: bool,
    /// Holds one of the certificates.
    cert: bool,
}

impl Link {
    fn asymmetric(&self) -> bool {
        self.err == 0 && self.ty == b"asymmetric"
    }
}

struct CertInfo {
    subject: Vec<u8>,
    algorithm: Vec<u8>,
    not_before: Vec<u8>,
}

/// A certificate a keyring should hold, and the link that holds it.
struct CertView {
    sha256: [u8; 32],
    fingerprint: [u8; 32],
    primary: bool,
    info: Result<CertInfo, c_int>,
    link: Option<usize>,
}

/// A keyring init froze: its live and frozen serials, every link it
/// holds and which of those init froze, and the certificates it should
/// hold.
struct KeyringView {
    /// Live, or -errno.
    serial: i32,
    /// Frozen, 0 for none, or -errno.
    pinned: i32,
    links: Result<Vec<Link>, c_int>,
    certs: Vec<CertView>,
    certs_rc: c_int,
    key_missing: bool,
}

impl KeyringView {
    fn new(serial: i32, pinned: i32, frozen: &[i32]) -> Self {
        let links = if serial < 0 {
            Err(serial)
        } else {
            keyring::links(serial).map(|links| {
                links
                    .into_iter()
                    .map(|l| Link {
                        frozen: frozen.contains(&l.serial),
                        serial: l.serial,
                        err: l.err,
                        ty: l.ty,
                        description: l.description,
                        cert: false,
                    })
                    .collect()
            })
        };
        KeyringView {
            serial,
            pinned,
            links,
            certs: Vec::new(),
            certs_rc: 0,
            key_missing: false,
        }
    }

    fn links(&self) -> &[Link] {
        self.links.as_deref().unwrap_or(&[])
    }

    fn n_unfrozen(&self) -> usize {
        self.links().iter().filter(|l| !l.frozen).count()
    }

    fn n_asymmetric(&self) -> usize {
        self.links().iter().filter(|l| l.asymmetric()).count()
    }

    /// Adds a certificate, with its subject, key and dates, and the link
    /// whose key it is.
    fn add(&mut self, mut c: CertView, der: &[u8]) {
        c.info = cert_info(der);
        let described = keyring::cert_description(der);
        if let (Ok(desc), Ok(links)) = (&described, &mut self.links) {
            let desc = &desc[..];
            if let Some(i) = links
                .iter()
                .position(|l| l.asymmetric() && !l.cert && l.description == desc)
            {
                links[i].cert = true;
                c.link = Some(i);
            }
        }
        self.certs.push(c);
    }

    fn bpf(
        serial: i32,
        pinned: i32,
        ident: &Identity,
        certs: &TrustedSet,
        certs_rc: c_int,
    ) -> Self {
        let n_frozen = if pinned >= 1 {
            (ident.n_keys as usize).min(IDENTITY_KEYS_MAX)
        } else {
            0
        };
        let mut k = KeyringView::new(serial, pinned, &ident.key_serials[..n_frozen]);

        k.certs_rc = certs_rc;
        if certs_rc != 0 {
            return k;
        }
        for t in keys::members(certs) {
            let c = CertView {
                sha256: *t.sha256(),
                fingerprint: *t.fingerprint(),
                primary: t.primary(),
                info: Err(0),
                link: None,
            };
            match keys::cert_der(t) {
                Ok(der) => k.add(c, der),
                Err(err) => k.certs.push(CertView {
                    info: Err(err),
                    ..c
                }),
            }
        }
        k
    }

    /// The config certificates come from the runtime image's bootstrap.
    fn dm_verity(serial: i32, pinned: i32, ident: &Identity) -> Self {
        let n_frozen = if pinned >= 1 {
            (ident.n_dm_verity_keys as usize).min(IDENTITY_KEYS_MAX)
        } else {
            0
        };
        let frozen = &ident.dm_verity_keys[..n_frozen];
        let mut k = KeyringView::new(serial, pinned, frozen);
        let mut boot = Box::new(ImageBootstrap::empty());

        if let Ok(links) = &k.links {
            k.key_missing = frozen
                .iter()
                .any(|key| !links.iter().any(|l| l.serial == *key));
        }
        let mut rc = image_bootstrap::read(RUNTIME_CONF_PATH, &mut boot, false)
            .err()
            .unwrap_or(0);
        if rc == 0 && boot.n_certificates == 0 {
            rc = -ENOENT;
        }
        for path in &boot.certificates[..if rc == 0 { boot.n_certificates } else { 0 }] {
            let read = CStr::from_bytes_until_nul(path)
                .map_err(|_| -ENAMETOOLONG)
                .and_then(keys::read_der)
                .and_then(|der| Ok((keys::digest_der(&der)?, der)));
            let (digests, der) = match read {
                Ok(read) => read,
                Err(err) => {
                    rc = err;
                    break;
                }
            };
            let c = CertView {
                sha256: digests.sha256,
                fingerprint: digests.fingerprint,
                primary: true,
                info: Err(0),
                link: None,
            };

            k.add(c, &der);
        }
        k.certs_rc = rc;
        k
    }

    fn emit_json(&self, e: &mut JsonEmit, key: &[u8], role: &[u8]) {
        e.obj_open_key(key);
        e.kv_bool(b"present", self.serial >= 0);
        match self.serial {
            s if s >= 0 => e.kv_int(b"serial", s.into()),
            _ => e.kv_null(b"serial"),
        }
        match self.pinned {
            p if p >= 1 => e.kv_int(b"serial_pinned", p.into()),
            _ => e.kv_null(b"serial_pinned"),
        }
        if self.serial >= 0 && self.pinned >= 1 {
            e.kv_bool(b"serial_matches", self.serial == self.pinned);
        } else {
            e.kv_null(b"serial_matches");
        }
        e.arr_open(b"certs");
        for c in &self.certs {
            e.obj_open();
            e.kv_string(b"sha256", &hex(&c.sha256));
            e.kv_string(b"fingerprint", &hex(&c.fingerprint));
            e.kv_bool(role, c.primary);
            match &c.info {
                Ok(i) => {
                    e.kv_string(b"subject", &i.subject);
                    e.kv_string(b"algorithm", &i.algorithm);
                    e.kv_string(b"not_before", &i.not_before);
                }
                Err(_) => {
                    e.kv_null(b"subject");
                    e.kv_null(b"algorithm");
                    e.kv_null(b"not_before");
                }
            }
            match c.link.map(|i| &self.links()[i]) {
                Some(l) => {
                    e.kv_int(b"key_serial", l.serial.into());
                    e.kv_string(b"key_description", &l.description);
                    e.kv_bool(b"frozen", l.frozen);
                }
                None => {
                    e.kv_null(b"key_serial");
                    e.kv_null(b"key_description");
                    e.kv_null(b"frozen");
                }
            }
            e.obj_close();
        }
        e.arr_close();
        e.arr_open(b"other_links");
        for l in self.links().iter().filter(|l| !l.cert) {
            e.obj_open();
            e.kv_int(b"serial", l.serial.into());
            if l.err != 0 {
                e.kv_null(b"type");
                e.kv_null(b"description");
            } else {
                e.kv_string(b"type", &l.ty);
                e.kv_string(b"description", &l.description);
            }
            e.kv_bool(b"frozen", l.frozen);
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
    }

    fn print_link(l: &Link, indent: &[u8]) {
        let serial = l.serial.to_string();

        if l.err != 0 {
            print(
                &[
                    indent,
                    b"link ",
                    serial.as_bytes(),
                    b"  (cannot describe: ",
                    strerr(-l.err),
                    b")",
                ]
                .concat(),
            );
        } else {
            let ty: &[u8] = if l.ty == b"asymmetric" { b"key" } else { &l.ty };
            print(&[indent, ty, b" ", serial.as_bytes(), b"  "].concat());
            // SAFETY: the description, to the C library's stdout.
            unsafe { fputs_sanitized(&l.description, stdout) };
        }
        print(if l.frozen {
            b"  (frozen)\n"
        } else {
            b"  (not frozen)\n"
        });
    }

    fn print_certs(&self, role: &[u8], unlinked: &[u8]) {
        for c in &self.certs {
            let role: Vec<u8> = if c.primary {
                [b"  (", role, b")"].concat()
            } else {
                Vec::new()
            };
            print(&[b"    ", &hex(&c.fingerprint)[..], &role, b"\n"].concat());
            match &c.info {
                Err(rc) => print(&[b"      (details unreadable: ", strerr(-rc), b")\n"].concat()),
                Ok(i) => print(
                    &[
                        b"      ",
                        &i.subject[..],
                        b", ",
                        &i.algorithm,
                        b", issued ",
                        &i.not_before,
                        b"\n",
                    ]
                    .concat(),
                ),
            }
            match c.link {
                Some(i) => Self::print_link(&self.links()[i], b"      "),
                None if self.links.is_ok() => {
                    print(&[b"      not in the keyring  (", unlinked, b")\n"].concat())
                }
                None => {}
            }
        }
    }

    fn print_other_links(&self) {
        let mut others = self.links().iter().filter(|l| !l.cert).peekable();

        if others.peek().is_some() {
            print(b"  Other links:\n");
        }
        for l in others {
            Self::print_link(l, b"    ");
        }
    }

    fn print_serials(&self) {
        let field = |label: &[u8], value: &[u8]| row(b"  ", label, value);
        let (serial, pinned) = (self.serial, self.pinned);

        if serial >= 0 {
            field(b"Serial:", serial.to_string().as_bytes());
        } else if pinned == -ENOENT {
            field(b"Serial:", b"absent before init");
        } else if serial == -ENOKEY {
            field(b"Serial:", b"absent");
        } else {
            field(b"Serial:", &[b"lookup error: ", strerr(-serial)].concat());
        }
        if pinned == -ENOENT || pinned == 0 {
            field(b"Frozen serial:", b"(none this boot)");
        } else if pinned < 0 {
            field(
                b"Frozen serial:",
                &[b"unreadable: ", strerr(-pinned)].concat(),
            );
        } else {
            let state: &[u8] = if serial < 0 {
                b"  (gone)"
            } else if serial == pinned {
                b"  (matches)"
            } else {
                b"  (swapped)"
            };
            field(
                b"Frozen serial:",
                &[pinned.to_string().as_bytes(), state].concat(),
            );
        }
        if let (Err(rc), true) = (&self.links, serial >= 0) {
            field(b"Links:", &[b"unreadable: ", strerr(-rc)].concat());
        }
    }
}

fn cert_info(der: &[u8]) -> Result<CertInfo, c_int> {
    let mut cert = Cert::new();
    let mut subject = [0u8; SUBJECT_MAX];
    let mut algorithm = [0u8; 32];
    let mut not_before = [0u8; 11];

    // SAFETY: the DER and the cert to fill.
    let rc = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: the certificate read above and room for the subject.
    let mut rc = unsafe { cert_subject(&cert, subject.as_mut_ptr().cast(), subject.len()) };
    if rc == 0 {
        // SAFETY: the certificate and room for its algorithm name.
        rc = unsafe { cert_key_algorithm(&cert, algorithm.as_mut_ptr().cast(), algorithm.len()) };
    }
    if rc == 0 {
        // SAFETY: the certificate and room for its date.
        rc = unsafe { cert_not_before(&cert, not_before.as_mut_ptr().cast()) };
    }
    if rc != 0 {
        return Err(rc);
    }
    Ok(CertInfo {
        subject: cstr(&subject).to_vec(),
        algorithm: cstr(&algorithm).to_vec(),
        not_before: cstr(&not_before).to_vec(),
    })
}

/// Appends `name` to the comma-separated `names`, ending them with
/// `, ...` once the next does not fit.
fn note(names: &mut [u8; UNMEASURED_NAMES], name: &[u8]) {
    let used = cstr(names).len();
    if names[..used].ends_with(b"...") {
        return;
    }

    let sep: &[u8] = if used == 0 { b"" } else { b", " };
    if strsprintf(&mut names[used..], &[sep, name]).is_ok() || used == 0 {
        return;
    }
    if strscpy(&mut names[used..], b", ...").is_err() {
        names[UNMEASURED_NAMES - 4..].copy_from_slice(b"...\0");
    }
}

/// What the checks of the pins against this boot's records found: each
/// count or -errno, and the names behind it.
struct Checked {
    unmeasured: c_int,
    unmeasured_names: [u8; UNMEASURED_NAMES],
    xdp_tampered: c_int,
    xdp_tampered_names: [u8; UNMEASURED_NAMES],
    links_lost: c_int,
    links_lost_names: [u8; UNMEASURED_NAMES],
    xdp_uncovered: c_int,
    xdp_uncovered_names: [u8; UNMEASURED_NAMES],
    checks_rc: c_int,
    coverage_rc: c_int,
}

/// `name on dev (why)` fits the C's entry, else `name` alone.
const UNCOVERED_MAX: usize = 64 + 16 + 64;

/// The pins and archives this boot's records do not hold, the loaded XDP
/// upatches whose archive changed, the upatches missing a link or their
/// archive, and the devices an XDP upatch selects that do not run it,
/// all under the register lock.
fn check_pins() -> Checked {
    let mut c = Checked {
        unmeasured: 0,
        unmeasured_names: [0; UNMEASURED_NAMES],
        xdp_tampered: 0,
        xdp_tampered_names: [0; UNMEASURED_NAMES],
        links_lost: 0,
        links_lost_names: [0; UNMEASURED_NAMES],
        xdp_uncovered: 0,
        xdp_uncovered_names: [0; UNMEASURED_NAMES],
        checks_rc: 0,
        coverage_rc: 0,
    };
    let lock = eventlog::lock();
    let set = match &lock {
        Err(err) => Err(*err),
        Ok(_) => MeasuredSet::boot(),
    };
    c.unmeasured = match &set {
        Err(err) => *err,
        Ok(_) => 0,
    };
    if let Ok(set) = &set {
        c.unmeasured = set.unmeasured_pins(|name| {
            note(&mut c.unmeasured_names, name);
            0
        });
        if c.unmeasured >= 0 {
            let archived = set.unmeasured_archives(|name, _| {
                note(&mut c.unmeasured_names, name);
                0
            });
            c.unmeasured = if archived < 0 {
                archived
            } else {
                c.unmeasured + archived
            };
        }
        if c.unmeasured >= 0 {
            let mut on_unbacked = |name: &[u8]| {
                note(&mut c.unmeasured_names, name);
                0
            };
            let jars = java_agent::unbacked(Some(&mut on_unbacked));
            c.unmeasured = if jars < 0 { jars } else { c.unmeasured + jars };
        }
        let (tampered, lost, uncovered) = (
            &mut c.xdp_tampered_names,
            &mut c.links_lost_names,
            &mut c.xdp_uncovered_names,
        );
        let mut on_changed = |name: &[u8]| {
            note(tampered, name);
            0
        };
        let mut on_lost = |name: &[u8]| {
            note(lost, name);
            0
        };
        let mut on_uncovered = |name: &[u8], dev: &[u8], why: &[u8]| {
            let entry = [name, b" on ", dev, b" (", why, b")"].concat();
            note(
                uncovered,
                if entry.len() < UNCOVERED_MAX {
                    &entry
                } else {
                    name
                },
            );
            0
        };
        let mut checks = Checks {
            changed: Some(&mut on_changed),
            lost: Some(&mut on_lost),
            uncovered: Some(&mut on_uncovered),
            ..Checks::default()
        };
        checks_run(set, &mut checks);
        let (nr_changed, nr_lost, nr_uncovered) =
            (checks.nr_changed, checks.nr_lost, checks.nr_uncovered);
        let (check_err, coverage_err) = (checks.check_err, checks.coverage_err);
        let unpinned = unpinned(set, |name| {
            note(&mut c.links_lost_names, name);
            0
        });
        c.xdp_tampered = nr_changed;
        c.links_lost = if unpinned < 0 {
            unpinned
        } else {
            unpinned + nr_lost
        };
        c.xdp_uncovered = nr_uncovered;
        c.checks_rc = check_err;
        c.coverage_rc = coverage_err;
    }
    drop(set);
    drop(lock);
    c
}

struct Assets {
    cert: bool,
    signing_key: bool,
    eventlog_bytes: Option<i64>,
    upatches: Option<usize>,
    bpffs_mounted: bool,
}

impl Assets {
    fn gather() -> Self {
        Assets {
            cert: exists(initrd::cert_path()),
            signing_key: exists(SIGNING_KEY_PATH),
            eventlog_bytes: std::fs::metadata(OsStr::from_bytes(eventlog()))
                .ok()
                .map(|m| m.len() as i64),
            upatches: count_dir(UPATCHES_DIR, true),
            // SAFETY: a C string.
            bpffs_mounted: unsafe { bpffs_mounted_at(BPFFS_DIR.as_ptr()) } > 0,
        }
    }
}

/// The OTLP export the configuration names, scrubbed when it goes.
struct Otel {
    cfg: Box<Config>,
}

impl Drop for Otel {
    fn drop(&mut self) {
        // SAFETY: the configuration, all of it.
        unsafe { explicit_bzero((&raw mut *self.cfg).cast(), size_of::<Config>()) };
    }
}

impl Otel {
    fn load() -> Result<Self, c_int> {
        let cfg = Box::new(Config::zeroed());
        let mut o = Otel { cfg };

        let err = config::load(&mut o.cfg);
        if err != 0 {
            let msg = message(&[b"status: load OTEL configuration: ", strerr(-err)]);
            crate::log::err(msg.to_bytes());
            return Err(1);
        }
        if !o.cfg.map_export_valid {
            crate::log::err(b"status: invalid OTEL configuration");
            return Err(2);
        }
        Ok(o)
    }

    fn opts(&self) -> OtelOpts {
        let c = &self.cfg;
        let set = |s: &[u8]| {
            if s[0] != 0 {
                s.as_ptr().cast()
            } else {
                ptr::null()
            }
        };

        OtelOpts {
            endpoint: set(&c.map_export_otel_endpoint),
            tenant_id: set(&c.map_export_tenant_id),
            s3_uri: ptr::null(),
            allow_insecure: c.map_export_otel_insecure,
            retries: c.map_export_otel_retries,
            log_record_max_bytes: 0,
            otlp_max_bytes: c.map_export_otlp_max_bytes,
        }
    }

    /// Unlike the general OTLP exporter, the keepalive must not silently
    /// turn an absent configuration into a request to localhost: it is
    /// sent only to an endpoint configured explicitly.
    fn endpoint_configured(&self) -> bool {
        let set = |var| std::env::var_os(var).is_some_and(|v| !v.is_empty());

        self.cfg.map_export_otel_endpoint[0] != 0
            || set("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
            || set("OTEL_EXPORTER_OTLP_ENDPOINT")
    }
}

/// What this host looks like.
struct Report {
    hostname: Vec<u8>,
    lsm_attached: bool,
    keyring_serial: i32,
    keyring_pinned: i32,
    keyring_mode: &'static CStr,
    certs: TrustedSet,
    certs_rc: c_int,
    bpf: KeyringView,
    dmv: KeyringView,
    is_operator: bool,
    cert_present: bool,
    is_target: bool,
    pins: Vec<Vec<u8>>,
    java: Vec<JavaAgent>,
    checked: Box<Checked>,
    assets: Assets,
    tamper: Result<TamperCounts, c_int>,
    integrity: Result<IntegrityCounts, c_int>,
    config_state: c_int,
    config_root: CString,
    tcti: Vec<u8>,
    cst: ChainStatus,
    chain_rc: c_int,
    eventlog: Option<(i64, i64)>,
    /// Whether the register equals this boot's records replayed.
    matches: Option<bool>,
    sysinfo: Option<Sysinfo>,
}

impl Report {
    fn gather(include_system: bool) -> Self {
        let sysinfo = include_system.then(sysinfo::gather);
        let mut host = [0u8; 256];
        // SAFETY: room for the name.
        if unsafe { gethostname(host.as_mut_ptr().cast(), host.len()) } != 0 {
            host[..2].copy_from_slice(b"?\0");
        }
        host[255] = 0;
        // SAFETY: a C string.
        let fd = unsafe { bpf_obj_get(LSM_LINK_PIN.as_ptr()) };
        if fd >= 0 {
            // SAFETY: the descriptor opened above.
            unsafe { close(fd) };
        }

        // The anchor init froze is the kernel's record; the live keyring
        // of that kind is what a load would name, and the two must agree.
        let (ident, mut pinned) = match identity::read() {
            Ok(id) => (id, 0),
            Err(err) => (Identity::zeroed(), err),
        };
        if pinned == 0 {
            pinned = ident.keyring_serial;
        }
        let serial = if pinned >= 1 {
            keyring::bpf_serial()
        } else {
            -ENOKEY
        };
        let mode = if serial >= 0 { c"bpf" } else { c"none" };
        // The certificates the keyring would have been given, and how
        // many keys it holds now: the two part when a certificate was
        // added or revoked since the boot.
        let (certs, certs_rc) = match keys::load(KEYS_DIR, None, serial >= 0) {
            Ok(set) => (set, 0),
            Err(err) => (TrustedSet::default(), err),
        };
        let bpf = KeyringView::bpf(serial, pinned, &ident, &certs, certs_rc);
        let dmv_pinned = if pinned < 0 {
            pinned
        } else {
            ident.dm_verity_ring
        };
        let dmv_serial = if dmv_pinned >= 1 {
            keyring::dm_verity_serial()
        } else {
            -ENOKEY
        };
        let dmv = KeyringView::dm_verity(dmv_serial, dmv_pinned, &ident);
        let is_operator = exists(SIGNING_KEY_PATH);
        let cert_present = exists(initrd::cert_path());
        let lsm_attached = fd >= 0;

        let pins = list_dir(BPFFS_UPATCHES_DIR).unwrap_or_default();
        let java = java_agents();
        let checked = Box::new(check_pins());
        let assets = Assets::gather();
        let tamper = tamper::read();
        let integrity = integrity::read();
        let mut root = [0u8; 32];
        let config_state = image_runtime::config_state(&mut root);
        let config_root = message(&[&if config_state != -ENODEV {
            hex(&root)
        } else {
            Vec::new()
        }]);

        let tcti = tpm::tcti().map_or_else(|_| b"?".to_vec(), CString::into_bytes);
        let mut cst = ChainStatus::zeroed();
        let mut chain_rc = chain::status(&mut cst);
        if chain_rc == 0 && !(cst.defined && cst.written) {
            chain_rc = -ENODEV;
        }
        let eventlog = count_eventlog();
        // Tamper check: the live register must be the index init bound
        // this boot and equal this boot's eventlog records replayed from
        // zero. A replay failure (malformed log, or no init record while
        // a register exists) is a mismatch.
        let matches = (chain_rc == 0).then(|| {
            let mut replay = [0u8; 32];
            cst.anchored
                && !cst.rebound
                && eventlog::replay(&mut replay) == 0
                && cst.value == replay
        });

        Report {
            hostname: cstr(&host).to_vec(),
            lsm_attached,
            keyring_serial: serial,
            keyring_pinned: pinned,
            keyring_mode: mode,
            certs,
            certs_rc,
            bpf,
            dmv,
            is_operator,
            cert_present,
            is_target: cert_present || lsm_attached || serial >= 0,
            pins,
            java,
            checked,
            assets,
            tamper,
            integrity,
            config_state,
            config_root,
            tcti,
            cst,
            chain_rc,
            eventlog,
            matches,
            sysinfo,
        }
    }

    fn keyring_present(&self) -> bool {
        self.keyring_serial >= 0
    }

    /// The conditions' input, which points into the report.
    fn input(&self) -> ConditionsInput<'_> {
        let (present, pinned) = (self.keyring_present(), self.keyring_pinned >= 1);
        let (dmv_present, dmvp_seen) = (self.dmv.serial >= 0, self.dmv.pinned >= 1);
        let c = &self.checked;

        ConditionsInput {
            reachable: true,
            parsed: true,
            unreach: None,
            lsm_attached: self.lsm_attached.into(),
            keyring_present: present.into(),
            keyring_serial: self.keyring_serial.into(),
            keyring_serial_pinned: if pinned {
                self.keyring_pinned.into()
            } else {
                0
            },
            keyring_serial_matches: (present
                && pinned
                && self.keyring_serial == self.keyring_pinned)
                .into(),
            ksp_seen: pinned.into(),
            ksm_seen: (present && pinned).into(),
            bpf_unfrozen: self.bpf.n_unfrozen() as c_int,
            dmv_present: dmv_present.into(),
            dmv_serial: self.dmv.serial.into(),
            dmv_serial_pinned: if dmvp_seen { self.dmv.pinned.into() } else { 0 },
            dmv_serial_matches: (dmv_present && dmvp_seen && self.dmv.serial == self.dmv.pinned)
                .into(),
            dmvp_seen: dmvp_seen.into(),
            dmvm_seen: (dmv_present && dmvp_seen).into(),
            dmv_unfrozen: self.dmv.n_unfrozen() as c_int,
            dmv_key_missing: self.dmv.key_missing.into(),
            tpm_reachable: self.cst.tpm.into(),
            chain_seen: (self.chain_rc == 0).into(),
            chain_matches: (self.matches == Some(true)).into(),
            cm_seen: self.matches.is_some().into(),
            nv_index: Some(NV_INDEX),
            config_seen: (self.config_state != -ENODEV).into(),
            config_state: self.config_state,
            config_root: Some(&self.config_root),
            pins_rc: c.unmeasured.min(0),
            pins_unmeasured: c.unmeasured.max(0),
            pins_detail: CStr::from_bytes_until_nul(&c.unmeasured_names).ok(),
            xdp_tampered: c.xdp_tampered.max(0),
            xdp_tampered_detail: CStr::from_bytes_until_nul(&c.xdp_tampered_names).ok(),
            links_lost: c.links_lost.max(0),
            links_lost_detail: CStr::from_bytes_until_nul(&c.links_lost_names).ok(),
            checks_rc: c.checks_rc,
            xdp_uncovered: c.xdp_uncovered.max(0),
            xdp_uncovered_detail: CStr::from_bytes_until_nul(&c.xdp_uncovered_names).ok(),
            xdp_coverage_rc: c.coverage_rc,
        }
    }

    fn chain_hex(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let c = &self.cst;
        (self.chain_rc == 0).then(|| (hex(&c.value), hex(&c.name[..c.name_len.min(c.name.len())])))
    }

    /// Room for the document: every loaded upatch adds a row, every
    /// certificate and link of the keyrings an entry, whose strings JSON
    /// escaping can grow sixfold, and the events[] dump re-emits the log.
    fn json_cap(&self, include_eventlog: bool) -> usize {
        let entries = self.bpf.certs.len()
            + self.bpf.links().len()
            + self.dmv.certs.len()
            + self.dmv.links().len();
        let mut cap =
            16384 + (self.pins.len() + self.java.len()) * (6 * size_of::<UpatchTableRow>() + 256);

        cap += entries * (6 * (keyring::DESC_MAX + SUBJECT_MAX) + 512);
        if let (true, Some((_, bytes))) = (include_eventlog, self.eventlog) {
            cap += 65536 + 3 * bytes as usize;
        }
        if self.sysinfo.is_some() {
            cap += 1024 * 1024;
        }
        cap.min(MAX_BYTES)
    }

    fn emit_json(&self, e: &mut JsonEmit, cin: &ConditionsInput<'_>, include_eventlog: bool) {
        let (present, pinned) = (self.keyring_present(), self.keyring_pinned >= 1);
        let mut conds: [Condition; CONDITIONS_MAX] = no_conditions();

        e.obj_open();
        e.kv_int(b"schema", 1);
        e.kv_string(b"version_id", version_id());
        e.kv_string_lossy(b"host", &self.hostname);
        e.kv_bool(b"is_target", self.is_target);
        e.kv_bool(b"is_operator", self.is_operator);
        e.kv_string(b"status", conditions::status_verdict(cin).to_bytes());
        let reason = conditions::status_reason(cin).to_bytes();
        match reason {
            [] => e.kv_null(b"reason"),
            r => e.kv_string(b"reason", r),
        }
        let nc = conditions::conditions(cin, &mut conds);
        e.arr_open(b"conditions");
        for c in &conds[..nc] {
            e.obj_open();
            e.kv_string(b"type", c.kind.to_bytes());
            e.kv_string(b"status", c.status.to_bytes());
            e.kv_string(b"detail", cstr(&c.detail));
            e.obj_close();
        }
        e.arr_close();
        e.kv_bool(b"lsm_attached", self.lsm_attached);
        e.kv_string(b"keyring_mode", self.keyring_mode.to_bytes());
        e.kv_bool(b"keyring_present", present);
        if present {
            e.kv_int(b"keyring_serial", self.keyring_serial.into());
        } else {
            e.kv_null(b"keyring_serial");
        }
        if pinned {
            e.kv_int(b"keyring_serial_pinned", self.keyring_pinned.into());
        } else {
            e.kv_null(b"keyring_serial_pinned");
        }
        if present && pinned {
            e.kv_bool(
                b"keyring_serial_matches",
                self.keyring_serial == self.keyring_pinned,
            );
        } else {
            e.kv_null(b"keyring_serial_matches");
        }
        e.kv_bool(b"cert_present", self.cert_present);
        e.arr_open(b"certs");
        for c in self.trusted() {
            e.obj_open();
            e.kv_string(b"sha256", &hex(c.sha256()));
            e.kv_string(b"fingerprint", &hex(c.fingerprint()));
            e.kv_bool(b"primary", c.primary());
            e.obj_close();
        }
        e.arr_close();
        let ok = self.certs_rc == 0;
        e.kv_int(
            b"certs_revoked",
            if ok { self.certs.n_revoked() as i64 } else { 0 },
        );
        e.kv_int(
            b"certs_unvouched",
            if ok {
                self.certs.n_unvouched() as i64
            } else {
                0
            },
        );
        match self.certs_enrolled() {
            Some(n) => e.kv_int(b"certs_enrolled", n as i64),
            None => e.kv_null(b"certs_enrolled"),
        }
        self.bpf.emit_json(e, b"bpf_keyring", b"primary");
        self.dmv.emit_json(e, b"dm_verity_keyring", b"config");
        e.kv_bool(b"signing_key_present", self.is_operator);
        upatch_table::emit_json(e, &upatch_rows(&self.pins, &self.java));
        self.emit_assets(e);
        // What the guards counted this boot, every counter by name so a
        // collector's keys stay the same from one record to the next;
        // null until init has pinned the map.
        emit_counters(e, b"tamper_attempts", &self.tamper, tamper::name);
        emit_counters(e, b"integrity_attempts", &self.integrity, integrity::name);
        if self.config_state != -ENODEV {
            e.obj_open_key(b"config");
            e.kv_string(b"root_hash", self.config_root.to_bytes());
            e.kv_bool(b"activation_pending", self.config_state == -EINPROGRESS);
            if self.config_state != 0 && self.config_state != -EINPROGRESS {
                e.kv_string(b"error", strerr(-self.config_state));
            } else {
                e.kv_null(b"error");
            }
            e.obj_close();
        } else {
            e.kv_null(b"config");
        }
        if let Some(si) = &self.sysinfo {
            sysinfo::emit_json(e, si);
        }
        self.emit_tpm(e, include_eventlog);
        bpm_tree_state::emit_status(e);
        e.obj_close();
    }

    fn emit_assets(&self, e: &mut JsonEmit) {
        let a = &self.assets;
        let count = |e: &mut JsonEmit, key: &[u8], n: Option<usize>| match n {
            Some(n) => e.kv_int(key, n as i64),
            None => e.kv_null(key),
        };

        e.obj_open_key(b"assets");
        e.kv_string(b"root", VAR_LIB);
        e.kv_bool(b"cert", a.cert);
        e.kv_bool(b"signing_key", a.signing_key);
        e.kv_bool(b"eventlog", a.eventlog_bytes.is_some());
        e.kv_int(b"eventlog_bytes", a.eventlog_bytes.unwrap_or(0));
        count(e, b"upatches", a.upatches);
        e.kv_bool(b"bpffs_mounted", a.bpffs_mounted);
        e.obj_close();
    }

    fn emit_tpm(&self, e: &mut JsonEmit, include_eventlog: bool) {
        let c = &self.cst;

        e.obj_open_key(b"tpm");
        e.kv_bool(b"reachable", c.tpm);
        e.kv_string(b"nv_index", NV_INDEX.to_bytes());
        match self.chain_hex() {
            Some((chain, name)) => {
                e.kv_string(b"chain", &chain);
                e.kv_string(b"nv_name", &name);
            }
            None => {
                e.kv_null(b"chain");
                e.kv_null(b"nv_name");
            }
        }
        e.kv_bool(b"register_bound", self.chain_rc == 0);
        e.kv_bool(b"register_anchored", c.anchored);
        e.kv_int(
            b"init_records",
            if c.logged { c.init.records.into() } else { 0 },
        );
        e.kv_bool(b"register_rebound", c.rebound);
        e.kv_int(b"pcr", CHAIN_PCR.into());
        e.kv_int(b"phase_pcr", CHAIN_PHASE_PCR.into());
        if c.logged {
            e.kv_string(b"pcr_before", &hex(&c.init.pcr_before));
            e.kv_string(b"phase_before", &hex(&c.init.phase_before));
            e.kv_string(b"bound_in", if c.init.initrd { b"initrd" } else { b"root" });
        } else {
            e.kv_null(b"pcr_before");
            e.kv_null(b"phase_before");
            e.kv_null(b"bound_in");
        }
        match self.matches {
            Some(m) => e.kv_bool(b"chain_matches_eventlog", m),
            None => e.kv_null(b"chain_matches_eventlog"),
        }
        e.obj_open_key(b"eventlog");
        e.kv_bool(b"present", self.eventlog.is_some());
        let (entries, bytes) = self.eventlog.unwrap_or((0, 0));
        e.kv_int(b"entries", entries);
        e.kv_int(b"bytes", bytes);
        if include_eventlog {
            emit_events(e);
        }
        e.obj_close();
        e.obj_close();
    }

    fn trusted(&self) -> &[keys::TrustedCert] {
        if self.certs_rc == 0 {
            keys::members(&self.certs)
        } else {
            &[]
        }
    }

    fn certs_enrolled(&self) -> Option<usize> {
        self.bpf.links.is_ok().then(|| self.bpf.n_asymmetric())
    }

    fn print_human(&self, cin: &ConditionsInput<'_>, show_full: bool, include_eventlog: bool) {
        let mut conds: [Condition; CONDITIONS_MAX] = no_conditions();
        let verdict = conditions::status_verdict(cin).to_bytes();
        let reason = conditions::status_reason(cin).to_bytes();
        let nc = conditions::conditions(cin, &mut conds);
        let rows = upatch_rows(&self.pins, &self.java);
        let mut folded: Vec<&[u8]> = Vec::new();
        // A section a condition vouches for says nothing the condition
        // did not: it unfolds when that condition is not OK on a target,
        // or on request.
        let (mut keyrings_open, mut tpm_open) = (show_full, show_full);

        for c in conds[..nc].iter().filter(|_| self.is_target) {
            let (kind, status) = (c.kind.to_bytes(), c.status.to_bytes());
            match (status, kind) {
                (b"OK", _) => {}
                (_, b"KeyringSealed") => keyrings_open = true,
                (_, b"ChainIntact" | b"TpmMeasured") => tpm_open = true,
                _ => {}
            }
        }
        system_row(b"", b"Host:", &self.hostname);
        row(b"", b"Roles:", roles(self.is_target, self.is_operator));
        match reason {
            [] => row(b"", b"Status:", verdict),
            r => row(b"", b"Status:", &[verdict, b"  (", r, b")"].concat()),
        }
        row(b"", b"Version ID:", version_id());
        print(b"\n");
        conditions::conditions_print(&conds[..nc]);
        print(b"\nTamper attempts (this boot):\n");
        print_counters(&self.tamper, tamper::name, tamper::meaning);
        print(b"\nIntegrity attempts (this boot):\n");
        print_counters(&self.integrity, integrity::name, integrity::meaning);
        upatch_table::print(&rows);
        drop(rows);
        if keyrings_open {
            self.print_keyrings();
        } else {
            folded.push(b"keyrings");
        }
        if tpm_open {
            self.print_tpm();
        } else {
            folded.push(b"TPM measurement");
        }
        if include_eventlog {
            print_events();
        }
        if show_full {
            self.print_assets();
        } else {
            folded.push(b"assets");
        }
        if let Some(si) = &self.sysinfo {
            print_system(si);
        }
        if !folded.is_empty() {
            print(
                &[
                    b"\nFolded: ",
                    &folded.join(&b", "[..])[..],
                    b" (--show-full)\n",
                ]
                .concat(),
            );
        }
    }

    fn print_keyrings(&self) {
        let (bpf, dmv) = (&self.bpf, &self.dmv);

        print(b"\nKeyring (.bpf):\n");
        bpf.print_serials();
        if self.certs_rc == 0 {
            let c = &self.certs;
            let mut line = format!(
                "{} trusted, {} revoked, {} unvouched",
                c.len(),
                c.n_revoked(),
                c.n_unvouched()
            );
            if let Some(n) = self.certs_enrolled() {
                line += &format!(", {n} in the bpf keyring");
            }
            row(b"  ", b"Certificates:", line.as_bytes());
            bpf.print_certs(b"primary", b"enrolled at the next boot");
        }
        bpf.print_other_links();
        print(b"\nKeyring (.dm-verity):\n");
        dmv.print_serials();
        if dmv.certs_rc == 0 {
            let mut line = format!("{} trusted", dmv.certs.len());
            if dmv.links.is_ok() {
                line += &format!(", {} in the dm-verity keyring", dmv.n_asymmetric());
            }
            row(b"  ", b"Certificates:", line.as_bytes());
            dmv.print_certs(b"config", b"missing");
        } else if dmv.certs_rc != -ENOENT {
            row(
                b"  ",
                b"Certificates:",
                &[b"unreadable: ", strerr(-dmv.certs_rc)].concat(),
            );
        }
        dmv.print_other_links();
    }

    fn print_tpm(&self) {
        let c = &self.cst;
        let field = |label: &[u8], value: &[u8]| row(b"  ", label, value);

        print(b"\nTPM measurement:\n");
        let reach: &[u8] = if c.tpm {
            b"reachable"
        } else {
            b"not reachable"
        };
        field(b"TPM:", &[reach, b" (", &self.tcti, b")"].concat());
        field(
            b"NV index:",
            &[NV_INDEX.to_bytes(), b" (anchored in PCR 9)"].concat(),
        );
        if let Some((chain, name)) = self.chain_hex() {
            field(b"Chain:", &chain);
            field(b"Register name:", &name);
            field(
                b"Anchored:",
                if c.anchored {
                    b"yes, name on record"
                } else {
                    b"no, the index is not the one init bound"
                },
            );
        } else if !c.tpm {
            field(b"Chain:", b"unavailable, no TPM answered");
        } else if self.chain_rc == -ENODEV {
            field(b"Chain:", b"unavailable, register not bound this boot");
        } else {
            field(
                b"Chain:",
                &[b"unavailable, TPM error: ", strerr(-self.chain_rc)].concat(),
            );
        }
        if c.logged {
            field(b"PCR before init:", &hex(&c.init.pcr_before));
            field(
                b"Phase at init:",
                &[&hex(&c.init.phase_before)[..], b" (PCR 11)"].concat(),
            );
            field(
                b"Bound in:",
                if c.init.initrd {
                    b"initrd"
                } else {
                    b"root file system"
                },
            );
        }
        if c.rebound {
            let line = format!(
                "{} for this TPM reset, rebound after init",
                c.init.records_epoch
            );
            field(b"Init records:", line.as_bytes());
        }
        field(
            b"Chain vs eventlog:",
            match self.matches {
                None => b"not evaluated",
                Some(true) => b"matches",
                Some(false) => b"mismatch",
            },
        );
        match self.eventlog {
            Some((entries, bytes)) => {
                let counts = format!("  ({entries} entries, {bytes} bytes)");
                field(b"Eventlog:", &[eventlog(), counts.as_bytes()].concat());
            }
            None => field(b"Eventlog:", b"absent"),
        }
    }

    fn print_assets(&self) {
        let a = &self.assets;
        let field = |label: &[u8], value: &[u8]| row(b"  ", label, value);
        let present = |p: bool| -> &'static [u8] { if p { b"present" } else { b"absent" } };

        print(&[b"\nAssets (", VAR_LIB, b"):\n"].concat());
        field(b"keys/cert.der", present(a.cert));
        field(b"keys/signing_key.pem", present(a.signing_key));
        match a.eventlog_bytes {
            Some(n) => field(b"eventlog", format!("present ({n} bytes)").as_bytes()),
            None => field(b"eventlog", b"absent"),
        }
        match a.upatches {
            None => field(b"upatches/", b"absent"),
            Some(n) => field(b"upatches/", format!("{n} archived").as_bytes()),
        }
        field(
            b"bpffs/",
            if a.bpffs_mounted {
                b"mounted"
            } else {
                b"not mounted"
            },
        );
    }
}

/// Room for the conditions before conditions() fills them.
fn no_conditions() -> [Condition; CONDITIONS_MAX] {
    [Condition::empty(); CONDITIONS_MAX]
}

fn roles(is_target: bool, is_operator: bool) -> &'static [u8] {
    match (is_target, is_operator) {
        (true, true) => b"target, operator",
        (false, true) => b"operator",
        (true, false) => b"target",
        (false, false) => b"none",
    }
}

fn version_id() -> &'static [u8] {
    // SAFETY: the version ID, a static C string.
    unsafe { ffi::c_str(&raw const shirudo_version_id) }
}

/// A set of guard counters under `key`, every counter by name so that a
/// collector's keys stay the same from one record to the next; null
/// until init has pinned the map.
fn emit_counters<const N: usize>(
    e: &mut JsonEmit,
    key: &[u8],
    counts: &Result<Counters<N>, c_int>,
    name: fn(usize) -> &'static [u8],
) {
    match counts {
        Ok(c) => {
            e.obj_open_key(key);
            e.kv_int(b"total", c.total as i64);
            e.obj_open_key(b"counters");
            for (i, &n) in c.count.iter().enumerate() {
                e.kv_int(name(i), n as i64);
            }
            e.obj_close();
            e.obj_close();
        }
        Err(_) => e.kv_null(key),
    }
}

/// The counters of a set that moved, each with what it counts.
fn print_counters<const N: usize>(
    counts: &Result<Counters<N>, c_int>,
    name: fn(usize) -> &'static [u8],
    meaning: fn(usize) -> &'static [u8],
) {
    match counts {
        Err(err) if *err == -ENOENT => print(b"  none recorded before init\n"),
        Err(err) => print(&[b"  unavailable: ", strerr(-err), b"\n"].concat()),
        Ok(c) => {
            if c.total == 0 {
                print(b"  none\n");
            }
            for (i, &n) in c.count.iter().enumerate().filter(|&(_, &n)| n != 0) {
                let count = format!("{n:>6}");
                print(
                    &[
                        &b"  "[..],
                        &pad(name(i), 20),
                        b" ",
                        count.as_bytes(),
                        b"  ",
                        meaning(i),
                        b"\n",
                    ]
                    .concat(),
                );
            }
        }
    }
}

/// `shirudo status`, on `args` from its name on.
pub(crate) fn cmd_status(args: &[&CStr]) -> c_int {
    let (mut json_stdout, mut otel, mut keepalive) = (false, false, false);
    let (mut check, mut show_full) = (false, false);
    let (mut include_system, mut include_eventlog) = (false, false);
    let mut p = OptParser::new(c"status", &OPTS, Some(&HELP), args, 1);

    loop {
        match p.next() {
            OPT_END => break,
            STATUS_JSON => json_stdout = true,
            STATUS_OTEL => otel = true,
            STATUS_KEEPALIVE => keepalive = true,
            STATUS_CHECK => check = true,
            STATUS_SHOW_FULL => show_full = true,
            STATUS_INCLUDE_SYSTEM => include_system = true,
            STATUS_INCLUDE_EVENTLOG => include_eventlog = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    if keepalive && (json_stdout || otel) {
        p.usage(b"--keepalive goes without --json and --otel");
        return EXIT_USAGE;
    }
    if show_full {
        include_system = true;
        include_eventlog = true;
    }
    let exporter = match otel.then(Otel::load).transpose() {
        Ok(o) => o,
        Err(ret) => return ret,
    };
    let configured = exporter.as_ref().is_some_and(Otel::endpoint_configured);
    let r = Report::gather(include_system);
    let cin = r.input();
    let mut ret = 0;

    if keepalive || configured {
        let root = (r.config_state == 0).then(|| r.config_root.to_bytes());
        let opts = exporter.as_ref().map(Otel::opts);
        ret = keepalive::run(&r, &cin, root, opts.as_ref());
    }
    let state = r.config_state;
    if otel && !configured && state != 0 && state != -ENODEV {
        let why: &[u8] = if state == -EINPROGRESS {
            b"pending"
        } else {
            b"unverifiable"
        };
        let msg = message(&[
            b"status: no keepalive is sent: with the config activation ",
            why,
            b", no export endpoint is known, since a config image is used only when its activation record vouches for it; OTEL_EXPORTER_OTLP_ENDPOINT in /etc/shirudo/map-export.env still names one",
        ]);
        crate::log::warn(msg.to_bytes());
    }
    if json_stdout {
        let mut buf = vec![0u8; r.json_cap(include_eventlog)];
        let mut e = JsonEmit::fixed(&mut buf);

        r.emit_json(&mut e, &cin, include_eventlog);
        if e.err() != 0 {
            eprint(&[b"status: json encode failed: ", strerr(-e.err()), b"\n"].concat());
            ret = 1;
        } else {
            print(&[e.output(), b"\n"].concat());
        }
    } else if !keepalive && !otel {
        r.print_human(&cin, show_full, include_eventlog);
    }
    if check && ret == 0 && conditions::status_verdict(&cin) == c"tampered" {
        ret = 1;
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::{UNMEASURED_NAMES, lines, note};
    use crate::text::cstr;

    #[test]
    fn name_list_marks_truncation_once() {
        let mut names = [0u8; UNMEASURED_NAMES];
        note(&mut names, b"first");
        note(&mut names, b"second");
        assert_eq!(cstr(&names), b"first, second");

        let mut near_full = [0u8; UNMEASURED_NAMES];
        note(&mut near_full, &vec![b'a'; UNMEASURED_NAMES - 2]);
        note(&mut near_full, b"next");
        assert_eq!(cstr(&near_full).len(), UNMEASURED_NAMES - 1);
        assert!(cstr(&near_full).ends_with(b"..."));
        let final_list = near_full;
        note(&mut near_full, b"another");
        assert_eq!(near_full, final_list);

        let mut empty = [0u8; UNMEASURED_NAMES];
        note(&mut empty, &vec![b'a'; UNMEASURED_NAMES]);
        assert_eq!(cstr(&empty), b"");
    }

    #[test]
    fn eventlog_lines_continue_after_nul_and_skip_unfinished_tail() {
        let text = b"first\nsecond\0bad\nthird\nunfinished";
        assert_eq!(
            lines(text).collect::<Vec<_>>(),
            vec![&b"first"[..], &b"second\0bad"[..], &b"third"[..]]
        );
        assert_eq!(lines(b"\n").collect::<Vec<_>>(), vec![&b""[..]]);
    }
}
