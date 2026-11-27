// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The package: a deterministic gzip-compressed ustar archive under one
//! top directory, `<name>-<version>/`, of the Beefile, the files, the
//! signed upatches, the README, the certificate and the build
//! environment. Every entry has owner 0 and time 0, so the same inputs
//! make the same archive.

use core::ffi::c_int;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

use super::beefile::{PATH_MAX, Spec};
use super::{build, path, print};
use crate::errno::{E2BIG, EFBIG, EINVAL, EIO, ENAMETOOLONG, ENOENT};
use crate::sys::libc::Zeroed;
use crate::sys::version::shirudo_version;
use crate::util::gzip::GzWrite;
use crate::util::io;
use crate::util::json::JsonEmit;
use crate::util::timefmt::iso8601;

/// The largest file a package takes in.
pub(super) const MAX_FILE: usize = 256 * 1024 * 1024;
/// `BPM_MAX_PACKAGE_BYTES`: what the target's extractor unpacks of a
/// package at most, its members together.
const MAX_PACKAGE: u64 = 256 * 1024 * 1024;
/// Room for the build environment's JSON.
const MAX_JSON: usize = 256 * 1024;

/// A file read whole, at most `max` bytes: -EFBIG for a larger one.
pub(super) fn read_file(p: &[u8], max: usize) -> Result<Vec<u8>, c_int> {
    let mut f = std::fs::File::open(path(p)).map_err(|e| io::errno_of(&e))?;
    let size = f.metadata().map_err(|e| io::errno_of(&e))?.len();
    if size > max as u64 {
        return Err(-EFBIG);
    }
    let mut body = vec![0u8; usize::try_from(size).map_err(|_| -EFBIG)?];
    let mut n = 0;
    while n < body.len() {
        match std::io::Read::read(&mut f, &mut body[n..]) {
            Ok(0) => return Err(-EIO),
            Ok(got) => n += got,
            Err(e) => return Err(io::errno_of(&e)),
        }
    }
    Ok(body)
}

/// The gzip stream the archive goes into, as zlib's gzopen(path, "wb9")
/// writes it, and the bytes of content written so far.
struct Tar(GzWrite<std::fs::File>, u64);

impl Tar {
    fn write(&mut self, data: &[u8]) -> Result<(), c_int> {
        if data.is_empty() {
            return Ok(());
        }
        if c_int::try_from(data.len()).is_err() {
            return Err(-EFBIG);
        }
        self.0.write(data).map_err(|_| -EIO)
    }

    /// One ustar entry, its header and its data padded to 512 bytes.
    fn entry(&mut self, name: &[u8], data: &[u8], mode: u32, ty: u8) -> Result<(), c_int> {
        let mut h = [0u8; 512];

        if name.len() >= 100 {
            return Err(-ENAMETOOLONG);
        }
        // The sum the target's extractor takes: more would build and
        // never install.
        let size = u64::try_from(data.len()).map_err(|_| -EFBIG)?;
        if size > MAX_PACKAGE - self.1 {
            return Err(-EFBIG);
        }
        self.1 += size;
        h[..name.len()].copy_from_slice(name);
        for (off, size, value) in [
            (100, 8, u64::from(mode & 0o7777)),
            (108, 8, 0),
            (116, 8, 0),
            (124, 12, size),
            (136, 12, 0),
        ] {
            let digits = format!("{value:0w$o}", w = size - 1);
            if digits.len() > size - 1 {
                return Err(-E2BIG);
            }
            h[off..off + digits.len()].copy_from_slice(digits.as_bytes());
        }
        h[148..156].fill(b' ');
        h[156] = ty;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let sum = format!("{sum:06o} ");
        if sum.len() > 7 {
            return Err(-E2BIG);
        }
        h[148..148 + sum.len()].copy_from_slice(sum.as_bytes());
        h[148 + sum.len()] = 0;
        self.write(&h)
            .and_then(|()| self.write(data))
            .map_err(|_| -EIO)?;
        if ty == b'0' && data.len() & 511 != 0 {
            return self.write(&[0u8; 512][..512 - (data.len() & 511)]);
        }
        Ok(())
    }

    /// The regular file at `file` as entry `name`, with its mode.
    fn file(&mut self, name: &[u8], file: &[u8]) -> Result<(), c_int> {
        let meta = std::fs::metadata(path(file)).map_err(|e| io::errno_of(&e))?;
        if !meta.is_file() {
            return Err(-EINVAL);
        }
        let body = read_file(file, MAX_FILE)?;
        self.entry(name, &body, meta.mode(), b'0')
    }
}

/// `<top>/<entry>`, within PATH_MAX.
fn entry_name(top: &[u8], entry: &[u8]) -> Result<Vec<u8>, c_int> {
    if top.len() + entry.len() + 2 > PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    Ok([top, b"/", entry].concat())
}

fn basename(p: &[u8]) -> &[u8] {
    p.iter()
        .rposition(|&c| c == b'/')
        .map_or(p, |s| &p[s + 1..])
}

/// build-environment.json: who built the package, when, where, with
/// what, and what the upatches came out as.
fn environment(spec: &Spec, version: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut stamp = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(Ok(0), |d| i64::try_from(d.as_secs()).map_err(|_| -EIO))?;
    let mut un = crate::sys::libc::Utsname::zeroed();
    // SAFETY: room for the names.
    if unsafe { crate::sys::libc::uname(&mut un) } != 0 || iso8601(now, &mut stamp) != 0 {
        return Err(-EIO);
    }
    let me = std::fs::read_link("/proc/self/exe")
        .ok()
        .map(|p| std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()).to_vec())
        .filter(|p| !p.is_empty() && p.len() < PATH_MAX)
        .unwrap_or_else(|| b"shirudo".to_vec());
    // SAFETY: the version, a static C string.
    let version_str = unsafe { crate::ffi::c_str(&raw const shirudo_version) };
    let mut buf = vec![0u8; MAX_JSON];
    let mut e = JsonEmit::fixed(&mut buf);
    let cstr = crate::text::cstr;

    e.obj_open();
    e.kv_int(b"format_version", 1);
    e.kv_string(b"builder", b"bpm build");
    e.kv_string(b"created_at", cstr(&stamp));
    e.obj_open_key(b"package");
    e.kv_string(b"name", &spec.name);
    e.kv_string(b"version", version);
    e.obj_close();
    e.kv_string(b"os", cstr(crate::sys::libc::bytes(&un.sysname)));
    e.kv_string(b"arch", cstr(crate::sys::libc::bytes(&un.machine)));
    e.kv_string(b"bpm_version", version_str);
    e.obj_open_key(b"shirudo");
    e.kv_string(b"path", &me);
    e.kv_string(b"version", version_str);
    e.kv_string(b"spki_sha256_fingerprint", fingerprint);
    e.obj_close();
    e.arr_open(b"upatches");
    for u in &spec.upatches {
        e.obj_open();
        e.kv_string(b"source", &u.source);
        e.kv_string(b"type", &u.ty);
        e.kv_string(b"load_target", &u.load_target);
        e.kv_string(b"load_output", basename(&u.load_target));
        e.kv_string(b"unload_target", &u.unload_target);
        e.kv_string(b"unload_output", basename(&u.unload_target));
        e.kv_string(b"upatch_name", &u.name);
        e.kv_string(b"payload_sha256", &u.payload_sha256);
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    let n = e.written();
    buf.truncate(n);
    Ok(buf)
}

fn entries(tar: &mut Tar, spec: &Spec, top: &[u8], cert: &[u8], env: &[u8]) -> Result<(), c_int> {
    let named = |entry: &[u8]| entry_name(top, entry);
    tar.entry(&named(b"")?, &[], 0o755, b'5')?;
    tar.entry(&named(b"Beefile")?, &spec.build_file, 0o644, b'0')?;
    for f in &spec.files {
        let resolved = build::resolve_source(spec, &f.source)?;
        tar.file(&named(&f.target)?, &resolved)?;
    }
    for u in &spec.upatches {
        tar.file(&named(&u.load_target)?, &u.load_path)?;
        tar.file(&named(&u.unload_target)?, &u.unload_path)?;
    }
    let readme = [&spec.scope[..], b"/README.md"].concat();
    if readme.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    match std::fs::metadata(path(&readme)) {
        Ok(_) if !build::within(&spec.scope, &readme) => return Err(-EINVAL),
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(ENOENT) => {}
        Err(e) => return Err(io::errno_of(&e)),
    }
    let r = CString::new(readme.clone()).unwrap_or_default();
    if super::super::compile::readable(&r) {
        tar.file(&named(b"README.md")?, &readme)?;
    }
    tar.entry(&named(b"cert.der")?, cert, 0o644, b'0')?;
    tar.entry(&named(b"build-environment.json")?, env, 0o644, b'0')?;
    tar.write(&[0u8; 1024])
}

/// The package of `spec` at version `version`, signed with the
/// certificate at `cert_path`, into `<out_dir>/<name>-<version>.bee`.
pub(super) fn write(
    command: &str,
    spec: &Spec,
    version: &[u8],
    cert_path: &[u8],
    fingerprint: &[u8],
    out_dir: &[u8],
) -> Result<(), c_int> {
    let top = [&spec.name[..], b"-", version].concat();
    let output = [out_dir, b"/", &top, b".bee"].concat();

    if top.len() >= PATH_MAX || output.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let env = environment(spec, version, fingerprint).map_err(|_| -EIO)?;
    let cert = read_file(cert_path, MAX_FILE).map_err(|_| -ENOENT)?;
    let file = std::fs::File::create(path(&output)).map_err(|e| io::errno_of(&e))?;
    let mut tar = Tar(GzWrite::new(file, 9, 3).map_err(|_| -EIO)?, 0);
    let written = entries(&mut tar, spec, &top, &cert, &env);
    let finished = tar.0.finish().map(|_| ()).map_err(|_| -EIO);
    let ret = written.and(finished).map_err(|err| {
        if err == -EFBIG {
            crate::log::err(
                format!(
                    "{command}: the members of the package are more than {} MiB together, the most a target installs",
                    MAX_PACKAGE >> 20
                )
                .as_bytes(),
            );
            -EINVAL
        } else {
            err
        }
    });
    if ret.is_err() {
        let _ = std::fs::remove_file(path(&output));
    } else {
        let line = [&output[..], b"\n"].concat();
        print(true, &line);
    }
    ret
}
