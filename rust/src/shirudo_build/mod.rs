// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build`, the operator's artifact pipeline: compiles a
//! `.bpf.c` with clang, packages and signs it as a `.upatch`, or signs
//! an unload directive; and dispatches the operator's image, upatch, bpm
//! and keys commands. It runs on the operator only, and is the one
//! binary that links the CMS signer.

mod bpm;
mod compile;
mod image;
mod jar;
mod package;
mod sign;
mod skeleton;
mod vouch;

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use crate::errno::{EIO, ENAMETOOLONG, EPERM};
use crate::ffi;
use crate::sys::libc::{access, close, fwrite, mkstemps, stderr, stdout, strerror};
use crate::text::{cstr, name_has_suffix};
use crate::util::harden::{harden_self, harden_stdio};
use crate::util::help::{Help, HelpSection};
use crate::util::hex::decode;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::paths::{key_file, key_files, keys_dir};
use crate::util::upatch::{TYPE_JAVA, Upatch};

const SIGNING_KEY_PATH: &CStr = c"/var/lib/shirudo/keys/signing_key.pem";
const CERT_PATH: &CStr = c"/var/lib/shirudo/keys/cert.der";
const SIGNING_KEY_FILE: &CStr = c"signing_key.pem";
const CERT_FILE: &CStr = c"cert.der";
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const PATH_MAX: usize = 4096;
const R_OK: c_int = 4;

fn say(level: fn(&[u8]), text: &[u8]) {
    let msg = CString::new(cstr(text).to_vec()).unwrap_or_default();

    level(msg.to_bytes());
}

fn error(text: &[u8]) {
    say(crate::log::err, text);
}

fn info(text: &[u8]) {
    say(crate::log::info, text);
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn last_err() -> c_int {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

fn print(to_stdout: bool, text: &[u8]) {
    // Keep writes ordered with the help and option parser's stdio.
    // SAFETY: libc provides both streams throughout the command.
    let stream = unsafe { if to_stdout { stdout } else { stderr } };
    // SAFETY: the bytes are readable for the duration of the write.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stream) };
}

fn check_access(path: &CStr, mode: c_int) -> Result<(), c_int> {
    // SAFETY: path is NUL terminated and access does not retain it.
    if unsafe { access(path.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(last_err())
    }
}

const BUILD_OUTPUT: c_int = 0;
const BUILD_NAME: c_int = 1;
const BUILD_KEYS_DIR: c_int = 2;
const BUILD_KEY: c_int = 3;
const BUILD_CERT: c_int = 4;
const BUILD_VMLINUX: c_int = 5;
const BUILD_EXTRA_CFLAGS: c_int = 6;
const BUILD_UNLOAD: c_int = 7;
const BUILD_PAYLOAD_SHA256: c_int = 8;
const BUILD_JAVA: c_int = 9;
const BUILD_EMIT_ARTIFACTS: c_int = 10;

const VMLINUX_HELP: &CStr = ffi::c_splice!(
    "compile against it instead of ./vmlinux.h, ./vendor/linux/vmlinux.h or ",
    compile::VMLINUX_PATH
);

static BUILD_OPTS: [OptSpec; 11] = [
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<output.upatch>"),
        c"where to write the upatch instead of beside the input, or of <name>.unload.upatch in the current directory",
    ),
    OptSpec::new(
        c"--name",
        0,
        0,
        Some(c"<upatch-name>"),
        c"the upatch's name instead of the one the input gives",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>, where SHIRUDO_KEYS_DIR points otherwise",
    ),
    OptSpec::new(
        c"--key",
        0,
        0,
        Some(c"<signing_key.pem>"),
        c"the signing key, over --keys-dir (default /var/lib/shirudo/keys/signing_key.pem)",
    ),
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate, over --keys-dir (default /var/lib/shirudo/keys/cert.der)",
    ),
    OptSpec::new(c"--vmlinux", 0, 0, Some(c"<vmlinux.h>"), VMLINUX_HELP),
    OptSpec::new(
        c"--extra-cflags",
        0,
        0,
        Some(c"'<flags>'"),
        c"more flags for clang",
    ),
    OptSpec::new(
        c"--unload",
        0,
        0,
        Some(c"<upatch-name>"),
        c"sign the UNLOAD directive of the named upatch",
    ),
    OptSpec::new(
        c"--payload-sha256",
        0,
        0,
        Some(c"<64-hex>"),
        c"with --unload, the payload digest, which the archive /var/lib/shirudo/upatches/<name>.upatch gives otherwise",
    ),
    OptSpec::new(
        c"--java",
        0,
        0,
        None,
        c"with --unload and --payload-sha256, sign the directive of a Java upatch, which the archive tells otherwise",
    ),
    OptSpec::new(
        c"--emit-artifacts",
        0,
        0,
        None,
        c"keep the compiled .bpf.o beside the .upatch and print each path written",
    ),
];

static BUILD_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &BUILD_OPTS)];

static BUILD_HELP: Help = Help::new(
    c"shirudo build <input.bpf.c|.bpf.o|.jar> [-o <output.upatch>] [options]\n       \
      shirudo build --unload <upatch-name> [-o <output.upatch>] [options]",
    Some(
        c"Compile a .bpf.c, or take a .bpf.o or a Java agent .jar, and sign it into\n\
          a .upatch, or sign the UNLOAD directive of a loaded upatch.\n\
          foo/bar.bpf.c becomes foo/bar.bpf.upatch, foo/agent.jar foo/agent.upatch.",
    ),
    &BUILD_SECTIONS,
    Some(
        c"The helper also serves shirudo image build and verify, the operator\n\
          bpm commands and keys vouch; each takes --help.",
    ),
);

fn has_suffix(s: &CStr, suffix: &CStr) -> bool {
    name_has_suffix(s.to_bytes(), suffix.to_bytes())
}

/// `stem` and then `ext`, as long as the path fits PATH_MAX.
fn with_ext(stem: &[u8], ext: &[u8]) -> Result<CString, c_int> {
    let path = [stem, ext].concat();

    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -ENAMETOOLONG)
}

/// foo/bar.bpf.c lands at foo/bar.bpf.upatch beside its input.
fn derive_output(input: &CStr) -> Result<CString, c_int> {
    let s = input.to_bytes();
    let stem = if has_suffix(input, c".c") || has_suffix(input, c".o") {
        &s[..s.len() - 2]
    } else if has_suffix(input, c".jar") {
        &s[..s.len() - 4]
    } else {
        s
    };

    with_ext(stem, b".upatch")
}

/// The .bpf.o sits beside the .upatch.
fn derive_artifact_o(output: &CStr) -> Result<CString, c_int> {
    let s = output.to_bytes();
    let stem = if has_suffix(output, c".upatch") {
        &s[..s.len() - 7]
    } else {
        s
    };

    with_ext(stem, b".o")
}

/// A temporary object clang compiles into, removed when it goes.
struct TempObject(CString);

impl Drop for TempObject {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(path(self.0.to_bytes()));
    }
}

fn compile_to_temp(
    source: &CStr,
    vmlinux_h: &CStr,
    extra: Option<&CStr>,
) -> Result<TempObject, c_int> {
    let mut tmpl = *b"/tmp/shirudo-build-XXXXXX.bpf.o\0";
    // SAFETY: the template, which mkstemps() fills in.
    let fd = unsafe { mkstemps(tmpl.as_mut_ptr().cast(), 6) };

    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: the descriptor opened above.
    unsafe { close(fd) };
    let obj = TempObject(CString::new(cstr(&tmpl).to_vec()).unwrap_or_default());
    compile::compile(source, &obj.0, vmlinux_h, extra, None)?;
    Ok(obj)
}

/// Whether the signing key opens as one and the certificate reads: 0,
/// or 1 with the reason logged.
fn check_keys(pkey: &CStr, cert: &CStr) -> c_int {
    if let Err(err) = sign::open_signing_key(pkey) {
        if err != -EPERM {
            error(b"run `shirudo genkey` on the operator (or pass --key).");
        }
        return 1;
    }
    if let Err(err) = check_access(cert, R_OK) {
        error(&[b"cert not readable: ", cert.to_bytes(), b": ", strerr(-err)].concat());
        error(b"run `shirudo genkey` on the operator (or pass --cert).");
        return 1;
    }
    0
}

/// The signing key and certificate a command signs with: named on its
/// command line, else under the keys directory, else the defaults.
struct KeyFiles {
    pkey: CString,
    cert: CString,
    pkey_named: bool,
    cert_named: bool,
}

impl Default for KeyFiles {
    fn default() -> Self {
        KeyFiles {
            pkey: SIGNING_KEY_PATH.into(),
            cert: CERT_PATH.into(),
            pkey_named: false,
            cert_named: false,
        }
    }
}

impl KeyFiles {
    /// The key and certificate under the directory `dir`, as key_files()
    /// spells them.
    fn under(dir: &[u8]) -> Result<Self, c_int> {
        let (pkey, cert) = key_files(dir)?;
        Ok(KeyFiles {
            pkey,
            cert,
            pkey_named: false,
            cert_named: false,
        })
    }

    fn set_pkey(&mut self, path: &CStr) {
        self.pkey = path.into();
        self.pkey_named = true;
    }

    fn set_cert(&mut self, path: &CStr) {
        self.cert = path.into();
        self.cert_named = true;
    }

    /// The key and the certificate under the keys directory, those not
    /// named; the directory and the error when one does not fit.
    fn resolve(&mut self, dir: Option<&CStr>) -> Result<(), (Vec<u8>, c_int)> {
        let dir = keys_dir(dir).to_bytes();
        let fail = |e| (dir.to_vec(), e);

        if !self.pkey_named {
            self.pkey = key_file(dir, SIGNING_KEY_FILE).map_err(fail)?;
        }
        if !self.cert_named {
            self.cert = key_file(dir, CERT_FILE).map_err(fail)?;
        }
        Ok(())
    }

    /// As resolve(), but both must fit under the directory, named or
    /// not, as key_files() has them.
    fn resolve_both(&mut self, dir: Option<&CStr>) -> Result<(), c_int> {
        let (pkey, cert) = key_files(keys_dir(dir).to_bytes())?;

        if !self.pkey_named {
            self.pkey = pkey;
        }
        if !self.cert_named {
            self.cert = cert;
        }
        Ok(())
    }
}

/// Owns a certificate returned by the shared crypto reader.
struct Certificate(crate::util::crypto_openssl::Cert);

impl Certificate {
    fn open(path: &CStr) -> Result<Self, c_int> {
        let mut cert = Self(crate::util::crypto_openssl::Cert::new());
        // SAFETY: path is NUL terminated and the certificate is empty.
        let ret =
            unsafe { crate::util::crypto_openssl::cert_read_file(path.as_ptr(), &mut cert.0) };
        if ret == 0 { Ok(cert) } else { Err(ret) }
    }

    fn as_cert(&self) -> &crate::util::crypto_openssl::Cert {
        &self.0
    }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

fn path(p: &[u8]) -> &std::ffi::OsStr {
    std::os::unix::ffi::OsStrExt::from_bytes(p)
}

#[derive(Default)]
struct Opts<'a> {
    output: Option<&'a CStr>,
    name: Option<&'a CStr>,
    java: bool,
    keys_dir: Option<&'a CStr>,
    pkey: Option<&'a CStr>,
    cert: Option<&'a CStr>,
    vmlinux: Option<&'a CStr>,
    extra_cflags: Option<&'a CStr>,
    unload: Option<&'a CStr>,
    payload_sha256: Option<&'a CStr>,
    emit_artifacts: bool,
    input: Option<&'a CStr>,
}

/// The digest of the payload an unload directive names: the one given,
/// else the loaded payload's as the operator's local archive records it,
/// since the target refuses a directive whose digest is not that.
/// None when the digest given is no 64 hex digits, a usage error.
fn unload_digest(name: &CStr, given: Option<&CStr>) -> Result<([u8; 32], bool), Option<c_int>> {
    let mut digest = [0u8; 32];

    if let Some(hex) = given {
        if decode(hex.to_bytes(), &mut digest).is_err() {
            return Err(None);
        }
        return Ok((digest, false));
    }
    let archive = [UPATCHES_DIR.as_bytes(), b"/", name.to_bytes(), b".upatch"].concat();
    if archive.len() >= PATH_MAX {
        error(&[b"archive path too long for '", name.to_bytes(), b"'"].concat());
        return Err(Some(1));
    }
    let path = CString::new(archive).unwrap_or_default();
    let Ok(u) = Upatch::open(&path) else {
        error(
            &[
                b"--payload-sha256 omitted and no archive at ",
                path.to_bytes(),
                b"; pass the digest upatch info shows",
            ]
            .concat(),
        );
        return Err(Some(2));
    };
    let java = u.hdr.ty == TYPE_JAVA;
    digest = u.hdr.payload_sha256;
    drop(u);
    info(&[b"--payload-sha256 derived from archive ", path.to_bytes()].concat());
    Ok((digest, java))
}

fn unload(p: &OptParser<'_>, o: &Opts, name: &CStr, pkey: &CStr, cert: &CStr) -> c_int {
    let (digest, inferred_java) = match unload_digest(name, o.payload_sha256) {
        Ok(found) => found,
        Err(None) => {
            p.usage(b"--payload-sha256 must be 64 hex characters");
            return EXIT_USAGE;
        }
        Err(Some(ret)) => return ret,
    };
    let derived;
    let output = match o.output {
        Some(out) => out,
        None => {
            derived = match with_ext(name.to_bytes(), b".unload.upatch") {
                Ok(p) => p,
                Err(_) => {
                    error(&[b"derived output path too long for '", name.to_bytes(), b"'"].concat());
                    return 1;
                }
            };
            info(&[b"writing ", derived.to_bytes(), b" (no -o given)"].concat());
            &derived
        }
    };
    let ret = package::unload_directive(name, &digest, output, pkey, cert, o.java || inferred_java);
    if ret.is_ok() && o.emit_artifacts {
        let text = [
            b"emitted:\n  upatch: ",
            output.to_bytes(),
            b"\n  bpf.o:  (none; --unload embeds the prebuilt unload program)\n",
        ]
        .concat();
        print(true, &text);
    }
    c_int::from(ret.is_err())
}

fn load(o: &Opts, input: &CStr, pkey: &CStr, cert: &CStr) -> c_int {
    // The output comes first: --emit-artifacts derives the .bpf.o from
    // it so the object lands in the same directory as the .upatch.
    let derived;
    let output = match o.output {
        Some(out) => out,
        None => {
            derived = match derive_output(input) {
                Ok(p) => p,
                Err(err) => {
                    error(
                        &[
                            b"cannot derive output path from ",
                            input.to_bytes(),
                            b": ",
                            strerr(-err),
                        ]
                        .concat(),
                    );
                    return 1;
                }
            };
            info(&[b"writing ", derived.to_bytes(), b" (no -o given)"].concat());
            &derived
        }
    };
    let derived_name;
    let name = match o.name {
        Some(n) => n,
        None => {
            derived_name = match bpm::upatch_name(input.to_bytes()) {
                Ok(n) => CString::new(n).unwrap_or_default(),
                Err(_) => {
                    error(&[b"upatch name from ", input.to_bytes(), b" too long"].concat());
                    return 2;
                }
            };
            &derived_name
        }
    };
    if has_suffix(input, c".jar") {
        let ret = package::java_load(input, output, name, (pkey, cert));
        if ret.is_ok() && o.emit_artifacts {
            print(
                true,
                &[b"emitted:\n  upatch: ", output.to_bytes(), b"\n"].concat(),
            );
        }
        return c_int::from(ret.is_err());
    }

    let mut temp = None;
    let artifact;
    let mut emitted = None;
    // The source anchors relative decoder paths; for an object they
    // resolve from the current directory.
    let (bpf_o, src): (&CStr, Option<&CStr>) = if has_suffix(input, c".bpf.c") {
        let Some(vmlinux_h) = compile::locate_vmlinux(o.vmlinux) else {
            let named = o.vmlinux.map_or(&b"(none)"[..], CStr::to_bytes);
            error(
                &[
                    b"vmlinux.h not found (tried ",
                    named,
                    b", ./vmlinux.h, ./vendor/linux/vmlinux.h, ",
                    compile::VMLINUX_PATH.as_bytes(),
                    b")",
                ]
                .concat(),
            );
            return 1;
        };
        let compiled = if o.emit_artifacts {
            artifact = match derive_artifact_o(output) {
                Ok(p) => p,
                Err(err) => {
                    error(
                        &[
                            b"cannot derive .bpf.o path from ",
                            output.to_bytes(),
                            b": ",
                            strerr(-err),
                        ]
                        .concat(),
                    );
                    return 1;
                }
            };
            match compile::compile(input, &artifact, vmlinux_h, o.extra_cflags, None) {
                Ok(()) => {
                    emitted = Some(&*artifact);
                    Ok(&*artifact)
                }
                Err(err) => Err(err),
            }
        } else {
            match compile_to_temp(input, vmlinux_h, o.extra_cflags) {
                Ok(t) => Ok(&*temp.insert(t).0),
                Err(err) => Err(err),
            }
        };
        match compiled {
            Ok(obj) => (obj, Some(input)),
            Err(err) => {
                error(
                    format!(
                        "compile {}: {err}",
                        String::from_utf8_lossy(input.to_bytes())
                    )
                    .as_bytes(),
                );
                return 1;
            }
        }
    } else if has_suffix(input, c".o") {
        (input, None)
    } else {
        error(b"input must be .bpf.c, .bpf.o or .jar");
        return 2;
    };
    let ret = package::load_object(bpf_o, src, output, name, pkey, cert);
    drop(temp);
    if ret.is_ok() && o.emit_artifacts {
        let obj: &[u8] = match emitted {
            Some(p) => p.to_bytes(),
            None => b"(none; input was a pre-compiled object, not recompiled)",
        };
        print(
            true,
            &[
                b"emitted:\n  upatch: ",
                output.to_bytes(),
                b"\n  bpf.o:  ",
                obj,
                b"\n",
            ]
            .concat(),
        );
    }
    c_int::from(ret.is_err())
}

/// `shirudo-build` on `args`, its command line whole.
fn run(args: &[&CStr]) -> c_int {
    harden_stdio();
    // SAFETY: opens the log once, before anything logs.
    crate::log::init();
    if harden_self() != 0 {
        return 1;
    }
    let word = |i: usize| args.get(i).map(|w| w.to_bytes());
    match word(1) {
        Some(b"image") => return image::run(&args[1..]),
        Some(b"upatch") => return package::upatch_cli(&args[1..]),
        Some(b"bpm") => return bpm::run(&args[1..]),
        Some(b"skeleton") => return skeleton::run(&args[1..]),
        Some(b"keys") if word(2) == Some(b"vouch") => return vouch::run(&args[2..]),
        _ => {}
    }

    let mut p = OptParser::new(c"build", &BUILD_OPTS, Some(&BUILD_HELP), args, 1);
    let mut o = Opts::default();
    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            BUILD_OUTPUT => o.output = value,
            BUILD_NAME => o.name = value,
            BUILD_KEYS_DIR => o.keys_dir = value,
            BUILD_KEY => o.pkey = value,
            BUILD_CERT => o.cert = value,
            BUILD_VMLINUX => o.vmlinux = value,
            BUILD_EXTRA_CFLAGS => o.extra_cflags = value,
            BUILD_UNLOAD => o.unload = value,
            BUILD_PAYLOAD_SHA256 => o.payload_sha256 = value,
            BUILD_JAVA => o.java = true,
            BUILD_EMIT_ARTIFACTS => o.emit_artifacts = true,
            OPT_ARG => {
                if o.input.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                o.input = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    if o.unload.is_some() && o.input.is_some() {
        p.usage(b"--unload takes no input");
        return EXIT_USAGE;
    }
    if o.unload.is_none() && o.input.is_none() {
        p.usage(b"takes <input.bpf.c|.bpf.o|.jar> or --unload <upatch-name>");
        return EXIT_USAGE;
    }
    if o.java && (o.unload.is_none() || o.payload_sha256.is_none()) {
        p.usage(b"--java takes --unload and --payload-sha256");
        return EXIT_USAGE;
    }

    let mut keys = KeyFiles::default();
    if let Some(p) = o.pkey {
        keys.set_pkey(p);
    }
    if let Some(c) = o.cert {
        keys.set_cert(c);
    }
    if let Err((dir, err)) = keys.resolve(o.keys_dir) {
        error(&[b"invalid keys dir ", &dir[..], b": ", strerr(-err)].concat());
        return 2;
    }
    if check_keys(&keys.pkey, &keys.cert) != 0 {
        return 1;
    }
    match (o.unload, o.input) {
        (Some(name), _) => unload(&p, &o, name, &keys.pkey, &keys.cert),
        (None, Some(input)) => load(&o, input, &keys.pkey, &keys.cert),
        (None, None) => EXIT_USAGE,
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    /// `shirudo-build`, from its main(): the command line, whole.
    ///
    /// # Safety
    ///
    /// `argv` holds `argc` C strings, as main() receives them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shirudo_build_main(argc: c_int, argv: *mut *mut c_char) -> c_int {
        // SAFETY: main()'s arguments, which live as long as the process.
        super::run(&unsafe { crate::ffi::args(argc, argv.cast_const().cast()) })
    }
}
