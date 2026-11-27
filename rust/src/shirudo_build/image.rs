// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build image`: `build` hands an ext4 image to
//! shirudo-gen-verity, which builds its verity tree and has this tool
//! sign the root; `sign-root` signs a root hash; `verify` checks an
//! image offline, its signature against a certificate and its tree with
//! veritysetup, on the very files it authenticated.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use super::{KeyFiles, error, hex, print, strerr};
use crate::errno::{EBADF, EINTR, EINVAL, EIO, EKEYREJECTED, ENOENT};
use crate::sys::libc::{F_SETFD, O_NOFOLLOW, O_NONBLOCK, fcntl, pread};
use crate::util::config_image::{self, ConfigImageOpen};
use crate::util::crypto_openssl::{cert_key_algorithm, cms_signed_by, verify_detached};
use crate::util::help::{Help, HelpSection, is_help, print_help};
use crate::util::io;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};

const SIG_MAX: usize = config_image::SIG_MAX as usize;
const X_OK: c_int = 1;

/// `image build`: runs shirudo-gen-verity, beside this tool when
/// installed or in the tree, with this tool as its signer; returns only
/// when it cannot.
fn build(args: &[&CStr]) -> c_int {
    let Ok(exe) = std::fs::read_link("/proc/self/exe") else {
        return 1;
    };
    let exe = exe.as_os_str().as_bytes().to_vec();
    if exe.len() >= super::PATH_MAX - 1 {
        return 1;
    }
    let Some(slash) = exe.iter().rposition(|&c| c == b'/') else {
        return 1;
    };
    let dir = &exe[..slash];
    let installed = [dir, b"/../gen-image/shirudo-gen-verity"].concat();
    let in_tree = [dir, b"/gen-image/shirudo-gen-verity"].concat();
    let fits = |p: &[u8]| p.len() < super::PATH_MAX;
    if !fits(&installed) {
        return 1;
    }
    let installed_c = std::ffi::CString::new(installed.clone()).unwrap_or_default();
    let script = if super::check_access(&installed_c, X_OK).is_ok() {
        installed
    } else if fits(&in_tree) {
        in_tree
    } else {
        return 1;
    };
    let err = Command::new(OsStr::from_bytes(&script))
        .arg("--builder")
        .arg(OsStr::from_bytes(&exe))
        .args(args[2..].iter().map(|a| OsStr::from_bytes(a.to_bytes())))
        .exec();
    error(
        &[
            b"image build: cannot run ",
            &script[..],
            b": ",
            strerr(-io::errno_of(&err)),
        ]
        .concat(),
    );
    1
}

/// Runs veritysetup on the very data and hash descriptors the image
/// reader checked. Only the child clears close-on-exec.
fn verify_verity(img: &ConfigImageOpen, root: &[u8]) -> Result<(), c_int> {
    let (data_fd, hash_fd) = (img.data.as_raw_fd(), img.hash.as_raw_fd());
    let (data, hash) = (
        format!("/proc/self/fd/{data_fd}"),
        format!("/proc/self/fd/{hash_fd}"),
    );
    let mut cmd = Command::new("veritysetup");

    cmd.args(["verify", "--hash-offset=0", &data, &hash])
        .arg(OsStr::from_bytes(root));
    let inherit_image = move || {
        for fd in [data_fd, hash_fd] {
            // SAFETY: fcntl is async-signal-safe and the image keeps fd open.
            if unsafe { fcntl(fd, F_SETFD, 0) } != 0 {
                return Err(std::io::Error::from_raw_os_error(EIO));
            }
        }
        Ok(())
    };
    // SAFETY: the child callback only calls async-signal-safe operations.
    unsafe { cmd.pre_exec(inherit_image) };
    match cmd.status() {
        Err(e) => {
            error(
                &[
                    b"veritysetup: ",
                    strerr(-io::errno_of(&e)),
                    b"; install the operator veritysetup tool",
                ]
                .concat(),
            );
            Err(-ENOENT)
        }
        Ok(s) => match (s.code(), s.signal()) {
            (Some(0), _) => Ok(()),
            (Some(127), _) => Err(-ENOENT),
            _ => Err(-EIO),
        },
    }
}

fn verify_root_signature(
    root: &[u8; 64],
    signature: &[u8],
    cert: &super::Certificate,
) -> Result<(), c_int> {
    let cert = cert.as_cert();
    let mut alg = [0u8; 32];
    // SAFETY: cert is live and alg has the stated writable capacity.
    let ret = unsafe { cert_key_algorithm(cert, alg.as_mut_ptr().cast(), alg.len()) };
    if ret != 0 {
        return Err(ret);
    }
    if crate::text::cstr(&alg) != b"ML-DSA-87" {
        return Err(-EKEYREJECTED);
    }
    if cms_signed_by(signature, cert) != 1 {
        return Err(-EKEYREJECTED);
    }
    let ret = verify_detached(root, signature, cert);
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// The signature the image holds, at most SIG_MAX bytes.
fn read_signature(img: &ConfigImageOpen) -> Result<Vec<u8>, c_int> {
    let Some(file) = &img.signature else {
        return Err(-EBADF);
    };
    let mut bytes = vec![0u8; SIG_MAX + 1];
    let mut size = 0;
    while size < bytes.len() {
        let offset = i64::try_from(size).map_err(|_| -EIO)?;
        let rest = &mut bytes[size..];
        // SAFETY: the image owns the fd and rest is writable for its length.
        let n = unsafe {
            pread(
                file.as_raw_fd(),
                rest.as_mut_ptr().cast(),
                rest.len(),
                offset,
            )
        };
        if n < 0 {
            let err = super::last_err();
            if err == -EINTR {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        size += usize::try_from(n).map_err(|_| -EIO)?;
    }
    if size == 0 || size > SIG_MAX {
        return Err(-EINVAL);
    }
    bytes.truncate(size);
    Ok(bytes)
}

fn verify(prefix: &CStr, cert: &CStr) -> Result<(), c_int> {
    let img = ConfigImageOpen::open(prefix, None)?;
    let signature = read_signature(&img)?;
    let root: [u8; 64] = hex(&img.image.root_hash).try_into().map_err(|_| -EINVAL)?;
    verify_root_signature(&root, &signature, &super::Certificate::open(cert)?)?;
    verify_verity(&img, &root)?;
    print(true, &[&root[..], b"\n"].concat());
    Ok(())
}

/// The file must itself contain exactly 64 lowercase hex digits.
fn read_root(input: &CStr) -> Result<[u8; 64], c_int> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(super::path(input.to_bytes()))
        .map_err(|e| io::errno_of(&e))?;
    let metadata = file.metadata().map_err(|e| io::errno_of(&e))?;
    let mut root = [0u8; 64];
    if !metadata.is_file() || metadata.size() != 64 {
        return Err(-EINVAL);
    }
    file.read_exact(&mut root).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            -EIO
        } else {
            io::errno_of(&e)
        }
    })?;
    if root.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(root)
    } else {
        Err(-EINVAL)
    }
}

/// Signs the root hash into a new file, removing an incomplete write.
fn sign_root(input: &CStr, output: &CStr, keys: &KeyFiles) -> Result<(), c_int> {
    if super::check_keys(&keys.pkey, &keys.cert) != 0 {
        return Err(-EKEYREJECTED);
    }
    let root = read_root(input)?;
    let (signature, _) = super::sign::cms_sign(&root, &[], SIG_MAX, &keys.pkey, &keys.cert)?;
    verify_root_signature(&root, &signature, &super::Certificate::open(&keys.cert)?)?;
    let out = super::path(output.to_bytes());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(out)
        .map_err(|e| io::errno_of(&e))?;
    let written = file.write_all(&signature).and_then(|()| file.sync_all());
    drop(file);
    if written.is_err() {
        let _ = std::fs::remove_file(out);
    }
    written.map_err(|e| io::errno_of(&e))
}

const IMAGE_VERIFY_CERT: c_int = 0;

static IMAGE_VERIFY_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--cert",
    0,
    0,
    Some(c"<cert.der>"),
    c"the certificate the image's root hash is signed for",
)];

const IMAGE_SIGN_OUTPUT: c_int = 0;
const IMAGE_SIGN_KEYS_DIR: c_int = 1;
const IMAGE_SIGN_KEY: c_int = 2;
const IMAGE_SIGN_CERT: c_int = 3;

static IMAGE_SIGN_OPTS: [OptSpec; 4] = [
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<signature>"),
        c"where to write the signature",
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
        Some(c"<private.pem>"),
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

static IMAGE_SECTIONS: [HelpSection; 1] =
    [HelpSection::options(c"verify options:", &IMAGE_VERIFY_OPTS)];

static IMAGE_HELP: Help = Help::new(
    c"shirudo image build <filesystem.img> -o <prefix> [--kind config|runtime]\n                     \
      [--keys-dir <dir>] [--key <private.pem>] [--cert <cert.der>]\n                     \
      [--salt <64-hex>]\n       \
      shirudo image verify <prefix> --cert <cert.der>",
    Some(
        c"build writes <prefix>.img, .verity, .roothash and .p7s from a 4096-byte\n\
          aligned ext4 file system image and refuses files that exist. Build and\n\
          offline verification require veritysetup.",
    ),
    &IMAGE_SECTIONS,
    None,
);

fn verify_cmd(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(
        c"image verify",
        &IMAGE_VERIFY_OPTS,
        Some(&IMAGE_HELP),
        args,
        2,
    );
    let (mut prefix, mut cert) = (None, None);

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            IMAGE_VERIFY_CERT => cert = value,
            OPT_ARG => {
                if prefix.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                prefix = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(prefix), Some(cert)) = (prefix, cert) else {
        p.usage(b"takes <prefix> and --cert <cert.der>");
        return EXIT_USAGE;
    };
    match verify(prefix, cert) {
        Ok(()) => 0,
        Err(err) => {
            error(&[b"image verify: ", strerr(-err)].concat());
            1
        }
    }
}

/// What shirudo-gen-verity calls back with for the root hash it made.
fn sign_root_cmd(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"image sign-root", &IMAGE_SIGN_OPTS, None, args, 2);
    let mut keys = KeyFiles::default();
    let (mut input, mut signature, mut keys_dir) = (None, None, None);

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            IMAGE_SIGN_OUTPUT => signature = value,
            IMAGE_SIGN_KEYS_DIR => keys_dir = value,
            IMAGE_SIGN_KEY => keys.set_pkey(value.unwrap_or_default()),
            IMAGE_SIGN_CERT => keys.set_cert(value.unwrap_or_default()),
            OPT_ARG => {
                if input.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                input = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(input), Some(signature)) = (input, signature) else {
        p.usage(b"takes <root-hash-file> and -o <signature>");
        return EXIT_USAGE;
    };
    if keys.resolve_both(keys_dir).is_err() {
        return EXIT_USAGE;
    }
    match sign_root(input, signature, &keys) {
        Ok(()) => 0,
        Err(err) => {
            error(&[b"image sign-root: ", strerr(-err)].concat());
            1
        }
    }
}

/// `shirudo-build image`, from `image` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let word = args.get(1).map(|a| a.to_bytes());

    if word == Some(b"build") {
        return build(args);
    }
    if args.len() < 2 || is_help(word) {
        print_help(&IMAGE_HELP);
        return if args.len() < 2 { EXIT_USAGE } else { 0 };
    }
    match word.unwrap_or_default() {
        b"verify" => verify_cmd(args),
        b"sign-root" => sign_root_cmd(args),
        other => {
            error(&[b"image: '", other, b"' is not a subcommand"].concat());
            EXIT_USAGE
        }
    }
}
