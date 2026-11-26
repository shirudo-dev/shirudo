// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm config update`: a published package rebuilt at a later version
//! with only its .rodata changed, by the converters' update commands and
//! the operator's new inputs. The load artifacts are the base package's,
//! verified against the operator's certificate, re-signed with the new
//! .rodata, and their unload directives bound anew.

use core::ffi::{CStr, c_int};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use super::build::{self, Override, cstring};
use super::download::{Download, digest_ok};
use super::{archive, error, path};
use crate::errno::{EACCES, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOTDIR};
use crate::shirudo_build::{KeyFiles, check_keys, package};
use crate::util::bpm_package::{PackageInfo, load_info, read_member_in, semver_compare};
use crate::util::help::{Help, HelpSection};
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_REPEAT, OptParser, OptSpec,
};
use crate::util::upatch;

const PATH_MAX: usize = 4096;

/// A package's identity, its certificate freed when it goes.
pub(super) struct Info(pub(super) PackageInfo);

impl Info {
    pub(super) fn load(package: &CStr) -> Result<Self, c_int> {
        let mut info = Info(PackageInfo::new());
        match load_info(package, &mut info.0) {
            0 => Ok(info),
            err => Err(err),
        }
    }

    pub(super) fn cert(&self) -> &[u8] {
        self.0.cert.as_ref().map_or(&[], |cert| cert.bytes())
    }
}

/// Member `member` of the package, at most `max` bytes.
pub(super) fn read_member(package: &CStr, member: &[u8], max: usize) -> Result<Vec<u8>, c_int> {
    let m = cstring(member);
    Ok(read_member_in(package, m.as_bytes(), None, None, max)?
        .bytes()
        .to_vec())
}

/// Member `member` of the package, written to `output`, which must not
/// exist, with the directories above it.
fn copy_member(package: &CStr, member: &[u8], output: &[u8]) -> Result<(), c_int> {
    let body = read_member(package, member, archive::MAX_FILE)?;
    if output.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    if let Some(slash) = output.iter().rposition(|&c| c == b'/') {
        let parent = &output[..slash];
        let start = usize::from(parent.first() == Some(&b'/'));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let ends = parent[start..]
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c == b'/')
            .map(|(i, _)| start + i)
            .chain([parent.len()]);
        for end in ends {
            let dir = &parent[..end];
            if let Err(e) = builder.create(path(dir))
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(-e.raw_os_error().unwrap_or(EIO));
            }
            match std::fs::symlink_metadata(path(dir)) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Err(-ENOTDIR),
                Err(e) => return Err(-e.raw_os_error().unwrap_or(EIO)),
            }
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path(output))
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    file.write_all(&body)
        .and_then(|()| file.sync_all())
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))
}

/// `bpm config update`, from `update` on.
const CONFIG_UPDATE_FILE: c_int = 0;
const CONFIG_UPDATE_BASE_PACKAGE: c_int = 1;
const CONFIG_UPDATE_BASE_DIGEST: c_int = 2;
const CONFIG_UPDATE_VERSION: c_int = 3;
const CONFIG_UPDATE_KEYS_DIR: c_int = 4;
const CONFIG_UPDATE_RODATA_INPUT: c_int = 5;

static CONFIG_UPDATE_OPTS: [OptSpec; 6] = [
    OptSpec::new(
        c"--file",
        0,
        0,
        Some(c"<name>.bee"),
        c"the Beefile, instead of the base package's",
    ),
    OptSpec::new(
        c"--base-package",
        0,
        0,
        Some(c"<package.bee|oci://host/repo:tag>"),
        c"the package the update builds on",
    ),
    OptSpec::new(
        c"--base-digest",
        0,
        0,
        Some(c"sha256:<manifest>"),
        c"the manifest digest of an oci:// base package",
    ),
    OptSpec::new(
        c"--version",
        0,
        0,
        Some(c"<version>"),
        c"the SemVer 2.0.0 version of the update",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--rodata-input",
        0,
        OPT_REPEAT,
        Some(c"<name>=<path>"),
        c"a file for a .rodata input (repeatable)",
    ),
];

static CONFIG_UPDATE_SECTIONS: [HelpSection; 1] =
    [HelpSection::options(c"options:", &CONFIG_UPDATE_OPTS)];

static CONFIG_UPDATE_HELP: Help = Help::new(
    c"shirudo bpm config update --base-package <package.bee|oci://host/repo:tag>\n                                 \
      --version <version> [options]",
    Some(
        c"Build a config update package on a base package. Without --file, the\n\
          Beefile and the updater inputs come from --base-package and are trusted\n\
          as operator-side code. An oci:// base package needs --base-digest, the\n\
          manifest digest bpm push printed for it.",
    ),
    &CONFIG_UPDATE_SECTIONS,
    None,
);

/// `bpm config update`, from `update` on: 0, EXIT_USAGE, or -errno.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(
        c"bpm config update",
        &CONFIG_UPDATE_OPTS,
        Some(&CONFIG_UPDATE_HELP),
        args,
        1,
    );
    let (mut file, mut base, mut base_digest) = (None, None, None);
    let (mut version, mut keys_arg) = (None, None);
    let mut overrides = Vec::new();

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            CONFIG_UPDATE_FILE => file = value,
            CONFIG_UPDATE_BASE_PACKAGE => base = value,
            CONFIG_UPDATE_BASE_DIGEST => base_digest = value,
            CONFIG_UPDATE_VERSION => version = value,
            CONFIG_UPDATE_KEYS_DIR => keys_arg = value,
            CONFIG_UPDATE_RODATA_INPUT => {
                match build::parse_override(value.map_or(&b""[..], CStr::to_bytes), &mut overrides)
                {
                    Ok(()) => {}
                    Err(None) => {
                        p.usage(b"--rodata-input takes <name>=<path>");
                        return EXIT_USAGE;
                    }
                    Err(Some(err)) => return err,
                }
            }
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(base), Some(version)) = (base, version) else {
        p.usage(b"takes --base-package and --version");
        return EXIT_USAGE;
    };
    if !build::version_ok(version) {
        error(format!("bpm config update: --version {} is not a SemVer 2.0.0 version such as 1.2.0, 1.2.0-rc.1 or 1.2.0+build.5", String::from_utf8_lossy(version.to_bytes())).as_bytes());
        return -EINVAL;
    }
    // A tag is the registry's to point at any package the key ever
    // signed, an older one included, whose loaders this would sign as a
    // new version: an oci:// base package is the manifest the operator
    // names.
    if base.to_bytes().starts_with(b"oci://") != base_digest.is_some() {
        error(b"bpm config update: --base-digest names the manifest of an oci:// base package, and one needs it");
        return -EINVAL;
    }
    if let Some(d) = base_digest.filter(|d| !digest_ok(d.to_bytes())) {
        error(
            format!(
                "bpm config update: --base-digest {} is not sha256:<64 lowercase hex>",
                String::from_utf8_lossy(d.to_bytes())
            )
            .as_bytes(),
        );
        return -EINVAL;
    }
    let download_guard;
    let local_path;
    let package = match base_digest {
        Some(want) => match Download::fetch(
            b"bpm config update",
            base.to_bytes(),
            want.to_bytes(),
            c"/tmp/shirudo-bpm-base-XXXXXX",
        ) {
            Ok(p) => {
                download_guard = p;
                download_guard.path().to_bytes()
            }
            Err(err) => return err,
        },
        None => match std::fs::canonicalize(path(base.to_bytes())) {
            Ok(p) => {
                local_path = p;
                local_path.as_os_str().as_bytes()
            }
            Err(e) => {
                let err = e.raw_os_error().unwrap_or(EIO);
                p.usage(
                    &[
                        b"--base-package ",
                        base.to_bytes(),
                        b": ",
                        super::strerr(err),
                    ]
                    .concat(),
                );
                return EXIT_USAGE;
            }
        },
    };
    update(&cstring(package), file, version, keys_arg, &overrides)
        .err()
        .unwrap_or(0)
}

fn update(
    package: &CStr,
    file: Option<&CStr>,
    version: &CStr,
    keys_arg: Option<&CStr>,
    overrides: &[Override],
) -> Result<(), c_int> {
    let info = Info::load(package)?;
    if semver_compare(version.to_bytes(), crate::text::cstr(&info.0.version)) <= 0 {
        return Err(-EINVAL);
    }
    let out_dir = std::env::current_dir().map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    let out_dir = out_dir.as_os_str().as_bytes();
    let Some(keys_abs) =
        super::resolve_keys_dir(keys_arg).and_then(|d| std::fs::canonicalize(path(&d)).ok())
    else {
        return Err(-ENOENT);
    };
    let keys = KeyFiles::under(keys_abs.as_os_str().as_bytes())?;
    if check_keys(&keys.pkey, &keys.cert) != 0 {
        return Err(-EACCES);
    }
    let mut spec = super::beefile::Spec::default();
    let ret = staged(
        &mut spec, package, &info, file, version, &keys, overrides, out_dir,
    );
    if !spec.stage.is_empty() {
        let back = std::env::set_current_dir(path(out_dir));
        drop(spec);
        return ret.and(back.map_err(|e| -e.raw_os_error().unwrap_or(EIO)));
    }
    ret
}

#[allow(clippy::too_many_arguments)]
fn staged(
    spec: &mut super::beefile::Spec,
    package: &CStr,
    info: &Info,
    file: Option<&CStr>,
    version: &CStr,
    keys: &KeyFiles,
    overrides: &[Override],
    out_dir: &[u8],
) -> Result<(), c_int> {
    let from_package = file.is_none();
    let build_file = if from_package {
        build::stage_open(spec)?;
        let source_dir = [&spec.stage[..], b"/source"].concat();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path(&source_dir))
            .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
        let bf = [&source_dir[..], b"/Beefile"].concat();
        match copy_member(package, b"Beefile", &bf) {
            Err(err) if err == -ENOENT => {
                error(format!("bpm config update: base package {} has no Beefile; rebuild it with a Beefile or pass --file <name>.bee", String::from_utf8_lossy(package.to_bytes())).as_bytes());
                return Err(-EINVAL);
            }
            other => other?,
        }
        bf
    } else {
        file.map(|f| f.to_bytes().to_vec()).unwrap_or_default()
    };
    let mut parsed = build::load_spec(&build_file, false, "")?;
    parsed.stage = core::mem::take(&mut spec.stage);
    *spec = parsed;
    if from_package {
        for f in &spec.files {
            if !super::beefile::target_ok(&f.source) || !super::beefile::target_ok(&f.target) {
                return Err(-EINVAL);
            }
            let out = [&spec.scope[..], b"/", &f.source].concat();
            copy_member(package, &f.target, &out)?;
        }
        match copy_member(
            package,
            b"README.md",
            &[&spec.scope[..], b"/README.md"].concat(),
        ) {
            Err(err) if err == -ENOENT => {}
            other => other?,
        }
    }
    build::validate(spec, from_package)?;
    build::overrides_known(spec, overrides)?;
    if spec.name != crate::text::cstr(&info.0.name)
        || spec.upatches.iter().all(|u| u.rodata.is_empty())
    {
        return Err(-EINVAL);
    }
    let fp = build::fingerprint(&keys.cert)?;
    if fp != crate::text::cstr(&info.0.signer) {
        return Err(-EKEYREJECTED);
    }
    std::env::set_current_dir(path(&spec.scope)).map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    if spec.stage.is_empty() {
        build::stage_open(spec)?;
    }
    for i in 0..spec.upatches.len() {
        let stage = String::from_utf8_lossy(&spec.stage).into_owned();
        let (load, unload) = (
            format!("{stage}/update-{i}.upatch").into_bytes(),
            format!("{stage}/update-{i}.unload.upatch").into_bytes(),
        );
        if load.len() >= PATH_MAX || unload.len() >= PATH_MAX {
            return Err(-ENAMETOOLONG);
        }
        copy_member(package, &spec.upatches[i].load_target, &load)?;
        package::verify_package(&cstring(&load), &keys.cert)?;
        let expected = build::upatch_name(&spec.upatches[i].source)?;
        name_matches(&load, &expected)?;
        build::rodata_apply(spec, i, &load, keys, overrides, true)?;
        build::record_payload(spec, i, &load, true)?;
        let u = &mut spec.upatches[i];
        u.load_path = load;
        u.unload_path = unload.clone();
        let digest = build::digest_of(&u.payload_sha256);
        if u.ty == b"java" {
            package::java_unload(
                &cstring(&u.name),
                &digest,
                &cstring(&unload),
                (&keys.pkey, &keys.cert),
            )?;
        } else {
            package::unload(
                &cstring(&u.name),
                &digest,
                &cstring(&unload),
                (&keys.pkey, &keys.cert),
            )?;
        }
    }
    archive::write(
        "bpm config update",
        spec,
        version.to_bytes(),
        keys.cert.to_bytes(),
        &fp,
        out_dir,
    )
}

/// The load artifact at `load` is a load directive named `expected`.
fn name_matches(load: &[u8], expected: &[u8]) -> Result<(), c_int> {
    let p = cstring(load);
    let u = upatch::Upatch::open(&p)?;
    let name = &u.hdr.name;
    let n = expected.len().min(name.len());
    let same =
        name[..n] == expected[..n] && (expected.len() >= name.len() || name[expected.len()] == 0);
    let bad = u.is_unload() || !same;
    if bad { Err(-EINVAL) } else { Ok(()) }
}
