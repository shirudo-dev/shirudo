// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-config-update: the config update journal driven step by step
//! against a simulated TPM, which a file in the journal's directory keeps
//! across runs, or the TPM itself with SHIRUDO_TEST_CONFIG_TPM; the
//! journal's state, staged update and events printed after each step.
//!
//!   test-config-update <dir> describe|boot|update|stage|cancel-stage|staged|complete|check|inspect|reset|restart|drift|lock [<id A-Z> [<pcr>]]
//!
//! The environment makes a step fail or crash where the protocol must
//! survive it: SHIRUDO_TEST_CONFIG_{READ_FAIL,EXTEND,PREPARE_FAIL,
//! ACTIVATE_FAIL,SEAL_FAIL,STAGE_CRASH,CRASH,FAIL,BOOT_PENDING,
//! LOCK_WAIT_MS}.

use core::cell::RefCell;
use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use super::{helper_main, out};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, EPERM, ETIMEDOUT, EUCLEAN};
use crate::util::chain::fold;
use crate::util::config_measure::nvpcr;
use crate::util::config_measure::{EVENT_BOOT, event};
use crate::util::config_update::{
    BootIdentity, Checkpoint, ConfigUpdate, ConfigUpdateOps, ConfigUpdateTarget,
};
use crate::util::hex::encode;
use crate::util::tpm::Tpm;
use crate::util::tpm_wire::policy_nv_written;
use libc::ECANCELED;

helper_main!(shirudo_helper_test_config_update, run);

/// The simulated TPM's state, kept whole in `<dir>/simulator`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Simulated {
    value: [u8; 32],
    active: [u8; 32],
    reset_count: u32,
    restart_count: u32,
    extends: u32,
    prepares: u32,
    activations: u32,
    partial: u32,
}

impl Simulated {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: a plain structure of arrays and u32s without padding,
        // whose bytes are all values.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast(), size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as as_bytes(); any bytes are a value.
        unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast(), size_of::<Self>()) }
    }
}

const _: () = assert!(size_of::<Simulated>() == 88);

/// The journal's operations: the simulated TPM or the TPM itself, and
/// the configs `/verified/config-<id>` whose root is 32 bytes of `<id>`.
struct Context<'a> {
    sim: Simulated,
    tpm: Option<Tpm>,
    directory: &'a CStr,
    staging: bool,
}

fn env(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name)
}

/// As strtoul() of base 10, which the C helper called: the leading
/// digits, 0 for none.
fn number(text: &[u8]) -> u64 {
    let n = text.iter().take_while(|c| c.is_ascii_digit()).count();
    std::str::from_utf8(&text[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0)
}

fn errno(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// What a step returned, as the helper prints it.
fn rc<T>(result: &Result<T, c_int>) -> c_int {
    match result {
        Ok(_) => 0,
        Err(err) => *err,
    }
}

impl Context<'_> {
    fn path(&self, name: &str) -> PathBuf {
        std::path::Path::new(OsStr::from_bytes(self.directory.to_bytes())).join(name)
    }

    /// The state written to a new file, synced, moved over the old and
    /// the directory synced.
    fn save(&self) -> Result<(), c_int> {
        let (path, temporary) = (self.path("simulator"), self.path("simulator.tmp"));
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            f.write_all(self.sim.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&temporary, &path)?;
            std::fs::File::open(OsStr::from_bytes(self.directory.to_bytes()))?.sync_all()
        };
        write().map_err(|e| errno(&e))
    }

    /// The state from the file, or a fresh TPM's when there is none.
    fn load(&mut self) -> Result<(), c_int> {
        let mut f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path("simulator"))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.sim.reset_count = 1;
                return Ok(());
            }
            Err(e) => return Err(errno(&e)),
        };
        match f.read(self.sim.as_bytes_mut()) {
            Ok(n) if n == size_of::<Simulated>() => Ok(()),
            _ => Err(-EIO),
        }
    }

    fn pcr_read(&self, pcr: u32) -> Result<[u8; 32], c_int> {
        if env("SHIRUDO_TEST_CONFIG_READ_FAIL").is_some() {
            return Err(-EIO);
        }
        match &self.tpm {
            Some(tpm) if nvpcr(pcr) => tpm.nv_read(pcr),
            Some(tpm) => tpm.pcr_read(pcr),
            None => Ok(self.sim.value),
        }
    }
}

impl ConfigUpdateOps for RefCell<Context<'_>> {
    fn boot_identity(&self) -> Result<BootIdentity, c_int> {
        let c = self.borrow();
        let (reset, restart) = match &c.tpm {
            Some(tpm) => tpm.boot_identity()?,
            None => (c.sim.reset_count, c.sim.restart_count),
        };

        Ok(BootIdentity { reset, restart })
    }

    fn pcr_read(&self, pcr: u32) -> Result<[u8; 32], c_int> {
        self.borrow().pcr_read(pcr)
    }

    fn pcr_extend(&self, pcr: u32, event: &[u8; 32]) -> Result<(), c_int> {
        let mode = env("SHIRUDO_TEST_CONFIG_EXTEND");
        let mode = mode.as_deref().map(OsStr::as_bytes);
        let mut c = self.borrow_mut();
        c.sim.extends += 1;
        c.save()?;
        if mode == Some(b"before") {
            return Err(-EIO);
        }
        let mut wrong = [0u8; 32];
        wrong[0] = 1;
        let event = if mode == Some(b"drift") {
            &wrong
        } else {
            event
        };
        match &c.tpm {
            Some(tpm) if nvpcr(pcr) => {
                let mut first = [0u8; 32];
                let ret = policy_nv_written(&[0u8; 32], false, &mut first);
                if ret != 0 {
                    return Err(ret);
                }
                tpm.nvpcr_extend(pcr, &first, event)?;
            }
            Some(tpm) => tpm.pcr_extend(pcr, event)?,
            None => {
                let ret = fold(&mut c.sim.value, event);
                if ret != 0 {
                    return Err(ret);
                }
            }
        }
        c.save()?;
        if mode == Some(b"ambiguous") {
            return Err(-ETIMEDOUT);
        }
        Ok(())
    }

    fn prepare(&self, target: &ConfigUpdateTarget) -> Result<(), c_int> {
        let mut c = self.borrow_mut();
        c.sim.prepares += 1;
        c.save()?;
        if env("SHIRUDO_TEST_CONFIG_PREPARE_FAIL").is_some() {
            return Err(-EKEYREJECTED);
        }
        match prefix(target).strip_prefix(b"/verified/config-") {
            Some(&[id]) if target.root_hash.iter().all(|&b| b == id) => Ok(()),
            _ => Err(-EKEYREJECTED),
        }
    }

    fn activate(
        &self,
        journal: &ConfigUpdate<'_>,
        target: &ConfigUpdateTarget,
    ) -> Result<(), c_int> {
        let mut c = self.borrow_mut();
        let record = journal.read_state()?;
        c.pcr_read(record.pcr)?;
        if !record.pending || target.root_hash != record.target.root_hash {
            return Err(-EUCLEAN);
        }
        c.sim.activations += 1;
        c.sim.partial = prefix(target).last().copied().map_or(0, u32::from);
        c.save()?;
        if env("SHIRUDO_TEST_CONFIG_ACTIVATE_FAIL").is_some() {
            return Err(-EIO);
        }
        c.sim.active = target.root_hash;
        c.sim.partial = 0;
        c.save()
    }

    fn seal(&self, _: BorrowedFd<'_>) -> Result<(), c_int> {
        if self.borrow().staging && env("SHIRUDO_TEST_CONFIG_STAGE_CRASH").is_some() {
            // SAFETY: the process gone mid-protocol, as a crash leaves it.
            unsafe { libc::_exit(99) };
        }
        if env("SHIRUDO_TEST_CONFIG_SEAL_FAIL").is_some() {
            Err(-EPERM)
        } else {
            Ok(())
        }
    }

    fn checkpoint(&self, point: Checkpoint) -> Result<(), c_int> {
        let at = |name| env(name).is_some_and(|v| number(v.as_bytes()) == point as u64);
        if at("SHIRUDO_TEST_CONFIG_CRASH") {
            // SAFETY: the process gone at the checkpoint, as a crash leaves it.
            unsafe { libc::_exit(99) };
        }
        if at("SHIRUDO_TEST_CONFIG_FAIL") {
            Err(-ECANCELED)
        } else {
            Ok(())
        }
    }
}

fn prefix(t: &ConfigUpdateTarget) -> &[u8] {
    crate::text::cstr(&t.prefix)
}

fn target(id: u8) -> ConfigUpdateTarget {
    let mut t = ConfigUpdateTarget::zeroed();
    let p = format!("/verified/config-{}", id as char);
    t.prefix[..p.len()].copy_from_slice(p.as_bytes());
    t.root_hash = [id; 32];
    t
}

fn hex(b: &[u8]) -> String {
    String::from_utf8_lossy(&encode(b)).into_owned()
}

fn inspect(c: &Context<'_>, journal: &ConfigUpdate<'_>) {
    out(&format!(
        "extends={}\nprepares={}\nactivations={}\npartial={}\n",
        c.sim.extends, c.sim.prepares, c.sim.activations, c.sim.partial
    ));
    if let Ok(value) = c.pcr_read(15) {
        out(&format!("pcr_value={}\n", hex(&value)));
    }
    let state = journal.read_state();
    out(&format!("state_rc={}\n", rc(&state)));
    if let Ok(record) = state {
        out(&format!(
            "sequence={}\npending={}\nkind={}\npcr={}\nreset={}\nprefix={}\nrestart={}\ninitial_pcr={}\nroot_hash={}\n",
            record.sequence,
            u32::from(record.pending),
            record.kind,
            record.pcr,
            record.reset_count,
            String::from_utf8_lossy(prefix(&record.target)),
            record.restart_count,
            hex(&record.initial_pcr),
            hex(&record.target.root_hash)
        ));
    }
    let staged = journal.read_staged();
    out(&format!("stage_rc={}\n", rc(&staged)));
    if let Ok(record) = staged {
        out(&format!(
            "stage_prefix={}\nstage_sequence={}\n",
            String::from_utf8_lossy(prefix(&record.target)),
            record.sequence
        ));
    }
    let mut count = 0u32;
    let events = journal.events(|r| {
        out(&format!(
            "event={}:{}:{}:{}:{}\n",
            r.sequence,
            r.reset_count,
            r.pcr,
            r.kind,
            hex(&r.target.root_hash)
        ));
        count += 1;
        Ok(())
    });
    out(&format!("events_rc={}\nevents={count}\n", rc(&events)));
}

fn describe(t: &ConfigUpdateTarget) -> c_int {
    out(&format!("root_hash={}\n", hex(&t.root_hash)));
    match event(EVENT_BOOT, &t.root_hash) {
        Ok(e) => {
            out(&format!("boot_event={}\n", hex(&e)));
            0
        }
        Err(_) => 1,
    }
}

/// Whether the boot after the selection in force takes the staged
/// config: printed, and 0 or the error.
fn staged(c: &RefCell<Context<'_>>, journal: &ConfigUpdate<'_>) -> c_int {
    let reset = c.borrow().sim.reset_count;
    let eligible = journal
        .read_state()
        .and_then(|previous| journal.staged(&previous, reset));
    let ret = match eligible {
        Ok(Some(_)) => 1,
        Ok(None) => 0,
        Err(err) => err,
    };
    out(&format!("eligible={ret}\n"));
    if let Ok(Some(t)) = eligible {
        out(&format!(
            "candidate={}\n",
            String::from_utf8_lossy(prefix(&t))
        ));
        return 0;
    }
    ret
}

/// The step `how` on `journal`, whose operations are `c`.
fn step(
    c: &RefCell<Context<'_>>,
    journal: &mut ConfigUpdate<'_>,
    how: &[u8],
    dir: &CStr,
    t: &ConfigUpdateTarget,
    pcr: u32,
) -> c_int {
    let ret = match how {
        b"boot" => {
            let ret = journal.boot(t, pcr);
            if ret.is_ok() && env("SHIRUDO_TEST_CONFIG_BOOT_PENDING").is_none() {
                journal.complete_boot()
            } else {
                ret
            }
        }
        b"update" => journal.begin(t, pcr),
        b"stage" => {
            c.borrow_mut().staging = true;
            journal.stage(t)
        }
        b"cancel-stage" => journal.clear_staged(),
        b"staged" => return staged(c, journal),
        b"complete" => journal.complete_boot(),
        b"check" => journal.check().map(|_| ()),
        b"inspect" => Ok(()),
        b"reset" | b"restart" | b"resume" | b"drift" => {
            let mut c = c.borrow_mut();
            match how {
                b"reset" => c.sim.reset_count += 1,
                b"restart" | b"resume" => c.sim.restart_count += 1,
                _ => {}
            }
            if how != b"resume" {
                c.sim.value = [if how == b"drift" { 0x55 } else { 0 }; 32];
            }
            c.save()
        }
        // A second command, which finds the lock held and does not wait.
        b"lock" => ConfigUpdate::open(dir, c, 0).map(|_second| ()),
        _ => Err(-EINVAL),
    };
    rc(&ret)
}

fn run(args: &[&CStr]) -> c_int {
    if !(3..=5).contains(&args.len()) {
        return 2;
    }
    let id = match args.get(3).map(|a| a.to_bytes()) {
        None => b'A',
        Some(&[id @ b'A'..=b'Z']) => id,
        Some(_) => return 2,
    };
    let pcr = args.get(4).map_or(15, |p| number(p.to_bytes()) as u32);
    let t = target(id);
    let how = args[2].to_bytes();
    if how == b"describe" {
        return describe(&t);
    }

    let c = RefCell::new(Context {
        sim: Simulated::default(),
        tpm: None,
        directory: args[1],
        staging: false,
    });
    let ret = 'out: {
        if let Err(err) = c.borrow_mut().load() {
            break 'out err;
        }
        if env("SHIRUDO_TEST_CONFIG_TPM").is_some() {
            match Tpm::open() {
                Ok(tpm) => c.borrow_mut().tpm = Some(tpm),
                Err(err) => break 'out err,
            }
        }
        let lock_wait_ms =
            env("SHIRUDO_TEST_CONFIG_LOCK_WAIT_MS").map_or(0, |v| number(v.as_bytes()) as u32);
        let mut journal = match ConfigUpdate::open(args[1], &c, lock_wait_ms) {
            Ok(journal) => journal,
            Err(err) => break 'out err,
        };
        let ret = step(&c, &mut journal, how, args[1], &t, pcr);
        inspect(&c.borrow(), &journal);
        ret
    };
    drop(c);
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
