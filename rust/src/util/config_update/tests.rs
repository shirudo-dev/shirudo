// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use core::cell::Cell;
use core::ffi::c_int;
use std::ffi::CString;
use std::os::fd::BorrowedFd;

use super::{
    BootIdentity, Checkpoint, ConfigUpdate, ConfigUpdateOps, ConfigUpdateRecord,
    ConfigUpdateTarget, RECORD_MAX, record_decode, record_encode,
};
use crate::errno::{EBADMSG, EBUSY, EINPROGRESS, EUCLEAN};
use crate::testutil::TempDir;
use crate::util::chain::fold;

const PCR: u32 = 12;

struct FakeTpm {
    boot: Cell<BootIdentity>,
    value: Cell<[u8; 32]>,
    extends: Cell<u32>,
    fail_at: Cell<u32>,
}

impl FakeTpm {
    fn new() -> Self {
        Self {
            boot: Cell::new(BootIdentity {
                reset: 1,
                restart: 0,
            }),
            value: Cell::new([0; 32]),
            extends: Cell::new(0),
            fail_at: Cell::new(0),
        }
    }

    fn resume(&self) {
        let mut boot = self.boot.get();
        boot.restart += 1;
        self.boot.set(boot);
    }

    fn restart(&self) {
        self.resume();
        self.value.set([0; 32]);
    }

    fn reboot(&self) {
        let mut boot = self.boot.get();
        boot.reset += 1;
        boot.restart = 0;
        self.boot.set(boot);
        self.value.set([0; 32]);
    }
}

impl ConfigUpdateOps for FakeTpm {
    fn boot_identity(&self) -> Result<BootIdentity, c_int> {
        Ok(self.boot.get())
    }

    fn pcr_read(&self, _: u32) -> Result<[u8; 32], c_int> {
        Ok(self.value.get())
    }

    fn pcr_extend(&self, _: u32, event: &[u8; 32]) -> Result<(), c_int> {
        self.extends.set(self.extends.get() + 1);
        let mut value = self.value.get();
        fold(&mut value, event)?;
        self.value.set(value);
        Ok(())
    }

    fn prepare(&self, _: &ConfigUpdateTarget) -> Result<(), c_int> {
        Ok(())
    }

    fn activate(&self, _: &ConfigUpdate<'_>, _: &ConfigUpdateTarget) -> Result<(), c_int> {
        Ok(())
    }

    fn seal(&self, _: BorrowedFd<'_>) -> Result<(), c_int> {
        Ok(())
    }

    fn checkpoint(&self, point: Checkpoint) -> Result<(), c_int> {
        if point as u32 == self.fail_at.get() {
            Err(-libc::ECANCELED)
        } else {
            Ok(())
        }
    }
}

struct JournalCase {
    _dir: TempDir,
    path: CString,
    tpm: FakeTpm,
}

impl JournalCase {
    fn new() -> Self {
        let dir = TempDir::new();
        let path = dir.cpath("");
        Self {
            _dir: dir,
            path,
            tpm: FakeTpm::new(),
        }
    }

    fn open(&self) -> ConfigUpdate<'_> {
        ConfigUpdate::open(&self.path, &self.tpm, 0).unwrap()
    }

    fn target(id: u8) -> ConfigUpdateTarget {
        let mut target = ConfigUpdateTarget::zeroed();
        let prefix = format!("/verified/config-{}", char::from(id));
        target.prefix[..prefix.len()].copy_from_slice(prefix.as_bytes());
        target.root_hash = [id; 32];
        target
    }

    fn init(&self, id: u8) -> Result<(), c_int> {
        let mut journal = self.open();
        journal.boot(&Self::target(id), PCR)?;
        journal.complete_boot()
    }

    fn update(&self, id: u8) -> Result<(), c_int> {
        self.open().begin(&Self::target(id), PCR)
    }

    fn check(&self) -> Result<(), c_int> {
        self.open().check().map(|_| ())
    }

    fn stage(&self, id: u8) -> Result<(), c_int> {
        self.open().stage(&Self::target(id))
    }

    fn staged(&self) -> Result<bool, c_int> {
        let journal = self.open();
        let active = journal.read_state()?;
        journal
            .staged(&active, self.tpm.boot.get().reset)
            .map(|target| target.is_some())
    }

    fn sequence(&self) -> u64 {
        self.open().read_state().unwrap().sequence
    }
}

#[test]
#[cfg_attr(miri, ignore = "journal uses libc openat, flock and fsync")]
fn resume_keeps_pending_activation() {
    let case = JournalCase::new();
    assert_eq!(case.init(b'A'), Ok(()));
    case.tpm.fail_at.set(Checkpoint::Extend as u32);
    assert_eq!(case.update(b'B'), Err(-libc::ECANCELED));
    case.tpm.fail_at.set(0);
    case.tpm.resume();
    let extends = case.tpm.extends.get();
    assert_eq!(case.init(b'B'), Err(-EINPROGRESS));
    assert_eq!(case.check(), Err(-EINPROGRESS));
    assert_eq!(case.tpm.extends.get(), extends);
    case.tpm.reboot();
    assert_eq!(case.init(b'B'), Ok(()));
    assert_eq!(case.check(), Ok(()));
}

#[test]
#[cfg_attr(miri, ignore = "journal uses libc openat, flock and fsync")]
fn resume_keeps_completed_selection() {
    let case = JournalCase::new();
    assert_eq!(case.init(b'A'), Ok(()));
    let sequence = case.sequence();
    case.tpm.resume();
    let extends = case.tpm.extends.get();
    assert_eq!(case.check(), Ok(()));
    assert_eq!(case.init(b'A'), Ok(()));
    assert_eq!(case.tpm.extends.get(), extends);
    assert_eq!(case.sequence(), sequence);
    assert_eq!(case.init(b'B'), Err(-EBUSY));
    assert_eq!(case.update(b'B'), Ok(()));
    assert_eq!(case.check(), Ok(()));
}

#[test]
#[cfg_attr(miri, ignore = "journal uses libc openat, flock and fsync")]
fn restart_cannot_reuse_a_cleared_config_pcr() {
    let case = JournalCase::new();
    assert_eq!(case.init(b'A'), Ok(()));
    case.tpm.restart();
    let extends = case.tpm.extends.get();
    assert_eq!(case.check(), Err(-EUCLEAN));
    assert_eq!(case.init(b'A'), Err(-EUCLEAN));
    assert_eq!(case.tpm.extends.get(), extends);
    case.tpm.reboot();
    assert_eq!(case.init(b'A'), Ok(()));
    assert_eq!(case.check(), Ok(()));
}

#[test]
#[cfg_attr(miri, ignore = "journal uses libc openat, flock and fsync")]
fn staged_config_waits_for_a_tpm_reset() {
    let case = JournalCase::new();
    assert_eq!(case.init(b'A'), Ok(()));
    assert_eq!(case.stage(b'B'), Ok(()));
    case.tpm.resume();
    assert_eq!(case.staged(), Ok(false));
    assert_eq!(case.init(b'A'), Ok(()));
    case.tpm.reboot();
    assert_eq!(case.staged(), Ok(true));
    assert_eq!(case.init(b'B'), Ok(()));
    assert_eq!(case.check(), Ok(()));
}

#[test]
#[cfg_attr(miri, ignore = "journal uses libc openat, flock and fsync")]
fn config_nv_index_roundtrips_through_journal() {
    let case = JournalCase::new();
    let mut journal = case.open();
    let pcr = crate::util::config_measure::CONFIG_NVPCR_INDEX;

    assert_eq!(journal.boot(&JournalCase::target(b'A'), pcr), Ok(()));
    assert_eq!(journal.read_state().map(|record| record.pcr), Ok(pcr));
    assert_eq!(journal.complete_boot(), Ok(()));
    assert_eq!(journal.check().map(|record| record.pcr), Ok(pcr));
}

#[test]
fn saved_record_rejects_disallowed_pcr() {
    let mut record = ConfigUpdateRecord::zeroed();
    record.target = JournalCase::target(b'A');
    record.sequence = 1;
    record.pcr = 16;
    record.kind = crate::util::config_measure::EVENT_BOOT;
    let mut wire = [0u8; RECORD_MAX];
    let encoded = record_encode(&record, true, &mut wire).unwrap();

    assert!(matches!(record_decode(encoded, true), Err(err) if err == -EBADMSG));
}
