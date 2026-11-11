-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Chain

/-!
The upatch load and unload protocol of builtin-upatch.c and the boot
restore of builtin-init.c, against crashes, concurrent commands and root.

`image_enter()` admits an upatch command only once this boot's config
activation is complete, which `image_boot_complete()` does after `init`
restored the archive and wrote its record. A load (`cmd_upatch_load()`)
takes the register lock (`eventlog_lock()`) and runs the undo pass
(`undo_unmeasured()`). The pass folds this boot's records into the
measured set (`measured_set_boot()`), removes every pin directory whose
xattr the set does not hold, with the archive of the same name
(`measured_unmeasured_pins()`, `undo_load()`), then every labeled archive
file the set does not hold (`measured_unmeasured_archives()`), and refuses
the command when it could not read the records, scan or remove. The load
then refuses a name whose pin directory carries a payload xattr, pins
(`attach_and_pin_progs()`), sets the payload xattr (`set_pin_payload()`,
whose failure takes the pins out and fails the load), archives
(`persist_upatch()`), extends the register (`chain_extend()`) and appends
the eventlog record (`eventlog_append()`); an archive copy or an
extension that fails undoes the load (`unload_unmeasured()`). An unload
(`cmd_upatch_unload()`) takes the lock, runs the undo pass, checks the
pin's xattr against the directive, extends, appends, then detaches
(`remove_pin_dir()`) and removes the archive. A live key revocation
purges (`upatch_purge()`): under the lock from before its archive read
to after its archive unlink, it records an unload of a pinned name, then
detaches and removes the archive. Its signer check, which leaves in place
an archive another key signed, changes nothing and is left out: the
model's purge takes what it finds. After a reboot the pins are gone and
`init` restores every labeled archive file the whole log's fold holds
(`boot_restore()`, `measured_set_log()`, `measured_holds()`), binds the
register with one init event and appends its record, which carries the
restored set.

The model keeps what those steps read and write: the pin directories, a
table from name to the payloads whose links it holds and its xattr; the
archive, a table from file to the artifact's name and payload and whether
it carries the seal label; this boot's register as the list of events
extended; and the eventlog, every boot's records. Each command is a
process with a program counter at the points between which a crash can
fall. Every failure the C handles is a step of its own, and so is root's
every move. The assumptions, each a step or the absence of one:

- `eventlog_lock()` excludes: a command takes it only while no
  descriptor holds it (`canLock`), and a kill releases it, since the
  `flock()` goes with the descriptor.
- A kill, at any point, keeps the pins, the archive, the register and
  the log; a link attached but not yet pinned goes with the process.
- A pin directory is removed whole or not at all, and a failed
  `remove_pin_dir()` leaves it; an archive copy appears whole, by
  `seal_write_file()`'s rename; a record is appended whole or not at
  all, as `append_line()` drops a torn one; an extend can fail with the
  register moved or not.
- A reboot kills every process and clears the pins and the register, and
  `init`'s run is one step, which completes or stops anywhere without its
  record. The gate is why: no upatch command runs in a boot before an
  `init` run completed, a run after one that stopped refuses at
  `image_boot()`, and a run after one that completed changes nothing the
  model keeps.
- Root starts and kills commands at will, adds, replaces and deletes
  unlabeled archive files and brings back a file of any content under a
  free name. The seal stops every other change to the archive, the
  eventlog and the private bpffs: root cannot write, rename onto or
  unlink a labeled file, nor touch a pin.
- The register's hash and the event encoding are collision resistant,
  as `Shirudo.Chain` assumes, for `replay_differs` only.

For every sequence of steps from a fresh install, in the C's protocol
(`C`):

- `commands_need_init`: every command runs in a boot whose init record
  is on the log.
- `undo_pass_sound`: once an upatch command's undo pass is done, every
  pin directory holds one link, of the payload its xattr names and this
  boot's measured set holds, and every labeled archive file shirudo wrote
  is one the measured set holds.
- `loaded_once`: no name ever holds two links.
- `recorded_runs`: every name this boot's records hold is pinned with one
  link of the payload they hold, under the xattr that names it.
- `init_restores_exactly`: after a reboot whose `init` completes, the
  upatches loaded are exactly the labeled archive files whose last record
  in the log is a load of that name and payload, each once with its
  xattr, and the new boot's measured set is exactly what was loaded.
- `log_sublist_register`: this boot's records are always a sublist of the
  register's events, in the same order. `register_length` and
  `register_eq_log_iff`: once the lock is free, the register holds them
  and `lost` events more, those whose append failed, whose extend failed
  after the TPM took it or whose process was killed between the two, so
  the two agree exactly when there are none; otherwise `replay_differs`
  shows the replay of the log differs from the register.

Each part of the protocol a variant drops breaks the theorem it carries.
Without the lock, `undo_pass_sound` and `register_eq_log_iff` fail
(`undo_pass_needs_lock`, `log_needs_lock`); without the undo pass,
`undo_pass_sound` (`undo_pass_needs_undo`); without the refusal,
`loaded_once` (`undo_needs_refusal`), and without the gate as well, in a
boot whose `init` failed (`failed_init_needs_gate_or_refusal`); without
the undo of a load whose payload xattr cannot be written, and without the
lock across the purge, `recorded_runs`, even with no process left and the
register and the log agreeing (`xattr_needs_undo`, `purge_needs_lock`);
and without the `measured_holds()` filter of `boot_restore()`,
`init_restores_exactly` (`init_needs_filter`).
testing/proofs/cbmc/measured-fold-model.c checks `measured_event()` and
`measured_holds()` against `fold` and `held` on every sequence of up to
six records.
-/

namespace Shirudo.UpatchLoad

/- Names and payloads are compared in most definitions and some lemmas
only; one `variable` line serves them all. -/
set_option linter.unusedSectionVars false

/-! ### Tables -/

/-- `f` with `a` mapped to `b`: one entry of a table changed. -/
def upd {α β : Type} [DecidableEq α] (f : α → β) (a : α) (b : β) : α → β :=
  fun x => if x = a then b else f x

@[simp] theorem upd_same {α β : Type} [DecidableEq α] (f : α → β) (a : α)
    (b : β) : upd f a b a = b := by
  simp [upd]

theorem upd_ne {α β : Type} [DecidableEq α] (f : α → β) {a x : α} (b : β)
    (h : x ≠ a) : upd f a b x = f x := by
  simp [upd, h]

theorem upd_others {α β : Type} [DecidableEq α] {f : α → β} {a : α} {b : β} :
    ∀ x, x ≠ a → upd f a b x = f x :=
  fun _ h => upd_ne f b h

/-! ### State -/

/-- A register event and an eventlog record: `init` carries the set
`boot_restore()` restored, `upatch_load` and `upatch_unload` a name and a
payload. -/
inductive Ev (Name Payload : Type) where
  | init (set : List (Name × Payload))
  | load (n : Name) (p : Payload)
  | unload (n : Name) (p : Payload)

def Ev.isInit {Name Payload : Type} : Ev Name Payload → Bool
  | .init _ => true
  | _ => false

/-- One eventlog line: the boot it was written in and its event. -/
structure Rec (Name Payload : Type) where
  boot : Nat
  ev : Ev Name Payload

/-- A pin directory under the private bpffs: the payloads of the loads
whose links it holds, and the payload xattr `set_pin_payload()` wrote. -/
structure Pin (Payload : Type) where
  links : List Payload
  xattr : Option Payload
  deriving DecidableEq

/-- A file of the archive: the name and payload its header carries,
whether it carries the seal label (`seal_owns()`), and, as a ghost the C
does not have, whether root rather than shirudo put it there. -/
structure Entry (Name Payload : Type) where
  name : Name
  payload : Payload
  labeled : Bool
  byRoot : Bool

/-- A command: a load or an unload of a name with a payload, or the purge
of a name a live revocation runs. -/
inductive Cmd (Name Payload : Type) where
  | load (n : Name) (p : Payload)
  | unload (n : Name) (p : Payload)
  | purge (n : Name)

def Cmd.name {Name Payload : Type} : Cmd Name Payload → Name
  | .load n _ => n
  | .unload n _ => n
  | .purge n => n

def Cmd.isPurge {Name Payload : Type} : Cmd Name Payload → Bool
  | .purge _ => true
  | _ => false

/-- The points of a command between which a crash can fall. -/
inductive Pc (Name Payload : Type) where
  /-- Before `eventlog_lock()`. -/
  | start
  /-- In `measured_unmeasured_pins()`, with the measured set read, the
  pin directories `scandir()` listed still to visit, and whether a
  removal failed. -/
  | undoPins (m : Name → Option Payload) (todo : List Name) (failed : Bool)
  /-- In `measured_unmeasured_archives()`. -/
  | undoArch (m : Name → Option Payload) (todo : List Name) (failed : Bool)
  /-- `undo_unmeasured()` returned. -/
  | acted
  /-- A load: `mkdir_if_absent()` of its pin directory done, `fresh` when
  it made the directory. -/
  | made (fresh : Bool)
  /-- A load: its links pinned. -/
  | attached
  /-- A load: `set_pin_payload()` done. -/
  | xattrDone
  /-- A load: `persist_upatch()` done. -/
  | persisted
  /-- A load or an unload: `chain_extend()` done, the append next. -/
  | extended
  /-- An unload or a purge: its record appended, `remove_pin_dir()` next. -/
  | detach
  /-- An unload or a purge: the archive's `unlink()` next. -/
  | unlinkArch
  /-- A purge: the archive read and the name found pinned, the extend
  next. -/
  | purgeWait (p : Payload)
  /-- A purge: extended, the append next. -/
  | purgeAppend (p : Payload)

structure Proc (Name Payload : Type) where
  cmd : Cmd Name Payload
  pc : Pc Name Payload

abbrev Measured (Name Payload : Type) := Name → Option Payload
abbrev Pins (Name Payload : Type) := Name → Option (Pin Payload)
abbrev Arch (Name Payload : Type) := Name → Option (Entry Name Payload)

/-- What the protocol reads and writes. `lost` is a ghost: the number of
events this boot extended without their append. -/
structure State (Name Payload : Type) where
  boot : Nat
  pins : Pins Name Payload
  arch : Arch Name Payload
  reg : List (Ev Name Payload)
  log : List (Rec Name Payload)
  lock : Option Nat
  procs : Nat → Option (Proc Name Payload)
  lost : Nat

variable {Name Payload : Type} [DecidableEq Name] [DecidableEq Payload]

/-! ### The measured set -/

/-- `measured_event()`: an init record starts the set afresh from the
set it carries, a load records its payload under its name, an unload
drops the name whatever its payload. -/
def applyEv (m : Measured Name Payload) :
    Ev Name Payload → Measured Name Payload
  | .init set => set.foldl (fun m e => upd m e.1 (some e.2)) (fun _ => none)
  | .load n p => upd m n (some p)
  | .unload n _ => upd m n none

/-- The measured set of a list of records (`measured_set_fold()`). -/
def fold (evs : List (Ev Name Payload)) : Measured Name Payload :=
  evs.foldl applyEv (fun _ => none)

/-- This boot's records (`walk_lines()` with `all` false). -/
def bootEvs (s : State Name Payload) : List (Ev Name Payload) :=
  (s.log.filter (fun r => r.boot == s.boot)).map Rec.ev

/-- Whether this boot's init record is on the log. -/
def hasInit (s : State Name Payload) : Bool :=
  (bootEvs s).any Ev.isInit

/-- `measured_set_boot()`: `-ENOENT` without this boot's init record. -/
def measuredBoot (s : State Name Payload) : Option (Measured Name Payload) :=
  if hasInit s then some (fold (bootEvs s)) else none

/-- `measured_set_log()`: the whole log, every init record a fresh start. -/
def measuredLog (s : State Name Payload) : Measured Name Payload :=
  fold (s.log.map Rec.ev)

/-- `measured_holds()` of a pin directory's xattr: a directory without
one is read as the empty string, which no record holds. -/
def held (m : Measured Name Payload) (n : Name) : Option Payload → Bool
  | none => false
  | some q => decide (m n = some q)

/-- The test of `measured_unmeasured_pins()` for one directory. -/
def pinUnmeasured (m : Measured Name Payload) (n : Name) :
    Option (Pin Payload) → Bool
  | none => false
  | some d => !held m n d.xattr

/-- The test of `measured_unmeasured_archives()` for one file: labeled,
and a name and payload the set does not hold. -/
def archUnmeasured (m : Measured Name Payload) :
    Option (Entry Name Payload) → Bool
  | none => false
  | some e => e.labeled && !decide (m e.name = some e.payload)

/-! ### Steps -/

/-- The process leaves, and with its descriptor goes its lock. -/
def State.exit (s : State Name Payload) (i : Nat) : State Name Payload :=
  { s with procs := upd s.procs i none,
           lock := if s.lock = some i then none else s.lock }

/-- The process moves on to `pc`. -/
def State.go (s : State Name Payload) (i : Nat) (c : Cmd Name Payload)
    (pc : Pc Name Payload) : State Name Payload :=
  { s with procs := upd s.procs i (some ⟨c, pc⟩) }

/-- How `undo_load()` ends: both removed, the pins removed but the
archive's `unlink()` failed, or `remove_pin_dir()` failed. -/
inductive UndoOut where
  | ok
  | archFail
  | pinFail

def UndoOut.failed : UndoOut → Bool
  | .ok => false
  | _ => true

/-- `undo_load()`: the pin directory, then the archive of that name. -/
def State.undoLoad (s : State Name Payload) (n : Name) :
    UndoOut → State Name Payload
  | .ok => { s with pins := upd s.pins n none, arch := upd s.arch n none }
  | .archFail => { s with pins := upd s.pins n none }
  | .pinFail => s

/-- One archive file in `boot_restore()`: skipped unless labeled and,
with the filter, held by the log's fold; counted when its name is pinned
with its payload, a failure when pinned with another, applied otherwise.
`none` is a failed restore. -/
def restoreStep (filter : Bool) (mL : Measured Name Payload)
    (arch : Arch Name Payload) :
    Option (Pins Name Payload × List (Name × Payload)) → Name →
    Option (Pins Name Payload × List (Name × Payload))
  | none, _ => none
  | some (pins, set), k =>
    match arch k with
    | none => some (pins, set)
    | some e =>
      if e.labeled = true ∧ (filter = false ∨ mL e.name = some e.payload) then
        match pins e.name with
        | some d =>
          if d.xattr = some e.payload then
            some (pins, set ++ [(e.name, e.payload)])
          else none
        | none =>
          some (upd pins e.name (some ⟨[e.payload], some e.payload⟩),
                set ++ [(e.name, e.payload)])
      else some (pins, set)

/-- `boot_restore()` over the files `scandir()` listed, from no pins. -/
def restore (filter : Bool) (mL : Measured Name Payload)
    (arch : Arch Name Payload) (ks : List Name) :
    Option (Pins Name Payload × List (Name × Payload)) :=
  ks.foldl (restoreStep filter mL arch) (some (fun _ => none, []))

/-- A new boot: no process, no pins, the register `reg`, the log `log`. -/
def booted (s : State Name Payload) (pins : Pins Name Payload)
    (reg : List (Ev Name Payload)) (log : List (Rec Name Payload))
    (lost : Nat) : State Name Payload :=
  { boot := s.boot + 1, pins, arch := s.arch, reg, log, lock := none,
    procs := fun _ => none, lost }

/-- The event a process extended and has yet to append. -/
def inflightEv : Proc Name Payload → Option (Ev Name Payload)
  | ⟨.load n p, .extended⟩ => some (.load n p)
  | ⟨.unload n p, .extended⟩ => some (.unload n p)
  | ⟨.purge n, .purgeAppend q⟩ => some (.unload n q)
  | _ => none

/-- Which parts of the protocol a variant keeps. `C` keeps them all. -/
structure Variant where
  /-- `eventlog_lock()` around a load's or an unload's undo pass, pins
  and append. -/
  lock : Bool := true
  /-- `undo_unmeasured()`. -/
  undo : Bool := true
  /-- `undo_unmeasured()` refuses the command when it cannot read this
  boot's records, scan or remove what they do not cover. -/
  refuse : Bool := true
  /-- A failed `set_pin_payload()` takes the load's pins out and fails the
  load. -/
  xattrUndo : Bool := true
  /-- `upatch_purge()` holds the lock from its archive read to its
  archive unlink. -/
  purgeLock : Bool := true
  /-- The `measured_holds()` filter of `boot_restore()`. -/
  filter : Bool := true
  /-- `image_enter()` admits an upatch command only once this boot's
  config activation is complete, which `image_boot_complete()` does after
  `init` wrote its record. -/
  gate : Bool := true

/-- The protocol as builtin-upatch.c and builtin-init.c have it. -/
def C : Variant := {}

/-- `eventlog_lock()` returns: no other descriptor holds the lock. -/
def canLock (V : Variant) (s : State Name Payload) : Prop :=
  V.lock = false ∨ s.lock = none

/-- One step of one process, of root, or a reboot. -/
inductive Step (V : Variant) :
    State Name Payload → State Name Payload → Prop where
  /-- Root, a timer or the operator starts a command; `image_enter()`
  admits it only once this boot's init record is on the log. -/
  | spawn (s) (i c) : s.procs i = none → (V.gate = true → hasInit s = true) →
      Step V s (s.go i c .start)
  /-- A command fails before it changes anything: version gate, staging,
  pre-flight, no archive to purge, or an undo pass that cannot read this
  boot's records, which refuses. -/
  | bailStart (s) (i c) : s.procs i = some ⟨c, .start⟩ → Step V s (s.exit i)
  /-- A command fails after its undo pass with nothing changed: a refused
  name (the xattr check, a payload mismatch, an xattr missing) or a
  signature, verifier or loader failure before the first pin. -/
  | bailActed (s) (i c) : s.procs i = some ⟨c, .acted⟩ → Step V s (s.exit i)
  /-- Root kills the process (`SIGKILL`). -/
  | kill (s) (i c) : s.procs i = some c →
      Step V s { s.exit i with
        lost := s.lost + if (inflightEv c).isSome then 1 else 0 }
  /-- `eventlog_lock()`, then `measured_set_boot()` and `scandir()` of
  the pin directories. -/
  | lockUndo (s) (i c m todo) : s.procs i = some ⟨c, .start⟩ →
      c.isPurge = false → canLock V s → V.undo = true →
      measuredBoot s = some m → (∀ n, s.pins n ≠ none → n ∈ todo) →
      Step V s { s.go i c (.undoPins m todo false) with lock := some i }
  /-- The lock and no undo pass: the variant without it, or a pass that
  cannot read the records and goes on regardless. -/
  | lockSkip (s) (i c) : s.procs i = some ⟨c, .start⟩ →
      c.isPurge = false → canLock V s →
      (V.undo = false ∨ V.refuse = false) →
      Step V s { s.go i c .acted with lock := some i }
  /-- A pin directory the set holds with its xattr. -/
  | undoKeep (s) (i c m n todo f) :
      s.procs i = some ⟨c, .undoPins m (n :: todo) f⟩ →
      pinUnmeasured m n (s.pins n) = false →
      Step V s (s.go i c (.undoPins m todo f))
  /-- `undo_unmeasured_pin()`: `undo_load()` of an unmeasured directory;
  a failure is kept and the pass goes on. -/
  | undoRemove (s) (i c m n todo f) (out : UndoOut) :
      s.procs i = some ⟨c, .undoPins m (n :: todo) f⟩ →
      pinUnmeasured m n (s.pins n) = true →
      Step V s ((s.undoLoad n out).go i c (.undoPins m todo (f || out.failed)))
  /-- The pins done, `scandir()` of the archive. -/
  | undoPinsDone (s) (i c m f todo) : s.procs i = some ⟨c, .undoPins m [] f⟩ →
      (∀ k, s.arch k ≠ none → k ∈ todo) →
      Step V s (s.go i c (.undoArch m todo f))
  /-- An archive file unlabeled, or held by the set. -/
  | undoArchKeep (s) (i c m k todo f) :
      s.procs i = some ⟨c, .undoArch m (k :: todo) f⟩ →
      archUnmeasured m (s.arch k) = false →
      Step V s (s.go i c (.undoArch m todo f))
  /-- `undo_unmeasured_archive()`: its `unlink()`, which may fail. -/
  | undoArchRemove (s) (i c m k todo f) (ok : Bool) :
      s.procs i = some ⟨c, .undoArch m (k :: todo) f⟩ →
      archUnmeasured m (s.arch k) = true →
      Step V s { s.go i c (.undoArch m todo (f || !ok)) with
        arch := if ok then upd s.arch k none else s.arch }
  /-- The pass done with nothing left it could not remove. -/
  | undoArchDone (s) (i c m f) : s.procs i = some ⟨c, .undoArch m [] f⟩ →
      (f = false ∨ V.refuse = false) →
      Step V s (s.go i c .acted)
  /-- `undo_unmeasured()` refuses the command: a `scandir()` failed, or a
  removal did and the pass is done. -/
  | undoRefuse (s) (i c m todo f) :
      (s.procs i = some ⟨c, .undoPins m todo f⟩ ∨
       s.procs i = some ⟨c, .undoArch m todo f⟩) → V.refuse = true →
      Step V s (s.exit i)
  /-- A `scandir()` fails and the command goes on regardless. -/
  | undoAbort (s) (i c m todo f) :
      (s.procs i = some ⟨c, .undoPins m todo f⟩ ∨
       s.procs i = some ⟨c, .undoArch m todo f⟩) → V.refuse = false →
      Step V s (s.go i c .acted)
  /-- A load past `upatch_pin_payload()`, which refuses a directory with an
  xattr: `mkdir_if_absent()` of its directory. -/
  | loadMkdir (s) (i n p) : s.procs i = some ⟨.load n p, .acted⟩ →
      (∀ d, s.pins n = some d → d.xattr = none) →
      Step V s { s.go i (.load n p) (.made (s.pins n).isNone) with
        pins := upd s.pins n (some ((s.pins n).getD ⟨[], none⟩)) }
  /-- Its links pinned: into a directory a stale load left, they collide
  or, with other link names, do not. -/
  | loadAttach (s) (i n p b d) : s.procs i = some ⟨.load n p, .made b⟩ →
      s.pins n = some d →
      Step V s { s.go i (.load n p) .attached with
        pins := upd s.pins n (some ⟨p :: d.links, d.xattr⟩) }
  /-- `attach_and_pin_progs()` fails: what it pinned is unpinned, the
  directory removed if it made it. -/
  | loadAttachFail (s) (i n p b) : s.procs i = some ⟨.load n p, .made b⟩ →
      Step V s { s.exit i with pins := if b then upd s.pins n none else s.pins }
  /-- `set_pin_payload()`. -/
  | loadXattr (s) (i n p) : s.procs i = some ⟨.load n p, .attached⟩ →
      Step V s { s.go i (.load n p) .xattrDone with
        pins := upd s.pins n ((s.pins n).map fun d => ⟨d.links, some p⟩) }
  /-- `set_pin_payload()` fails: `remove_pin_dir()`, which may fail too,
  and the load fails at `link_create`. -/
  | loadXattrFail (s) (i n p) (removed : Bool) :
      s.procs i = some ⟨.load n p, .attached⟩ → V.xattrUndo = true →
      Step V s { s.exit i with
        pins := if removed then upd s.pins n none else s.pins }
  /-- `set_pin_payload()` fails and the load goes on regardless. -/
  | loadXattrIgnore (s) (i n p) : s.procs i = some ⟨.load n p, .attached⟩ →
      V.xattrUndo = false → Step V s (s.go i (.load n p) .xattrDone)
  /-- `persist_upatch()`: `seal_write_file()` renames the copy in. -/
  | loadPersist (s) (i n p) : s.procs i = some ⟨.load n p, .xattrDone⟩ →
      Step V s { s.go i (.load n p) .persisted with
        arch := upd s.arch n (some ⟨n, p, true, false⟩) }
  /-- `persist_upatch()` fails, before or after its rename, and
  `unload_unmeasured()` undoes the load. -/
  | loadPersistFail (s) (i n p) (wrote : Bool) (out : UndoOut) :
      s.procs i = some ⟨.load n p, .xattrDone⟩ →
      Step V s ((({ s with
        arch := if wrote then upd s.arch n (some ⟨n, p, true, false⟩)
                else s.arch } : State Name Payload).undoLoad n out).exit i)
  /-- `chain_extend()`, which needs this boot's init record. -/
  | loadExtend (s) (i n p) : s.procs i = some ⟨.load n p, .persisted⟩ →
      hasInit s = true →
      Step V s { s.go i (.load n p) .extended with reg := s.reg ++ [.load n p] }
  /-- `chain_extend()` fails, with the register moved (`after`, a read
  back or a response lost) or not, and `unload_unmeasured()` undoes the
  load. -/
  | loadExtendFail (s) (i n p) (after : Bool) (out : UndoOut) :
      s.procs i = some ⟨.load n p, .persisted⟩ →
      (after = true → hasInit s = true) →
      Step V s ((({ s with reg := if after then s.reg ++ [.load n p] else s.reg,
                           lost := if after then s.lost + 1 else s.lost } :
                    State Name Payload).undoLoad n out).exit i)
  /-- `eventlog_append()`, and the lock released. -/
  | loadAppend (s) (i n p) : s.procs i = some ⟨.load n p, .extended⟩ →
      Step V s { s.exit i with log := s.log ++ [⟨s.boot, .load n p⟩] }
  /-- The append fails after the extend: the load stays. -/
  | loadAppendFail (s) (i n p) : s.procs i = some ⟨.load n p, .extended⟩ →
      Step V s { s.exit i with lost := s.lost + 1 }
  /-- An unload whose name has no pin directory: "already unloaded", the
  archive's `unlink()`, no event. -/
  | unloadGone (s) (i n p) (ok : Bool) :
      s.procs i = some ⟨.unload n p, .acted⟩ →
      s.pins n = none →
      Step V s { s.exit i with
        arch := if ok then upd s.arch n none else s.arch }
  /-- An unload whose pin carries the directive's payload: the extend. -/
  | unloadExtend (s) (i n p d) : s.procs i = some ⟨.unload n p, .acted⟩ →
      s.pins n = some d → d.xattr = some p → hasInit s = true →
      Step V s { s.go i (.unload n p) .extended with
        reg := s.reg ++ [.unload n p] }
  /-- The extend fails: nothing detached. -/
  | unloadExtendFail (s) (i n p d) (after : Bool) :
      s.procs i = some ⟨.unload n p, .acted⟩ → s.pins n = some d →
      d.xattr = some p → (after = true → hasInit s = true) →
      Step V s { s.exit i with
        reg := if after then s.reg ++ [.unload n p] else s.reg,
        lost := if after then s.lost + 1 else s.lost }
  /-- `eventlog_append()`, the lock kept for the detach. -/
  | unloadAppend (s) (i n p) : s.procs i = some ⟨.unload n p, .extended⟩ →
      Step V s { s.go i (.unload n p) .detach with
        log := s.log ++ [⟨s.boot, .unload n p⟩] }
  /-- The append fails after the extend: nothing detached. -/
  | unloadAppendFail (s) (i n p) : s.procs i = some ⟨.unload n p, .extended⟩ →
      Step V s { s.exit i with lost := s.lost + 1 }
  /-- `remove_pin_dir()` of an unload or a purge. -/
  | detach (s) (i c) : s.procs i = some ⟨c, .detach⟩ →
      Step V s { s.go i c .unlinkArch with pins := upd s.pins c.name none }
  | detachFail (s) (i c) : s.procs i = some ⟨c, .detach⟩ → Step V s (s.exit i)
  /-- The archive's `unlink()`, which may fail. -/
  | unlinkArch (s) (i c) (ok : Bool) : s.procs i = some ⟨c, .unlinkArch⟩ →
      Step V s { s.exit i with
        arch := if ok then upd s.arch c.name none else s.arch }
  /-- `upatch_purge()` takes the lock, reads the labeled archive and finds
  the name pinned. -/
  | purgeRead (s) (i n e) : s.procs i = some ⟨.purge n, .start⟩ →
      s.arch n = some e → e.labeled = true → s.pins n ≠ none →
      (V.purgeLock = true → canLock V s) →
      Step V s { s.go i (.purge n) (.purgeWait e.payload) with
        lock := if V.purgeLock then some i else s.lock }
  /-- Not pinned: only the archive goes. -/
  | purgeArchOnly (s) (i n e) : s.procs i = some ⟨.purge n, .start⟩ →
      s.arch n = some e → e.labeled = true → s.pins n = none →
      (V.purgeLock = true → canLock V s) →
      Step V s { s.go i (.purge n) .unlinkArch with
        lock := if V.purgeLock then some i else s.lock }
  /-- `upatch_chain_event_locked()`: the extend, under the lock the purge
  holds, or, without it, one taken for the event. -/
  | purgeExtend (s) (i n q) : s.procs i = some ⟨.purge n, .purgeWait q⟩ →
      (V.purgeLock = true → s.lock = some i) →
      (V.purgeLock = false → canLock V s) → hasInit s = true →
      Step V s { s.go i (.purge n) (.purgeAppend q) with
        reg := s.reg ++ [.unload n q], lock := some i }
  | purgeExtendFail (s) (i n q) (after : Bool) :
      s.procs i = some ⟨.purge n, .purgeWait q⟩ →
      (V.purgeLock = true → s.lock = some i) →
      (V.purgeLock = false → canLock V s) →
      (after = true → hasInit s = true) →
      Step V s { s.exit i with
        reg := if after then s.reg ++ [.unload n q] else s.reg,
        lost := if after then s.lost + 1 else s.lost }
  /-- The append; the lock stays for the detach, or, without it, goes. -/
  | purgeAppend (s) (i n q) : s.procs i = some ⟨.purge n, .purgeAppend q⟩ →
      Step V s { s.go i (.purge n) .detach with
        log := s.log ++ [⟨s.boot, .unload n q⟩],
        lock := if V.purgeLock then s.lock else none }
  | purgeAppendFail (s) (i n q) : s.procs i = some ⟨.purge n, .purgeAppend q⟩ →
      Step V s { s.exit i with lost := s.lost + 1 }
  /-- Root writes or replaces an unlabeled file in the archive. -/
  | rootAdd (s) (k) (e : Entry Name Payload) : e.labeled = false →
      (∀ e', s.arch k = some e' → e'.labeled = false) →
      Step V s { s with arch := upd s.arch k (some e) }
  /-- Root deletes an unlabeled file. -/
  | rootDel (s) (k) (e : Entry Name Payload) : s.arch k = some e →
      e.labeled = false → Step V s { s with arch := upd s.arch k none }
  /-- Root brings a file back under a free name, labeled or not. -/
  | rootBring (s) (k) (e : Entry Name Payload) : s.arch k = none →
      e.byRoot = true → Step V s { s with arch := upd s.arch k (some e) }
  /-- A reboot, and `init` restores, binds the register and appends its
  record. -/
  | rebootOk (s) (ks : List Name) (pins set) : (∀ k, s.arch k ≠ none → k ∈ ks) →
      restore V.filter (measuredLog s) s.arch ks = some (pins, set) →
      Step V s
        (booted s pins [.init set] (s.log ++ [⟨s.boot + 1, .init set⟩]) 0)
  /-- A reboot whose `init` stops without its record: after restoring part
  of the archive, each name with one link and with its xattr or, when
  `set_pin_payload()` and the removal after it failed, without, or before
  or after binding the register. -/
  | rebootFail (s) (pins : Pins Name Payload) (set) (bound : Bool) :
      (∀ n d, pins n = some d →
        ∃ p, d.links = [p] ∧ (d.xattr = none ∨ d.xattr = some p)) →
      Step V s (booted s pins (if bound then [.init set] else []) s.log
        (if bound then 1 else 0))

/-- A fresh install before its first boot. -/
def s0 : State Name Payload :=
  { boot := 0, pins := fun _ => none, arch := fun _ => none, reg := [],
    log := [], lock := none, procs := fun _ => none, lost := 0 }

/-- The states some sequence of steps reaches from a fresh install. -/
inductive Reach (V : Variant) : State Name Payload → Prop where
  | init : Reach V s0
  | step {s s'} : Reach V s → Step V s s' → Reach V s'

/-! ### Field lemmas -/

section fields
variable (s : State Name Payload) (i : Nat) (c : Cmd Name Payload)
  (pc : Pc Name Payload) (n : Name) (out : UndoOut)

@[simp] theorem go_procs :
    (s.go i c pc).procs = upd s.procs i (some ⟨c, pc⟩) := rfl
@[simp] theorem go_lock : (s.go i c pc).lock = s.lock := rfl
@[simp] theorem go_pins : (s.go i c pc).pins = s.pins := rfl
@[simp] theorem go_arch : (s.go i c pc).arch = s.arch := rfl
@[simp] theorem go_log : (s.go i c pc).log = s.log := rfl
@[simp] theorem go_boot : (s.go i c pc).boot = s.boot := rfl
@[simp] theorem go_reg : (s.go i c pc).reg = s.reg := rfl
@[simp] theorem go_lost : (s.go i c pc).lost = s.lost := rfl
@[simp] theorem exit_procs : (s.exit i).procs = upd s.procs i none := rfl
@[simp] theorem exit_lock :
    (s.exit i).lock = if s.lock = some i then none else s.lock := rfl
@[simp] theorem exit_pins : (s.exit i).pins = s.pins := rfl
@[simp] theorem exit_arch : (s.exit i).arch = s.arch := rfl
@[simp] theorem exit_log : (s.exit i).log = s.log := rfl
@[simp] theorem exit_boot : (s.exit i).boot = s.boot := rfl
@[simp] theorem exit_reg : (s.exit i).reg = s.reg := rfl
@[simp] theorem exit_lost : (s.exit i).lost = s.lost := rfl
@[simp] theorem undoLoad_procs : (s.undoLoad n out).procs = s.procs := by
  cases out <;> rfl
@[simp] theorem undoLoad_lock : (s.undoLoad n out).lock = s.lock := by
  cases out <;> rfl
@[simp] theorem undoLoad_log : (s.undoLoad n out).log = s.log := by
  cases out <;> rfl
@[simp] theorem undoLoad_boot : (s.undoLoad n out).boot = s.boot := by
  cases out <;> rfl
@[simp] theorem undoLoad_reg : (s.undoLoad n out).reg = s.reg := by
  cases out <;> rfl
@[simp] theorem undoLoad_lost : (s.undoLoad n out).lost = s.lost := by
  cases out <;> rfl
/-- `undo_load()` only removes. -/
theorem undoLoad_pins_sub (m : Name) (d : Pin Payload) :
    (s.undoLoad n out).pins m = some d → s.pins m = some d := by
  cases out <;> simp only [State.undoLoad] <;> intro h
  · by_cases hm : m = n
    · subst hm; simp at h
    · rwa [upd_ne _ _ hm] at h
  · by_cases hm : m = n
    · subst hm; simp at h
    · rwa [upd_ne _ _ hm] at h
  · exact h

end fields

theorem bootEvs_congr {s s' : State Name Payload} (hb : s'.boot = s.boot)
    (hl : s'.log = s.log) : bootEvs s' = bootEvs s := by
  simp [bootEvs, hb, hl]

theorem hasInit_congr {s s' : State Name Payload} (hb : s'.boot = s.boot)
    (hl : s'.log = s.log) : hasInit s' = hasInit s := by
  simp [hasInit, bootEvs_congr hb hl]

theorem bootEvs_snoc (s : State Name Payload) (log : List (Rec Name Payload))
    (e : Ev Name Payload) (hl : log = s.log ++ [⟨s.boot, e⟩])
    (s' : State Name Payload) (hb : s'.boot = s.boot) (hl' : s'.log = log) :
    bootEvs s' = bootEvs s ++ [e] := by
  subst hl
  simp [bootEvs, hb, hl', List.filter_append]

/-! ### The lock -/

/-- Whether the process holds `eventlog.lock`: every command from its
`eventlog_lock()` to its exit. -/
def holds (_ : Cmd Name Payload) : Pc Name Payload → Bool
  | .start => false
  | _ => true

/-- Lock exclusion: a process holds the lock exactly when the lock names
it, so at most one does. -/
def LockInv (procs : Nat → Option (Proc Name Payload)) (lock : Option Nat) :
    Prop :=
  (∀ i c, procs i = some c → holds c.cmd c.pc = true → lock = some i) ∧
  (∀ i, lock = some i → ∃ c, procs i = some c ∧ holds c.cmd c.pc = true)

section lockinv
variable {procs : Nat → Option (Proc Name Payload)} {lock : Option Nat}

theorem LockInv.move (h : LockInv procs lock) {i : Nat}
    {c c' : Proc Name Payload}
    (hi : procs i = some c) (hh : holds c'.cmd c'.pc = holds c.cmd c.pc) :
    LockInv (upd procs i (some c')) lock := by
  constructor
  · intro j d hj hd
    by_cases hji : j = i
    · subst hji
      simp at hj
      subst hj
      exact h.1 _ _ hi (hh ▸ hd)
    · rw [upd_ne _ _ hji] at hj
      exact h.1 _ _ hj hd
  · intro j hj
    obtain ⟨d, hd, hdh⟩ := h.2 j hj
    by_cases hji : j = i
    · subst hji
      rw [hi] at hd
      cases hd
      exact ⟨c', by simp, hh ▸ hdh⟩
    · exact ⟨d, by rw [upd_ne _ _ hji]; exact hd, hdh⟩

theorem LockInv.exit (h : LockInv procs lock) {i : Nat} :
    LockInv (upd procs i none) (if lock = some i then none else lock) := by
  constructor
  · intro j d hj hd
    by_cases hji : j = i
    · subst hji; simp at hj
    · rw [upd_ne _ _ hji] at hj
      have := h.1 _ _ hj hd
      simp [this, hji]
  · intro j hj
    by_cases hl : lock = some i
    · simp [hl] at hj
    · simp only [hl, ite_false] at hj
      obtain ⟨d, hd, hdh⟩ := h.2 j hj
      have hji : j ≠ i := by
        intro e; subst e; exact hl hj
      exact ⟨d, by rw [upd_ne _ _ hji]; exact hd, hdh⟩

theorem LockInv.acquire (h : LockInv procs lock) {i : Nat}
    {c' : Proc Name Payload}
    (hl : lock = none) (hc' : holds c'.cmd c'.pc = true) :
    LockInv (upd procs i (some c')) (some i) := by
  constructor
  · intro j d hj hd
    by_cases hji : j = i
    · rw [hji]
    · rw [upd_ne _ _ hji] at hj
      rw [h.1 _ _ hj hd] at hl
      cases hl
  · intro j hj
    cases hj
    exact ⟨c', by simp, hc'⟩

theorem LockInv.spawn (h : LockInv procs lock) {i : Nat}
    {c' : Proc Name Payload}
    (hi : procs i = none) (hc' : holds c'.cmd c'.pc = false) :
    LockInv (upd procs i (some c')) lock := by
  constructor
  · intro j d hj hd
    by_cases hji : j = i
    · subst hji; simp at hj; subst hj; rw [hc'] at hd; cases hd
    · rw [upd_ne _ _ hji] at hj
      exact h.1 _ _ hj hd
  · intro j hj
    obtain ⟨d, hd, hdh⟩ := h.2 j hj
    have hji : j ≠ i := by
      intro e; subst e; rw [hi] at hd; cases hd
    exact ⟨d, by rw [upd_ne _ _ hji]; exact hd, hdh⟩

theorem LockInv.empty :
    LockInv (fun _ => (none : Option (Proc Name Payload))) none := by
  constructor
  · intro i c h; simp at h
  · intro i h; simp at h

end lockinv

theorem canLock_C {s : State Name Payload} (h : canLock C s) :
    s.lock = none := by
  rcases h with h | h
  · cases h
  · exact h

theorem holds_start (c : Cmd Name Payload) : holds c .start = false := by
  cases c <;> rfl

theorem holds_of_ne_start {c : Cmd Name Payload} {pc : Pc Name Payload}
    (hpc : pc ≠ .start) : holds c pc = true := by
  cases pc <;> simp_all [holds]

theorem holds_load (n : Name) (p : Payload) {pc : Pc Name Payload}
    (hpc : pc ≠ .start) : holds (.load n p) pc = true :=
  holds_of_ne_start hpc

theorem holds_unload (n : Name) (p : Payload) {pc : Pc Name Payload}
    (hpc : pc ≠ .start) : holds (.unload n p) pc = true :=
  holds_of_ne_start hpc

/-- The lock admits one holder at a time in every reachable state. -/
theorem lockInv_step {s s' : State Name Payload} (h : LockInv s.procs s.lock)
    (hs : Step C s s') : LockInv s'.procs s'.lock := by
  cases hs with
  | spawn i c hi => exact h.spawn hi (holds_start c)
  | bailStart i c hi => exact h.exit
  | bailActed i c hi => exact h.exit
  | kill i c hi => exact h.exit
  | lockUndo i c m todo hi hc hl =>
    exact h.acquire (canLock_C hl) (holds_of_ne_start (by simp))
  | lockSkip i c hi hc hl =>
    exact h.acquire (canLock_C hl) (holds_of_ne_start (by simp))
  | undoKeep i c m n todo f hi => exact h.move hi rfl
  | undoRemove i c m n todo f out hi =>
    simpa using h.move (c' := ⟨c, .undoPins m todo (f || out.failed)⟩) hi rfl
  | undoPinsDone i c m f todo hi => exact h.move hi rfl
  | undoArchKeep i c m k todo f hi => exact h.move hi rfl
  | undoArchRemove i c m k todo f ok hi => exact h.move hi rfl
  | undoArchDone i c m f hi => exact h.move hi rfl
  | undoRefuse i c m todo f hi => exact h.exit
  | undoAbort i c m todo f hi => rcases hi with hi | hi <;> exact h.move hi rfl
  | loadMkdir i n p hi => exact h.move hi rfl
  | loadAttach i n p b d hi => exact h.move hi rfl
  | loadAttachFail i n p b hi => exact h.exit
  | loadXattr i n p hi => exact h.move hi rfl
  | loadXattrFail i n p removed hi => exact h.exit
  | loadXattrIgnore i n p hi => exact h.move hi rfl
  | loadPersist i n p hi => exact h.move hi rfl
  | loadPersistFail i n p wrote out hi => simpa using h.exit (i := i)
  | loadExtend i n p hi => exact h.move hi rfl
  | loadExtendFail i n p after out hi => simpa using h.exit (i := i)
  | loadAppend i n p hi => exact h.exit
  | loadAppendFail i n p hi => exact h.exit
  | unloadGone i n p ok hi => exact h.exit
  | unloadExtend i n p d hi => exact h.move hi rfl
  | unloadExtendFail i n p d after hi => exact h.exit
  | unloadAppend i n p hi => exact h.move hi rfl
  | unloadAppendFail i n p hi => exact h.exit
  | detach i c hi => exact h.move hi rfl
  | detachFail i c hi => exact h.exit
  | unlinkArch i c ok hi => exact h.exit
  | purgeRead i n e hi _ _ _ hl =>
    exact h.acquire (canLock_C (hl rfl)) rfl
  | purgeArchOnly i n e hi _ _ _ hl =>
    exact h.acquire (canLock_C (hl rfl)) rfl
  | purgeExtend i n q hi hl =>
    show LockInv (upd s.procs i _) (some i)
    rw [← hl rfl]
    exact h.move hi rfl
  | purgeExtendFail i n q after hi => exact h.exit
  | purgeAppend i n q hi => exact h.move hi rfl
  | purgeAppendFail i n q hi => exact h.exit
  | rootAdd => exact h
  | rootDel => exact h
  | rootBring => exact h
  | rebootOk => exact LockInv.empty
  | rebootFail => exact LockInv.empty

/-! ### The register and the log -/

theorem holds_of_inflight {c : Proc Name Payload} {e : Ev Name Payload}
    (h : inflightEv c = some e) : holds c.cmd c.pc = true := by
  rcases c with ⟨cmd, pc⟩
  cases cmd <;> cases pc <;> simp_all [inflightEv, holds]

/-- Under the lock at most one process is between its extend and its
append. -/
theorem inflight_unique {s : State Name Payload} (hl : LockInv s.procs s.lock)
    {i j : Nat} {c c' : Proc Name Payload} {e e' : Ev Name Payload}
    (hi : s.procs i = some c) (hc : inflightEv c = some e)
    (hj : s.procs j = some c') (hc' : inflightEv c' = some e') : i = j := by
  have h1 := hl.1 _ _ hi (holds_of_inflight hc)
  have h2 := hl.1 _ _ hj (holds_of_inflight hc')
  rw [h1] at h2
  cases h2
  rfl

theorem noInflight_of_holder {s : State Name Payload}
    (hl : LockInv s.procs s.lock)
    {i : Nat} {c : Proc Name Payload} (hi : s.procs i = some c)
    (hc : holds c.cmd c.pc = true) (hni : inflightEv c = none) :
    ∀ j c', s.procs j = some c' → inflightEv c' = none := by
  intro j c' hj
  cases hce : inflightEv c' with
  | none => rfl
  | some e =>
    have h1 := hl.1 _ _ hi hc
    have h2 := hl.1 _ _ hj (holds_of_inflight hce)
    rw [h1] at h2
    cases h2
    rw [hi] at hj
    cases hj
    rw [hni] at hce
    cases hce

theorem noInflight_of_free {s : State Name Payload}
    (hl : LockInv s.procs s.lock) (hfree : s.lock = none) :
    ∀ j c', s.procs j = some c' → inflightEv c' = none := by
  intro j c' hj
  cases hce : inflightEv c' with
  | none => rfl
  | some e =>
    have h2 := hl.1 _ _ hj (holds_of_inflight hce)
    rw [hfree] at h2
    cases h2

/-- The log's records of this boot are a sublist of the register's
events: the register holds them in the same order, and `lost` more
besides, and the event of a process between its extend and its append
comes last. -/
def RegInv (s : State Name Payload) : Prop :=
  (∀ r ∈ s.log, r.boot ≤ s.boot) ∧
  ∃ X, List.Sublist (bootEvs s) X ∧ X.length = (bootEvs s).length + s.lost ∧
    ((s.reg = X ∧ ∀ i c, s.procs i = some c → inflightEv c = none) ∨
     (∃ i c e, s.procs i = some c ∧ inflightEv c = some e ∧ s.reg = X ++ [e]))

section reginv
variable {s s' : State Name Payload}

/-- A step that leaves the register, the log and every process between
its extend and its append alone. -/
theorem RegInv.quiet (h : RegInv s) (hb : s'.boot = s.boot)
    (hlog : s'.log = s.log)
    (hreg : s'.reg = s.reg) (hlost : s'.lost = s.lost)
    (hp : ∀ j c, s'.procs j = some c → inflightEv c = none ∨ s.procs j = some c)
    (hp' : ∀ j c, s.procs j = some c → inflightEv c ≠ none →
      s'.procs j = some c) :
    RegInv s' := by
  obtain ⟨hbound, X, hX, hlen, hd⟩ := h
  refine ⟨by rw [hlog, hb]; exact hbound, X, ?_, ?_, ?_⟩
  · rw [bootEvs_congr hb hlog]; exact hX
  · rw [bootEvs_congr hb hlog, hlost]; exact hlen
  · rcases hd with ⟨hr, hall⟩ | ⟨i, c, e, hi, hc, hr⟩
    · left
      refine ⟨by rw [hreg]; exact hr, ?_⟩
      intro j c hj
      rcases hp j c hj with h | h
      · exact h
      · exact hall j c h
    · right
      refine ⟨i, c, e, hp' i c hi (by rw [hc]; simp), hc, ?_⟩
      rw [hreg]; exact hr

/-- A process moves on, or leaves, outside its extend-to-append window. -/
theorem RegInv.move (h : RegInv s) {i : Nat} {o : Option (Proc Name Payload)}
    (hb : s'.boot = s.boot) (hlog : s'.log = s.log) (hreg : s'.reg = s.reg)
    (hlost : s'.lost = s.lost) (hprocs : s'.procs = upd s.procs i o)
    (hold : ∀ c, s.procs i = some c → inflightEv c = none)
    (hnew : ∀ c, o = some c → inflightEv c = none) : RegInv s' := by
  refine h.quiet hb hlog hreg hlost ?_ ?_
  · intro j c hj
    rw [hprocs] at hj
    by_cases hji : j = i
    · subst hji; simp at hj; left; exact hnew c hj
    · rw [upd_ne _ _ hji] at hj; right; exact hj
  · intro j c hj hc
    rw [hprocs]
    by_cases hji : j = i
    · subst hji; exact absurd (hold c hj) hc
    · rw [upd_ne _ _ hji]; exact hj

/-- An extend with no process between its extend and its append. -/
theorem RegInv.extend (h : RegInv s)
    (hnone : ∀ j c, s.procs j = some c → inflightEv c = none)
    {i : Nat} {c' : Proc Name Payload} {e : Ev Name Payload}
    (hc' : inflightEv c' = some e)
    (hb : s'.boot = s.boot) (hlog : s'.log = s.log)
    (hreg : s'.reg = s.reg ++ [e])
    (hlost : s'.lost = s.lost) (hprocs : s'.procs = upd s.procs i (some c')) :
    RegInv s' := by
  obtain ⟨hbound, X, hX, hlen, hd⟩ := h
  have hr : s.reg = X := by
    rcases hd with ⟨hr, _⟩ | ⟨j, c, e', hj, hc, _⟩
    · exact hr
    · rw [hnone j c hj] at hc; cases hc
  refine ⟨by rw [hlog, hb]; exact hbound, X, ?_, ?_, ?_⟩
  · rw [bootEvs_congr hb hlog]; exact hX
  · rw [bootEvs_congr hb hlog, hlost]; exact hlen
  · right
    exact ⟨i, c', e, by rw [hprocs]; simp, hc', by rw [hreg, hr]⟩

/-- An extend that fails, the register moved or not, and the process
leaves. -/
theorem RegInv.extendFail (h : RegInv s)
    (hnone : ∀ j c, s.procs j = some c → inflightEv c = none)
    {e : Ev Name Payload} (after : Bool)
    (hb : s'.boot = s.boot) (hlog : s'.log = s.log)
    (hreg : s'.reg = if after then s.reg ++ [e] else s.reg)
    (hlost : s'.lost = if after then s.lost + 1 else s.lost)
    (hprocs : ∀ j c, s'.procs j = some c → inflightEv c = none) :
    RegInv s' := by
  obtain ⟨hbound, X, hX, hlen, hd⟩ := h
  have hr : s.reg = X := by
    rcases hd with ⟨hr, _⟩ | ⟨j, c, e', hj, hc, _⟩
    · exact hr
    · rw [hnone j c hj] at hc; cases hc
  refine ⟨by rw [hlog, hb]; exact hbound, s'.reg, ?_, ?_, Or.inl ⟨rfl, hprocs⟩⟩
  · rw [bootEvs_congr hb hlog, hreg]
    cases after
    · simpa [hr] using hX
    · simpa [hr] using hX.trans (List.sublist_append_left X [e])
  · rw [bootEvs_congr hb hlog, hreg, hlost]
    cases after
    · simpa [hr] using hlen
    · simp [hr, hlen]; omega

/-- The append of the process between its extend and its append. -/
theorem RegInv.append (hl : LockInv s.procs s.lock) (h : RegInv s)
    {i : Nat} {c : Proc Name Payload} {e : Ev Name Payload}
    {o : Option (Proc Name Payload)}
    (hi : s.procs i = some c) (hc : inflightEv c = some e)
    (hb : s'.boot = s.boot) (hlog : s'.log = s.log ++ [⟨s.boot, e⟩])
    (hreg : s'.reg = s.reg) (hlost : s'.lost = s.lost)
    (hprocs : s'.procs = upd s.procs i o)
    (hnew : ∀ c, o = some c → inflightEv c = none) :
    RegInv s' := by
  obtain ⟨hbound, X, hX, hlen, hd⟩ := h
  have hr : s.reg = X ++ [e] := by
    rcases hd with ⟨_, hall⟩ | ⟨j, c', e', hj, hc', hr⟩
    · rw [hall i c hi] at hc; cases hc
    · have hji := inflight_unique hl hj hc' hi hc
      subst hji
      rw [hi] at hj
      cases hj
      rw [hc] at hc'
      cases hc'
      exact hr
  have hbe : bootEvs s' = bootEvs s ++ [e] :=
    bootEvs_snoc s (s.log ++ [⟨s.boot, e⟩]) e rfl s' hb hlog
  refine ⟨?_, X ++ [e], ?_, ?_, Or.inl ⟨by rw [hreg, hr], ?_⟩⟩
  · intro r hr'
    rw [hlog] at hr'
    rw [hb]
    rcases List.mem_append.1 hr' with hr' | hr'
    · exact hbound r hr'
    · simp at hr'; rw [hr']; exact Nat.le_refl _
  · rw [hbe]; exact hX.append_right [e]
  · rw [hbe]; simp [hlen]; omega
  · intro j c' hj
    rw [hprocs] at hj
    by_cases hji : j = i
    · subst hji; simp at hj; exact hnew c' hj
    · rw [upd_ne _ _ hji] at hj
      cases hce : inflightEv c' with
      | none => rfl
      | some e' => exact absurd (inflight_unique hl hj hce hi hc) hji

/-- The append of the process between its extend and its append fails,
or the process is killed there: the event stays in the register only. -/
theorem RegInv.appendFail (hl : LockInv s.procs s.lock) (h : RegInv s)
    {i : Nat} {c : Proc Name Payload} {e : Ev Name Payload}
    (hi : s.procs i = some c) (hc : inflightEv c = some e)
    (hb : s'.boot = s.boot) (hlog : s'.log = s.log)
    (hreg : s'.reg = s.reg) (hlost : s'.lost = s.lost + 1)
    (hprocs : s'.procs = upd s.procs i none) : RegInv s' := by
  obtain ⟨hbound, X, hX, hlen, hd⟩ := h
  have hr : s.reg = X ++ [e] := by
    rcases hd with ⟨_, hall⟩ | ⟨j, c', e', hj, hc', hr⟩
    · rw [hall i c hi] at hc; cases hc
    · have hji := inflight_unique hl hj hc' hi hc
      subst hji
      rw [hi] at hj
      cases hj
      rw [hc] at hc'
      cases hc'
      exact hr
  refine ⟨by rw [hlog, hb]; exact hbound, X ++ [e], ?_, ?_,
    Or.inl ⟨by rw [hreg, hr], ?_⟩⟩
  · rw [bootEvs_congr hb hlog]; exact hX.trans (List.sublist_append_left X [e])
  · rw [bootEvs_congr hb hlog, hlost]; simp [hlen]; omega
  · intro j c' hj
    rw [hprocs] at hj
    by_cases hji : j = i
    · subst hji; simp at hj
    · rw [upd_ne _ _ hji] at hj
      cases hce : inflightEv c' with
      | none => rfl
      | some e' => exact absurd (inflight_unique hl hj hce hi hc) hji

end reginv

theorem inflightEv_none_of (c : Cmd Name Payload) (pc : Pc Name Payload)
    (h : pc ≠ .extended) (h' : ∀ q, pc ≠ .purgeAppend q) :
    inflightEv ⟨c, pc⟩ = none := by
  cases c <;> cases pc <;> simp_all [inflightEv]

theorem hold_none {s : State Name Payload} {i : Nat} {c : Cmd Name Payload}
    {pc : Pc Name Payload} (hi : s.procs i = some ⟨c, pc⟩)
    (h : pc ≠ .extended := by simp) (h' : ∀ q, pc ≠ .purgeAppend q := by simp) :
    ∀ c', s.procs i = some c' → inflightEv c' = none := by
  intro c' h''
  rw [hi] at h''
  cases h''
  exact inflightEv_none_of c pc h h'

theorem new_none {c : Cmd Name Payload} {pc : Pc Name Payload}
    (h : pc ≠ .extended := by simp) (h' : ∀ q, pc ≠ .purgeAppend q := by simp) :
    ∀ c', some (⟨c, pc⟩ : Proc Name Payload) = some c' →
      inflightEv c' = none := by
  intro c' h''
  cases h''
  exact inflightEv_none_of c pc h h'

theorem exit_none :
    ∀ c' : Proc Name Payload, (none : Option (Proc Name Payload)) = some c' →
    inflightEv c' = none := by
  intro c' h; cases h

theorem upd_none_all {s : State Name Payload} (hl : LockInv s.procs s.lock)
    {i : Nat} {c : Proc Name Payload} (hi : s.procs i = some c)
    (hc : holds c.cmd c.pc = true)
    (hni : inflightEv c = none) :
    ∀ j c', upd s.procs i none j = some c' → inflightEv c' = none := by
  intro j c' hj
  by_cases hji : j = i
  · subst hji; simp at hj
  · rw [upd_ne _ _ hji] at hj
    exact noInflight_of_holder hl hi hc hni j c' hj

theorem bootEvs_booted_old {s : State Name Payload}
    (hbound : ∀ r ∈ s.log, r.boot ≤ s.boot)
    (pins : Pins Name Payload) (reg : List (Ev Name Payload)) (lost : Nat) :
    bootEvs (booted s pins reg s.log lost) = [] := by
  simp only [bootEvs, booted]
  rw [List.filter_eq_nil_iff.2]
  · rfl
  · intro r hr; have := hbound r hr; simp; omega

theorem bootEvs_booted_new {s : State Name Payload}
    (hbound : ∀ r ∈ s.log, r.boot ≤ s.boot)
    (pins : Pins Name Payload) (reg : List (Ev Name Payload)) (lost : Nat)
    (e : Ev Name Payload) :
    bootEvs (booted s pins reg (s.log ++ [⟨s.boot + 1, e⟩]) lost) = [e] := by
  have : s.log.filter (fun r => r.boot == s.boot + 1) = [] := by
    rw [List.filter_eq_nil_iff]
    intro r hr; have := hbound r hr; simp; omega
  simp [bootEvs, booted, List.filter_append, this]

/-- Every step keeps the log a sublist of the register. -/
theorem regInv_step {s s' : State Name Payload} (hl : LockInv s.procs s.lock)
    (h : RegInv s) (hs : Step C s s') : RegInv s' := by
  cases hs with
  | spawn i c hi =>
    exact h.move rfl rfl rfl rfl rfl (fun c' h' => by rw [hi] at h'; cases h')
      new_none
  | bailStart i c hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | bailActed i c hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | kill i c hi =>
    cases hce : inflightEv c with
    | none =>
      exact h.move rfl rfl rfl (by simp) rfl
        (fun c' h' => by rw [hi] at h'; cases h'; exact hce) exit_none
    | some e => exact h.appendFail hl hi hce rfl rfl rfl (by simp) rfl
  | lockUndo i c m todo hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | lockSkip i c hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoKeep i c m n todo f hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoRemove i c m n todo f out hi =>
    exact h.move (o := some ⟨c, .undoPins m todo (f || out.failed)⟩)
      (by simp) (by simp) (by simp) (by simp) (by simp) (hold_none hi) new_none
  | undoPinsDone i c m f todo hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoArchKeep i c m k todo f hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoArchRemove i c m k todo f ok hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoArchDone i c m f hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | undoRefuse i c m todo f hi =>
    rcases hi with hi | hi <;>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | undoAbort i c m todo f hi =>
    rcases hi with hi | hi <;>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadMkdir i n p hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadAttach i n p b d hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadAttachFail i n p b hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | loadXattr i n p hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadXattrFail i n p removed hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | loadXattrIgnore i n p hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadPersist i n p hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | loadPersistFail i n p wrote out hi =>
    exact h.move (by simp) (by simp) (by simp) (by simp) (by simp)
      (hold_none hi) exit_none
  | loadExtend i n p hi =>
    exact h.extend (noInflight_of_holder hl hi rfl rfl)
      (c' := ⟨.load n p, .extended⟩) rfl rfl rfl rfl rfl rfl
  | loadExtendFail i n p after out hi =>
    exact h.extendFail (noInflight_of_holder hl hi rfl rfl) (e := .load n p)
      after (by simp) (by simp) (by simp) (by simp)
      (by simpa using upd_none_all hl hi rfl rfl)
  | loadAppend i n p hi =>
    exact h.append hl hi rfl rfl rfl rfl rfl rfl exit_none
  | loadAppendFail i n p hi =>
    exact h.appendFail hl hi rfl rfl rfl rfl rfl rfl
  | unloadGone i n p ok hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | unloadExtend i n p d hi =>
    exact h.extend (noInflight_of_holder hl hi rfl rfl)
      (c' := ⟨.unload n p, .extended⟩) rfl rfl rfl rfl rfl rfl
  | unloadExtendFail i n p d after hi =>
    exact h.extendFail (noInflight_of_holder hl hi rfl rfl) (e := .unload n p)
      after rfl rfl rfl rfl (upd_none_all hl hi rfl rfl)
  | unloadAppend i n p hi =>
    exact h.append hl hi rfl rfl rfl rfl rfl rfl new_none
  | unloadAppendFail i n p hi =>
    exact h.appendFail hl hi rfl rfl rfl rfl rfl rfl
  | detach i c hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | detachFail i c hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | unlinkArch i c ok hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) exit_none
  | purgeRead i n e hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | purgeArchOnly i n e hi =>
    exact h.move rfl rfl rfl rfl rfl (hold_none hi) new_none
  | purgeExtend i n q hi =>
    exact h.extend (noInflight_of_holder hl hi rfl rfl)
      (c' := ⟨.purge n, .purgeAppend q⟩) rfl rfl rfl rfl rfl rfl
  | purgeExtendFail i n q after hi =>
    exact h.extendFail (noInflight_of_holder hl hi rfl rfl) (e := .unload n q)
      after rfl rfl rfl rfl (upd_none_all hl hi rfl rfl)
  | purgeAppend i n q hi =>
    exact h.append hl hi rfl rfl rfl rfl rfl rfl new_none
  | purgeAppendFail i n q hi =>
    exact h.appendFail hl hi rfl rfl rfl rfl rfl rfl
  | rootAdd k e =>
    exact h.quiet rfl rfl rfl rfl (fun j c hj => Or.inr hj) (fun j c hj _ => hj)
  | rootDel k e =>
    exact h.quiet rfl rfl rfl rfl (fun j c hj => Or.inr hj) (fun j c hj _ => hj)
  | rootBring k e =>
    exact h.quiet rfl rfl rfl rfl (fun j c hj => Or.inr hj) (fun j c hj _ => hj)
  | rebootOk ks pins set hks hr =>
    obtain ⟨hbound, -⟩ := h
    have hnew := bootEvs_booted_new hbound pins [.init set] 0 (.init set)
    refine ⟨?_, [.init set], by rw [hnew]; exact List.Sublist.refl _,
      by rw [hnew]; simp [booted], Or.inl ⟨rfl, ?_⟩⟩
    · intro r hr
      simp only [booted, List.mem_append, List.mem_singleton] at hr ⊢
      rcases hr with hr | hr
      · have := hbound r hr; omega
      · rw [hr]; exact Nat.le_refl _
    · intro j c hj; simp [booted] at hj
  | rebootFail pins set bound hp =>
    obtain ⟨hbound, -⟩ := h
    have hnew := bootEvs_booted_old hbound pins
      (if bound then [.init set] else []) (if bound then 1 else 0)
    refine ⟨?_, (if bound then [.init set] else []), ?_, ?_, Or.inl ⟨rfl, ?_⟩⟩
    · intro r hr; have := hbound r hr; simp [booted]; omega
    · rw [hnew]; exact List.nil_sublist _
    · rw [hnew]; cases bound <;> simp [booted]
    · intro j c hj; simp [booted] at hj

/-! ### Boot restore -/

theorem foldl_restoreStep_none (f : Bool) (mL : Measured Name Payload)
    (arch : Arch Name Payload) (ks : List Name) :
    ks.foldl (restoreStep f mL arch) none = none := by
  induction ks with
  | nil => rfl
  | cons k ks ih => simpa [List.foldl, restoreStep] using ih

/-- The set an init record carries, as `measured_event()` folds it. -/
def setFold (set : List (Name × Payload)) : Measured Name Payload :=
  set.foldl (fun m e => upd m e.1 (some e.2)) (fun _ => none)

theorem setFold_snoc (set : List (Name × Payload)) (n : Name) (p : Payload) :
    setFold (set ++ [(n, p)]) = upd (setFold set) n (some p) := by
  simp [setFold, List.foldl_append]

theorem fold_init (set : List (Name × Payload)) :
    fold [.init set] = setFold set := rfl

/-- Every directory the restore makes holds one link and names it. -/
theorem restore_shape (f : Bool) (mL : Measured Name Payload)
    (arch : Arch Name Payload) (ks : List Name) :
    ∀ acc : Pins Name Payload × List (Name × Payload),
      (∀ n d, acc.1 n = some d → ∃ q, d = ⟨[q], some q⟩) →
      ∀ r, ks.foldl (restoreStep f mL arch) (some acc) = some r →
        ∀ n d, r.1 n = some d → ∃ q, d = ⟨[q], some q⟩ := by
  induction ks with
  | nil => intro acc h r hr; simp at hr; subst hr; exact h
  | cons k ks ih =>
    intro acc h r hr
    rcases acc with ⟨pins, set⟩
    simp only [List.foldl] at hr
    cases hstep : restoreStep f mL arch (some (pins, set)) k with
    | none => rw [hstep, foldl_restoreStep_none] at hr; cases hr
    | some acc' =>
      rw [hstep] at hr
      refine ih acc' ?_ r hr
      simp only [restoreStep] at hstep
      split at hstep
      · cases hstep; exact h
      · rename_i e he
        split at hstep
        · split at hstep
          · split at hstep
            · cases hstep; exact h
            · cases hstep
          · cases hstep
            intro n d hd
            dsimp only at hd
            by_cases hn : n = e.name
            · subst hn; simp at hd; exact ⟨_, hd.symm⟩
            · rw [upd_ne _ _ hn] at hd; exact h n d hd
        · cases hstep; exact h

/-- The archive files among `pre` whose load of `n` with `p` the log's
fold records. -/
def wantIn (mL : Measured Name Payload) (arch : Arch Name Payload)
    (pre : List Name) (n : Name) (p : Payload) : Prop :=
  ∃ k ∈ pre, ∃ e, arch k = some e ∧ e.labeled = true ∧ e.name = n ∧
    e.payload = p ∧ mL n = some p

/-- What `boot_restore()` should load: a labeled archive file of `n` with
`p`, whose last record in the log is a load of `n` with `p`. -/
def Wanted (mL : Measured Name Payload) (arch : Arch Name Payload)
    (n : Name) (p : Payload) : Prop :=
  ∃ k e, arch k = some e ∧ e.labeled = true ∧ e.name = n ∧ e.payload = p ∧
    mL n = some p

/-- The restore after `pre`: a name is pinned with one link of `p`
exactly when a file of `pre` wants it, and the set folds to the pins. -/
def RestoreInv (mL : Measured Name Payload) (arch : Arch Name Payload)
    (pre : List Name) (acc : Pins Name Payload × List (Name × Payload)) :
    Prop :=
  (∀ n, (acc.1 n = none ∧ ∀ p, ¬ wantIn mL arch pre n p) ∨
        ∃ p, acc.1 n = some ⟨[p], some p⟩ ∧ wantIn mL arch pre n p) ∧
  (∀ n, setFold acc.2 n = (acc.1 n).bind Pin.xattr)

theorem wantIn_snoc (mL : Measured Name Payload) (arch : Arch Name Payload)
    (pre : List Name) (k n : Name) (p : Payload) :
    wantIn mL arch (pre ++ [k]) n p ↔ wantIn mL arch pre n p ∨
      ∃ e, arch k = some e ∧ e.labeled = true ∧ e.name = n ∧ e.payload = p ∧
        mL n = some p := by
  constructor
  · rintro ⟨k', hk', e, he⟩
    rcases List.mem_append.1 hk' with hk' | hk'
    · exact Or.inl ⟨k', hk', e, he⟩
    · simp at hk'; subst hk'; exact Or.inr ⟨e, he⟩
  · rintro (⟨k', hk', e, he⟩ | ⟨e, he⟩)
    · exact ⟨k', List.mem_append_left _ hk', e, he⟩
    · exact ⟨k, by simp, e, he⟩

theorem restoreInv_step (mL : Measured Name Payload)
    (arch : Arch Name Payload) (pre : List Name) (k : Name)
    (acc acc' : Pins Name Payload × List (Name × Payload))
    (h : RestoreInv mL arch pre acc)
    (hs : restoreStep true mL arch (some acc) k = some acc') :
    RestoreInv mL arch (pre ++ [k]) acc' := by
  rcases acc with ⟨pins, set⟩
  obtain ⟨hp, hset⟩ := h
  dsimp only at hp hset
  simp only [restoreStep] at hs
  split at hs
  · rename_i hk
    cases hs
    refine ⟨fun n => ?_, hset⟩
    rcases hp n with ⟨hn, hw⟩ | ⟨p, hn, hw⟩
    · left
      refine ⟨hn, fun p hw' => ?_⟩
      rcases (wantIn_snoc mL arch pre k n p).1 hw' with hw' | ⟨e, he, _⟩
      · exact hw p hw'
      · rw [hk] at he; cases he
    · exact Or.inr ⟨p, hn, (wantIn_snoc mL arch pre k n p).2 (Or.inl hw)⟩
  · rename_i e hk
    split at hs
    · rename_i hcond
      have hlab : e.labeled = true := hcond.1
      have hm : mL e.name = some e.payload := by
        rcases hcond.2 with h | h
        · cases h
        · exact h
      have hnew : ∀ n p, wantIn mL arch (pre ++ [k]) n p ↔
          wantIn mL arch pre n p ∨ (n = e.name ∧ p = e.payload) := by
        intro n p
        rw [wantIn_snoc]
        constructor
        · rintro (h | ⟨e', he', -, hn, hp', -⟩)
          · exact Or.inl h
          · rw [hk] at he'; cases he'; exact Or.inr ⟨hn.symm, hp'.symm⟩
        · rintro (h | ⟨hn, hp'⟩)
          · exact Or.inl h
          · subst hn; subst hp'; exact Or.inr ⟨e, hk, hlab, rfl, rfl, hm⟩
      split at hs
      · rename_i d hd
        split at hs
        · rename_i hx
          cases hs
          have hd' : d = ⟨[e.payload], some e.payload⟩ := by
            rcases hp e.name with ⟨hn, -⟩ | ⟨q, hn, hw⟩
            · rw [hd] at hn; cases hn
            · rw [hd] at hn; cases hn
              obtain ⟨_, _, _, _, _, _, _, hq⟩ := hw
              rw [hm] at hq; cases hq; rfl
          refine ⟨fun n => ?_, fun n => ?_⟩
          · rcases hp n with ⟨hn, hw⟩ | ⟨q, hn, hw⟩
            · left
              refine ⟨hn, fun q hw' => ?_⟩
              rcases (hnew n q).1 hw' with hw' | ⟨hn', -⟩
              · exact hw q hw'
              · subst hn'; rw [hd] at hn; cases hn
            · exact Or.inr ⟨q, hn, (hnew n q).2 (Or.inl hw)⟩
          · show setFold (set ++ [(e.name, e.payload)]) n =
              (pins n).bind Pin.xattr
            rw [setFold_snoc]
            by_cases hn : n = e.name
            · subst hn; simp [hd, hx]
            · rw [upd_ne _ _ hn]; exact hset n
        · cases hs
      · rename_i hd
        cases hs
        refine ⟨fun n => ?_, fun n => ?_⟩
        · by_cases hn : n = e.name
          · subst hn
            right
            exact ⟨e.payload, by simp, (hnew _ _).2 (Or.inr ⟨rfl, rfl⟩)⟩
          · simp only [upd_ne _ _ hn]
            rcases hp n with ⟨hn', hw⟩ | ⟨q, hn', hw⟩
            · left
              refine ⟨hn', fun q hw' => ?_⟩
              rcases (hnew n q).1 hw' with hw' | ⟨hn'', -⟩
              · exact hw q hw'
              · exact hn hn''
            · exact Or.inr ⟨q, hn', (hnew n q).2 (Or.inl hw)⟩
        · show setFold (set ++ [(e.name, e.payload)]) n = _
          rw [setFold_snoc]
          by_cases hn : n = e.name
          · subst hn; simp
          · simp only [upd_ne _ _ hn]; exact hset n
    · rename_i hcond
      cases hs
      refine ⟨fun n => ?_, hset⟩
      rcases hp n with ⟨hn, hw⟩ | ⟨p, hn, hw⟩
      · left
        refine ⟨hn, fun p hw' => ?_⟩
        rcases (wantIn_snoc mL arch pre k n p).1 hw' with
          hw' | ⟨e', he', hl, hn', hp', hm⟩
        · exact hw p hw'
        · rw [hk] at he'; cases he'
          subst hn'; subst hp'
          exact hcond ⟨hl, Or.inr hm⟩
      · exact Or.inr ⟨p, hn, (wantIn_snoc mL arch pre k n p).2 (Or.inl hw)⟩

theorem restoreInv_foldl (mL : Measured Name Payload)
    (arch : Arch Name Payload) (ks : List Name) :
    ∀ pre acc r, RestoreInv mL arch pre acc →
      ks.foldl (restoreStep true mL arch) (some acc) = some r →
      RestoreInv mL arch (pre ++ ks) r := by
  induction ks with
  | nil => intro pre acc r h hr; simp at hr; subst hr; simpa using h
  | cons k ks ih =>
    intro pre acc r h hr
    simp only [List.foldl] at hr
    cases hstep : restoreStep true mL arch (some acc) k with
    | none => rw [hstep, foldl_restoreStep_none] at hr; cases hr
    | some acc' =>
      rw [hstep] at hr
      have := ih (pre ++ [k]) acc' r
        (restoreInv_step mL arch pre k acc acc' h hstep) hr
      simpa using this

/-- `boot_restore()` loads exactly what the log's fold records of the
labeled archive, each name once with one link, and the init record's set
is what it loaded. -/
theorem restore_exact (mL : Measured Name Payload)
    (arch : Arch Name Payload) (ks : List Name)
    (hks : ∀ k, arch k ≠ none → k ∈ ks)
    {pins : Pins Name Payload} {set : List (Name × Payload)}
    (h : restore true mL arch ks = some (pins, set)) :
    (∀ n, (pins n = none ∧ ∀ p, ¬ Wanted mL arch n p) ∨
          ∃ p, pins n = some ⟨[p], some p⟩ ∧ Wanted mL arch n p) ∧
    (∀ n, setFold set n = (pins n).bind Pin.xattr) := by
  have h0 : RestoreInv mL arch [] (fun _ => none, []) :=
    ⟨fun n => Or.inl ⟨rfl, fun p ⟨k, hk, _⟩ => by cases hk⟩, fun n => rfl⟩
  have hinv := restoreInv_foldl mL arch ks [] _ _ h0 h
  simp only [List.nil_append] at hinv
  have hw : ∀ n p, wantIn mL arch ks n p ↔ Wanted mL arch n p := by
    intro n p
    constructor
    · rintro ⟨k, -, e, he⟩; exact ⟨k, e, he⟩
    · rintro ⟨k, e, he⟩
      exact ⟨k, hks k (by rw [he.1]; simp), e, he⟩
  refine ⟨fun n => ?_, hinv.2⟩
  rcases hinv.1 n with ⟨hn, hn'⟩ | ⟨p, hn, hn'⟩
  · exact Or.inl ⟨hn, fun p hp => hn' p ((hw n p).2 hp)⟩
  · exact Or.inr ⟨p, hn, (hw n p).1 hn'⟩

/-! ### Pins and the measured set -/

/-- Every pin directory holds at most one link, and one whose xattr names
a payload holds a link of that payload. -/
def I1 (pins : Pins Name Payload) : Prop :=
  ∀ n d, pins n = some d →
    d.links.length ≤ 1 ∧ ∀ q, d.xattr = some q → d.links = [q]

/-- Every pin directory carries an xattr the measured set holds. -/
def Good (m : Measured Name Payload) (pins : Pins Name Payload) : Prop :=
  ∀ n d, pins n = some d → ∃ q, d.xattr = some q ∧ m n = some q

/-- Every labeled archive file shirudo wrote is one the measured set
holds. -/
def ArchGood (m : Measured Name Payload) (arch : Arch Name Payload) : Prop :=
  ∀ k e, arch k = some e → e.labeled = true → e.byRoot = false →
    m e.name = some e.payload

/-- Every name this boot's records hold is pinned with one link of the
payload they hold, under the xattr that names it. -/
def Recorded (s : State Name Payload) : Prop :=
  ∀ n p, fold (bootEvs s) n = some p → s.pins n = some ⟨[p], some p⟩

/-- What holds at each point of a command while it holds the lock. -/
def PcInv (s : State Name Payload) (c : Cmd Name Payload) :
    Pc Name Payload → Prop
  | .undoPins m todo f => hasInit s = true ∧ m = fold (bootEvs s) ∧
      (f = false → ∀ n d, s.pins n = some d → n ∉ todo →
        ∃ q, d.xattr = some q ∧ m n = some q)
  | .undoArch m todo f => hasInit s = true ∧ m = fold (bootEvs s) ∧
      (f = false → Good m s.pins ∧
        ∀ k e, s.arch k = some e → e.labeled = true → e.byRoot = false →
          k ∉ todo → m e.name = some e.payload)
  | .acted => hasInit s = true ∧
      Good (fold (bootEvs s)) s.pins ∧ ArchGood (fold (bootEvs s)) s.arch
  | .made _ => ∀ n p, c = .load n p →
      s.pins n = some ⟨[], none⟩ ∧ fold (bootEvs s) n = none
  | .attached => ∀ n p, c = .load n p →
      s.pins n = some ⟨[p], none⟩ ∧ fold (bootEvs s) n = none
  | .xattrDone => ∀ n p, c = .load n p →
      s.pins n = some ⟨[p], some p⟩ ∧ fold (bootEvs s) n = none
  | .persisted => ∀ n p, c = .load n p →
      s.pins n = some ⟨[p], some p⟩ ∧ fold (bootEvs s) n = none
  | .extended => ∀ n p, c = .load n p →
      s.pins n = some ⟨[p], some p⟩ ∧ fold (bootEvs s) n = none
  | .detach => fold (bootEvs s) c.name = none
  | _ => True

/-- The pins are well formed, the records hold only what is pinned, and
every command is where its point says. -/
def WF (s : State Name Payload) : Prop :=
  I1 s.pins ∧ Recorded s ∧ ∀ i c, s.procs i = some c → PcInv s c.cmd c.pc

theorem pcInv_of_not_holds (s : State Name Payload) {c : Cmd Name Payload}
    {pc : Pc Name Payload} (h : holds c pc = false) : PcInv s c pc := by
  cases pc <;> simp_all [holds, PcInv]

/-- A step that leaves the pins and the log alone and only removes archive
files shirudo wrote. -/
def Shrinks (s s' : State Name Payload) : Prop :=
  s'.boot = s.boot ∧ s'.log = s.log ∧ s'.pins = s.pins ∧
  (∀ k e, s'.arch k = some e → e.labeled = true → e.byRoot = false →
    s.arch k = some e)

theorem Shrinks.mk' {s s' : State Name Payload} (hb : s'.boot = s.boot)
    (hl : s'.log = s.log) (hp : s'.pins = s.pins) (ha : s'.arch = s.arch) :
    Shrinks s s' :=
  ⟨hb, hl, hp, fun k e h _ _ => by rwa [ha] at h⟩

theorem sub_upd_none (f : Name → Option α) (n : Name) :
    ∀ m d, upd f n none m = some d → f m = some d := by
  intro m d h
  by_cases hm : m = n
  · subst hm; simp at h
  · rwa [upd_ne _ _ hm] at h

theorem sub_ite_upd_none (b : Bool) (f : Name → Option α) (n : Name) :
    ∀ m d, (if b then upd f n none else f) m = some d → f m = some d := by
  cases b
  · intro m d h; exact h
  · exact sub_upd_none f n

theorem asub_of_sub {f g : Arch Name Payload}
    (h : ∀ k e, g k = some e → f k = some e) :
    ∀ k e, g k = some e → e.labeled = true → e.byRoot = false →
      f k = some e :=
  fun k e he _ _ => h k e he

theorem I1.shrink {p p' : Pins Name Payload} (h : I1 p)
    (hs : ∀ n d, p' n = some d → p n = some d) : I1 p' :=
  fun n d hd => h n d (hs n d hd)

theorem I1.upd {p : Pins Name Payload} (h : I1 p) (n : Name) {d : Pin Payload}
    (hd : d.links.length ≤ 1 ∧ ∀ q, d.xattr = some q → d.links = [q]) :
    I1 (upd p n (some d)) := by
  intro m d' hm
  by_cases hmn : m = n
  · subst hmn; simp at hm; subst hm; exact hd
  · rw [upd_ne _ _ hmn] at hm; exact h m d' hm

theorem PcInv.shrink {s s' : State Name Payload} (hS : Shrinks s s')
    {c : Cmd Name Payload} {pc : Pc Name Payload} (h : PcInv s c pc) :
    PcInv s' c pc := by
  obtain ⟨hb, hl, hp, ha⟩ := hS
  have hbe := bootEvs_congr hb hl
  have hhi := hasInit_congr hb hl
  cases pc with
  | undoPins m todo f =>
    obtain ⟨h1, h2, h3⟩ := h
    show hasInit s' = true ∧ _ ∧ _
    rw [hhi, hbe, hp]
    exact ⟨h1, h2, h3⟩
  | undoArch m todo f =>
    obtain ⟨h1, h2, h3⟩ := h
    show hasInit s' = true ∧ _ ∧ _
    rw [hhi, hbe, hp]
    refine ⟨h1, h2, fun hf => ?_⟩
    obtain ⟨hg, ha'⟩ := h3 hf
    exact ⟨hg, fun k e he hlab hr hk => ha' k e (ha k e he hlab hr) hlab hr hk⟩
  | acted =>
    obtain ⟨h1, hg, ha'⟩ := h
    show hasInit s' = true ∧ _ ∧ _
    rw [hhi, hbe, hp]
    exact ⟨h1, hg, fun k e he hlab hr => ha' k e (ha k e he hlab hr) hlab hr⟩
  | made b => intro n p hc; rw [hbe, hp]; exact h n p hc
  | attached => intro n p hc; rw [hbe, hp]; exact h n p hc
  | xattrDone => intro n p hc; rw [hbe, hp]; exact h n p hc
  | persisted => intro n p hc; rw [hbe, hp]; exact h n p hc
  | extended => intro n p hc; rw [hbe, hp]; exact h n p hc
  | detach => show fold (bootEvs s') c.name = none; rw [hbe]; exact h
  | start => trivial
  | unlinkArch => trivial
  | purgeWait q => trivial
  | purgeAppend q => trivial

theorem Recorded.shrink {s s' : State Name Payload} (hS : Shrinks s s')
    (h : Recorded s) : Recorded s' := by
  intro n p hn
  rw [bootEvs_congr hS.1 hS.2.1] at hn
  rw [hS.2.2.1]
  exact h n p hn

/-- A step of process `i` that leaves the pins and the log alone. -/
theorem WF.of_shrink {s s' : State Name Payload} {i : Nat} (hw : WF s)
    (hS : Shrinks s s') (hother : ∀ j, j ≠ i → s'.procs j = s.procs j)
    (hown : (∀ c, s.procs i = some c → PcInv s c.cmd c.pc) →
      ∀ c, s'.procs i = some c → PcInv s' c.cmd c.pc) : WF s' := by
  obtain ⟨hI1, hR, hP⟩ := hw
  refine ⟨by rw [hS.2.2.1]; exact hI1, hR.shrink hS, fun j c hj => ?_⟩
  by_cases hji : j = i
  · subst hji; exact hown (hP j) c hj
  · rw [hother j hji] at hj; exact (hP j c hj).shrink hS

/-- A step of root's that leaves the pins and the log alone. -/
theorem WF.of_shrink_all {s s' : State Name Payload} (hw : WF s)
    (hS : Shrinks s s') (hprocs : s'.procs = s.procs) : WF s' := by
  obtain ⟨hI1, hR, hP⟩ := hw
  refine ⟨by rw [hS.2.2.1]; exact hI1, hR.shrink hS, fun j c hj => ?_⟩
  rw [hprocs] at hj
  exact (hP j c hj).shrink hS

/-- A step of the lock holder: every other command is at its start. -/
theorem WF.of_holder {s s' : State Name Payload} {i : Nat}
    {c : Proc Name Payload} (hl : LockInv s.procs s.lock)
    (hi : s.procs i = some c) (hc : holds c.cmd c.pc = true)
    (hother : ∀ j, j ≠ i → s'.procs j = s.procs j)
    (hown : I1 s'.pins ∧ Recorded s' ∧
      ∀ c', s'.procs i = some c' → PcInv s' c'.cmd c'.pc) : WF s' := by
  obtain ⟨hI1, hR, hP⟩ := hown
  refine ⟨hI1, hR, fun j c' hj => ?_⟩
  by_cases hji : j = i
  · subst hji; exact hP c' hj
  · rw [hother j hji] at hj
    cases hh : holds c'.cmd c'.pc with
    | false => exact pcInv_of_not_holds s' hh
    | true =>
      have h1 := hl.1 _ _ hi hc
      have h2 := hl.1 _ _ hj hh
      rw [h1] at h2; cases h2; exact absurd rfl hji

theorem own_go {s s' : State Name Payload} {i : Nat} {c : Cmd Name Payload}
    {pc : Pc Name Payload} (hp : s'.procs = upd s.procs i (some ⟨c, pc⟩))
    (h : PcInv s' c pc) :
    ∀ c', s'.procs i = some c' → PcInv s' c'.cmd c'.pc := by
  intro c' hc'
  rw [hp] at hc'
  simp at hc'
  subst hc'
  exact h

theorem own_exit {s s' : State Name Payload} {i : Nat}
    (hp : s'.procs = upd s.procs i none) :
    ∀ c', s'.procs i = some c' → PcInv s' c'.cmd c'.pc := by
  intro c' hc'
  rw [hp] at hc'
  simp at hc'

theorem hasInit_snoc (s s' : State Name Payload) (e : Ev Name Payload)
    (he : e.isInit = false)
    (hb : s'.boot = s.boot) (hl : s'.log = s.log ++ [⟨s.boot, e⟩]) :
    hasInit s' = hasInit s := by
  simp [hasInit, bootEvs_snoc s _ e rfl s' hb hl, he]

theorem fold_snoc (l : List (Ev Name Payload)) (e : Ev Name Payload) :
    fold (l ++ [e]) = applyEv (fold l) e := by
  simp [fold, List.foldl_append]

theorem fold_of_measuredBoot {s : State Name Payload}
    {m : Measured Name Payload}
    (h : measuredBoot s = some m) : m = fold (bootEvs s) := by
  unfold measuredBoot at h
  split at h
  · cases h; rfl
  · cases h

theorem hasInit_of_measuredBoot {s : State Name Payload}
    {m : Measured Name Payload} (h : measuredBoot s = some m) :
    hasInit s = true := by
  unfold measuredBoot at h
  split at h
  · assumption
  · cases h

theorem pinUnmeasured_false {m : Measured Name Payload} {n : Name}
    {d : Pin Payload} (h : pinUnmeasured m n (some d) = false) :
    ∃ q, d.xattr = some q ∧ m n = some q := by
  simp only [pinUnmeasured, Bool.not_eq_false'] at h
  cases hx : d.xattr with
  | none => rw [hx] at h; simp [held] at h
  | some q => rw [hx] at h; exact ⟨q, rfl, by simpa [held] using h⟩

theorem archUnmeasured_false {m : Measured Name Payload}
    {e : Entry Name Payload}
    (h : archUnmeasured m (some e) = false) (hl : e.labeled = true) :
    m e.name = some e.payload := by
  simp only [archUnmeasured, hl, Bool.true_and, Bool.not_eq_false'] at h
  simpa using h

theorem I1_of_restore {f : Bool} {mL : Measured Name Payload}
    {arch : Arch Name Payload} {ks : List Name}
    {pins : Pins Name Payload} {set : List (Name × Payload)}
    (h : restore f mL arch ks = some (pins, set)) : I1 pins := by
  have := restore_shape f mL arch ks (fun _ => none, [])
    (by intro n d h; simp at h) _ h
  intro n d hd
  obtain ⟨q, hq⟩ := this n d hd
  subst hq
  refine ⟨by simp, fun q' hq' => ?_⟩
  cases hq'
  rfl

/-- A name the records hold is pinned, so one unpinned is not on record. -/
theorem Recorded.of_unpinned {s : State Name Payload} (h : Recorded s)
    {n : Name}
    (hn : s.pins n = none) : fold (bootEvs s) n = none := by
  cases hf : fold (bootEvs s) n with
  | none => rfl
  | some p => rw [h n p hf] at hn; cases hn

/-- An undo pass removes only what the records do not hold. -/
theorem Recorded.unmeasured {s : State Name Payload} (h : Recorded s)
    {m : Measured Name Payload} (hm : m = fold (bootEvs s)) {n : Name}
    (hu : pinUnmeasured m n (s.pins n) = true) : fold (bootEvs s) n = none := by
  cases hf : fold (bootEvs s) n with
  | none => rfl
  | some p =>
    rw [h n p hf] at hu
    subst hm
    simp [pinUnmeasured, held, hf] at hu

/-- Pins of names not on record may change. -/
theorem Recorded.of_pins {s s' : State Name Payload} (h : Recorded s)
    (hb : s'.boot = s.boot) (hl : s'.log = s.log)
    (hp : ∀ m, fold (bootEvs s) m ≠ none → s'.pins m = s.pins m) :
    Recorded s' := by
  intro n p hn
  rw [bootEvs_congr hb hl] at hn
  rw [hp n (by rw [hn]; simp)]
  exact h n p hn

theorem pins_upd_off {s : State Name Payload} {n : Name}
    (hn : fold (bootEvs s) n = none) (o : Option (Pin Payload)) :
    ∀ m, fold (bootEvs s) m ≠ none → upd s.pins n o m = s.pins m := by
  intro m hm
  have : m ≠ n := by intro e; subst e; exact hm hn
  exact upd_ne _ _ this

theorem undoLoad_pins_off (s : State Name Payload) {n : Name}
    (hn : fold (bootEvs s) n = none) (out : UndoOut) :
    ∀ m, fold (bootEvs s) m ≠ none → (s.undoLoad n out).pins m = s.pins m := by
  intro m hm
  cases out
  · exact pins_upd_off hn none m hm
  · exact pins_upd_off hn none m hm
  · rfl

theorem fold_boot_snoc {s s' : State Name Payload} {e : Ev Name Payload}
    (hb : s'.boot = s.boot) (hl : s'.log = s.log ++ [⟨s.boot, e⟩]) :
    fold (bootEvs s') = applyEv (fold (bootEvs s)) e := by
  rw [bootEvs_snoc s _ e rfl s' hb hl, fold_snoc]

/-- An unload's or a purge's record takes the name off the records. -/
theorem fold_unload {s s' : State Name Payload} {n : Name} {q : Payload}
    (hb : s'.boot = s.boot) (hl : s'.log = s.log ++ [⟨s.boot, .unload n q⟩]) :
    fold (bootEvs s') n = none := by
  rw [fold_boot_snoc hb hl]
  simp [applyEv]

theorem Recorded.unload {s s' : State Name Payload} (h : Recorded s)
    {n : Name} {q : Payload} (hb : s'.boot = s.boot)
    (hl : s'.log = s.log ++ [⟨s.boot, .unload n q⟩]) (hp : s'.pins = s.pins) :
    Recorded s' := by
  intro n' p' hn'
  rw [fold_boot_snoc hb hl] at hn'
  simp only [applyEv] at hn'
  rw [hp]
  by_cases hnn : n' = n
  · subst hnn; simp at hn'
  · rw [upd_ne _ _ hnn] at hn'; exact h n' p' hn'

/-- A load's record names what its pins hold. -/
theorem Recorded.load {s s' : State Name Payload} (h : Recorded s)
    {n : Name} {p : Payload} (hb : s'.boot = s.boot)
    (hl : s'.log = s.log ++ [⟨s.boot, .load n p⟩]) (hp : s'.pins = s.pins)
    (hpin : s.pins n = some ⟨[p], some p⟩) : Recorded s' := by
  intro n' p' hn'
  rw [fold_boot_snoc hb hl] at hn'
  simp only [applyEv] at hn'
  rw [hp]
  by_cases hnn : n' = n
  · subst hnn; simp at hn'; subst hn'; exact hpin
  · rw [upd_ne _ _ hnn] at hn'; exact h n' p' hn'

/-- Every step keeps the pins well formed, the records covered by the
pins, and each command where its point says. -/
theorem wf_step {s s' : State Name Payload} (hl : LockInv s.procs s.lock)
    (hbound : ∀ r ∈ s.log, r.boot ≤ s.boot) (hw : WF s) (hs : Step C s s') :
    WF s' := by
  have hI1 := hw.1
  have hR := hw.2.1
  have hP := hw.2.2
  cases hs with
  | spawn i c hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl trivial)
  | bailStart i c hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | bailActed i c hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | kill i c hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | lockUndo i c m todo hi hc hcan hu hm hcov =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl ⟨hasInit_of_measuredBoot hm,
        fold_of_measuredBoot hm, fun _ n d hd hn => absurd
          (hcov n (by rw [show s.pins n = some d from hd]; simp)) hn⟩)
  | lockSkip i c hi hc hcan hu => simp [C] at hu
  | undoKeep i c m n todo f hi hk =>
    refine hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun hP' => own_go rfl ?_)
    obtain ⟨h1, hm, hg⟩ := hP' _ hi
    refine ⟨h1, hm, fun hf n' d hd hn' => ?_⟩
    by_cases hnn : n' = n
    · subst hnn
      rw [show s.pins n' = some d from hd] at hk
      exact pinUnmeasured_false hk
    · exact hg hf n' d hd (by simp [hnn, hn'])
  | undoRemove i c m n todo f out hi hrem =>
    obtain ⟨h1, hm, hg⟩ := hP i _ hi
    have hn := hR.unmeasured hm hrem
    refine WF.of_holder hl hi rfl (fun j hj => by simp [upd_ne _ _ hj]) ⟨?_, ?_,
      own_go (s := s) (c := c) (pc := .undoPins m todo (f || out.failed))
        (by simp) ?_⟩
    · exact hI1.shrink (fun m d hd => undoLoad_pins_sub s n out m d hd)
    · exact hR.of_pins (by simp) (by simp) (undoLoad_pins_off s hn out)
    · refine ⟨(hasInit_congr (s := s) (by simp) (by simp)).trans h1,
        hm.trans (congrArg fold
          (bootEvs_congr (s := s) (by simp) (by simp)).symm),
        fun hf n' d hd hn' => ?_⟩
      simp only [Bool.or_eq_false_iff] at hf
      obtain ⟨hf, ho⟩ := hf
      cases out with
      | ok =>
        have hnn : n' ≠ n := by
          intro e; subst e; simp [State.undoLoad] at hd
        have hd' : s.pins n' = some d := sub_upd_none _ _ n' d hd
        exact hg hf n' d hd' (by simp [hnn, hn'])
      | archFail => simp [UndoOut.failed] at ho
      | pinFail => simp [UndoOut.failed] at ho
  | undoPinsDone i c m f todo hi hcov =>
    refine hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun hP' => own_go rfl ?_)
    obtain ⟨h1, hm, hg⟩ := hP' _ hi
    exact ⟨h1, hm, fun hf => ⟨fun n d hd => hg hf n d hd (List.not_mem_nil),
      fun k e he _ _ hk => absurd
        (hcov k (by rw [show s.arch k = some e from he]; simp)) hk⟩⟩
  | undoArchKeep i c m k todo f hi hk =>
    refine hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun hP' => own_go rfl ?_)
    obtain ⟨h1, hm, hg⟩ := hP' _ hi
    refine ⟨h1, hm, fun hf => ⟨(hg hf).1, fun k' e he hlab hr hk' => ?_⟩⟩
    by_cases hkk : k' = k
    · subst hkk
      rw [show s.arch k' = some e from he] at hk
      exact archUnmeasured_false hk hlab
    · exact (hg hf).2 k' e he hlab hr (by simp [hkk, hk'])
  | undoArchRemove i c m k todo f ok hi hrem =>
    refine hw.of_shrink
      ⟨rfl, rfl, rfl, asub_of_sub (sub_ite_upd_none ok _ _)⟩ upd_others
      (fun hP' => own_go rfl ?_)
    obtain ⟨h1, hm, hg⟩ := hP' _ hi
    refine ⟨h1, hm, fun hf => ?_⟩
    simp only [Bool.or_eq_false_iff, Bool.not_eq_false'] at hf
    obtain ⟨hf, hok⟩ := hf
    subst hok
    refine ⟨(hg hf).1, fun k' e he hlab hr hk' => ?_⟩
    have hkk : k' ≠ k := by
      intro e'; subst e'; simp at he
    have he' : s.arch k' = some e := sub_upd_none _ _ k' e he
    exact (hg hf).2 k' e he' hlab hr (by simp [hkk, hk'])
  | undoArchDone i c m f hi hf =>
    refine hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun hP' => own_go rfl ?_)
    obtain ⟨h1, hm, hg⟩ := hP' _ hi
    have hf : f = false := by
      rcases hf with hf | hf
      · exact hf
      · simp [C] at hf
    obtain ⟨hgood, ha⟩ := hg hf
    subst hm
    exact ⟨h1, hgood,
      fun k e he hlab hr => ha k e he hlab hr (List.not_mem_nil)⟩
  | undoRefuse i c m todo f hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | undoAbort i c m todo f hi hr => simp [C] at hr
  | loadMkdir i n p hi hx =>
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others ?_
    obtain ⟨-, hgood, -⟩ := hP i _ hi
    have hnone : s.pins n = none := by
      cases h : s.pins n with
      | none => rfl
      | some d =>
        obtain ⟨q, hq, _⟩ := hgood n d h
        rw [hx d h] at hq; cases hq
    have hf := hR.of_unpinned hnone
    refine ⟨?_, hR.of_pins rfl rfl (pins_upd_off hf _), own_go rfl ?_⟩
    · simpa [hnone] using hI1.upd n (d := ⟨[], none⟩) (by simp)
    · intro n' p' hc
      cases hc
      exact ⟨by simp [hnone], hf⟩
  | loadAttach i n p b d hi hd =>
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others ?_
    obtain ⟨hpin, hf⟩ := hP i _ hi n p rfl
    rw [hpin] at hd
    cases hd
    refine ⟨hI1.upd n (by simp), hR.of_pins rfl rfl (pins_upd_off hf _),
      own_go rfl ?_⟩
    intro n' p' hc
    cases hc
    exact ⟨by simp, hf⟩
  | loadAttachFail i n p b hi =>
    obtain ⟨-, hf⟩ := hP i _ hi n p rfl
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others
      ⟨hI1.shrink (sub_ite_upd_none b _ _), hR.of_pins rfl rfl ?_, own_exit rfl⟩
    intro m hm
    cases b
    · rfl
    · exact pins_upd_off hf none m hm
  | loadXattr i n p hi =>
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others ?_
    obtain ⟨hpin, hf⟩ := hP i _ hi n p rfl
    refine ⟨?_, hR.of_pins rfl rfl (pins_upd_off hf _), own_go rfl ?_⟩
    · show I1 (upd s.pins n ((s.pins n).map fun d => ⟨d.links, some p⟩))
      rw [hpin]
      exact hI1.upd n (by simp)
    · intro n' p' hc
      cases hc
      exact ⟨by simp [hpin], hf⟩
  | loadXattrFail i n p removed hi hu =>
    obtain ⟨-, hf⟩ := hP i _ hi n p rfl
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others
      ⟨hI1.shrink (sub_ite_upd_none removed _ _), hR.of_pins rfl rfl ?_,
        own_exit rfl⟩
    intro m hm
    cases removed
    · rfl
    · exact pins_upd_off hf none m hm
  | loadXattrIgnore i n p hi hu => simp [C] at hu
  | loadPersist i n p hi =>
    refine WF.of_holder hl hi (holds_load n p (by simp)) upd_others
      ⟨hI1, hR.of_pins rfl rfl (fun _ _ => rfl), own_go rfl ?_⟩
    exact fun n' p' hc => by cases hc; exact hP i _ hi n p rfl
  | loadPersistFail i n p wrote out hi =>
    obtain ⟨-, hf⟩ := hP i _ hi n p rfl
    refine WF.of_holder hl hi (holds_load n p (by simp))
      (fun j hj => by simp [upd_ne _ _ hj])
      ⟨hI1.shrink (fun m d hd => by
          have := undoLoad_pins_sub _ n out m d hd; simpa using this),
        hR.of_pins (by simp) (by simp) ?_, own_exit (s := s) (by simp)⟩
    intro m hm
    have := undoLoad_pins_off ({ s with
      arch := if wrote then upd s.arch n (some ⟨n, p, true, false⟩)
              else s.arch }) hf out m hm
    simpa using this
  | loadExtend i n p hi hinit =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun hP' => own_go rfl fun n' p' hc => by
        cases hc; exact hP' _ hi n p rfl)
  | loadExtendFail i n p after out hi hh =>
    obtain ⟨-, hf⟩ := hP i _ hi n p rfl
    refine WF.of_holder hl hi (holds_load n p (by simp))
      (fun j hj => by simp [upd_ne _ _ hj])
      ⟨hI1.shrink (fun m d hd => by
          have := undoLoad_pins_sub _ n out m d hd; simpa using this),
        hR.of_pins (by simp) (by simp) ?_, own_exit (s := s) (i := i) (by simp)⟩
    intro m hm
    have := undoLoad_pins_off ({ s with
      reg := if after then s.reg ++ [.load n p] else s.reg,
      lost := if after then s.lost + 1 else s.lost }) hf out m hm
    simpa using this
  | loadAppend i n p hi =>
    obtain ⟨hpin, -⟩ := hP i _ hi n p rfl
    exact WF.of_holder hl hi (holds_load n p (by simp)) upd_others
      ⟨hI1, hR.load rfl rfl rfl hpin, own_exit rfl⟩
  | loadAppendFail i n p hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | unloadGone i n p ok hi hn =>
    exact hw.of_shrink
      ⟨rfl, rfl, rfl, asub_of_sub (sub_ite_upd_none ok _ _)⟩ upd_others
      (fun _ => own_exit rfl)
  | unloadExtend i n p d hi hd hx hinit =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl (fun n' p' hc => by cases hc))
  | unloadExtendFail i n p d after hi hd hx hh =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | unloadAppend i n p hi =>
    exact WF.of_holder hl hi (holds_unload n p (by simp)) upd_others
      ⟨hI1, hR.unload rfl rfl rfl, own_go rfl (fold_unload (s := s) rfl rfl)⟩
  | unloadAppendFail i n p hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | detach i c hi =>
    have hf : fold (bootEvs s) c.name = none := hP i _ hi
    exact WF.of_holder hl hi rfl upd_others
      ⟨hI1.shrink (sub_upd_none _ _), hR.of_pins rfl rfl (pins_upd_off hf _),
        own_go rfl trivial⟩
  | detachFail i c hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | unlinkArch i c ok hi =>
    exact hw.of_shrink
      ⟨rfl, rfl, rfl, asub_of_sub (sub_ite_upd_none ok _ _)⟩ upd_others
      (fun _ => own_exit rfl)
  | purgeRead i n e hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl trivial)
  | purgeArchOnly i n e hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl trivial)
  | purgeExtend i n q hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_go rfl trivial)
  | purgeExtendFail i n q after hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | purgeAppend i n q hi =>
    exact WF.of_holder hl hi (c := ⟨.purge n, .purgeAppend q⟩) rfl
      upd_others
      ⟨hI1, hR.unload rfl rfl rfl, own_go rfl (fold_unload (s := s) rfl rfl)⟩
  | purgeAppendFail i n q hi =>
    exact hw.of_shrink (Shrinks.mk' rfl rfl rfl rfl) upd_others
      (fun _ => own_exit rfl)
  | rootAdd k e hlab hk =>
    refine hw.of_shrink_all ⟨rfl, rfl, rfl, fun k' e' he' hl' _ => ?_⟩ rfl
    replace he' : upd s.arch k (some e) k' = some e' := he'
    by_cases hkk : k' = k
    · subst hkk; simp at he'; subst he'; rw [hlab] at hl'; cases hl'
    · rwa [upd_ne _ _ hkk] at he'
  | rootDel k e he hlab =>
    exact hw.of_shrink_all
      ⟨rfl, rfl, rfl, asub_of_sub (sub_upd_none _ _)⟩ rfl
  | rootBring k e hk hr =>
    refine hw.of_shrink_all ⟨rfl, rfl, rfl, fun k' e' he' _ hr' => ?_⟩ rfl
    replace he' : upd s.arch k (some e) k' = some e' := he'
    by_cases hkk : k' = k
    · subst hkk; simp at he'; subst he'; rw [hr] at hr'; cases hr'
    · rwa [upd_ne _ _ hkk] at he'
  | rebootOk ks pins set hks hr =>
    obtain ⟨hp, hset⟩ := restore_exact (measuredLog s) s.arch ks hks hr
    refine ⟨I1_of_restore hr, ?_, fun j c hj => by simp [booted] at hj⟩
    intro n p hn
    rw [bootEvs_booted_new hbound, fold_init, hset n] at hn
    show pins n = _
    rcases hp n with ⟨hn', -⟩ | ⟨q, hn', -⟩
    · rw [hn'] at hn; cases hn
    · rw [hn'] at hn ⊢; cases hn; rfl
  | rebootFail pins set bound hp =>
    refine ⟨fun n d hd => ?_, ?_, fun j c hj => by simp [booted] at hj⟩
    · obtain ⟨q, hq, hx⟩ := hp n d hd
      refine ⟨by simp [hq], fun q' hq' => ?_⟩
      rcases hx with hx | hx
      · rw [hx] at hq'; cases hq'
      · rw [hx] at hq'; cases hq'; exact hq
    · intro n p hn
      rw [bootEvs_booted_old hbound] at hn
      cases hn

/-! ### The gate -/

/-- Every command runs in a boot whose init record is on the log. -/
def GateInv (s : State Name Payload) : Prop :=
  ∀ i c, s.procs i = some c → hasInit s = true

theorem GateInv.of_move {s s' : State Name Payload} (h : GateInv s)
    {i : Nat} {c : Proc Name Payload} {o : Option (Proc Name Payload)}
    (hi : s.procs i = some c) (hp : s'.procs = upd s.procs i o)
    (hhas : hasInit s = true → hasInit s' = true) : GateInv s' := by
  intro j c' hj
  rw [hp] at hj
  by_cases hji : j = i
  · subst hji; exact hhas (h j c hi)
  · rw [upd_ne _ _ hji] at hj; exact hhas (h j c' hj)

theorem hasInit_snoc_true {s s' : State Name Payload} {e : Ev Name Payload}
    (h : hasInit s = true) (he : e.isInit = false) (hb : s'.boot = s.boot)
    (hl : s'.log = s.log ++ [⟨s.boot, e⟩]) : hasInit s' = true := by
  rwa [hasInit_snoc s s' e he hb hl]

theorem gateInv_step {s s' : State Name Payload} (h : GateInv s)
    (hs : Step C s s') : GateInv s' := by
  cases hs with
  | spawn i c hi hg =>
    intro j c' hj
    by_cases hji : j = i
    · exact hg rfl
    · rw [show (s.go i c .start).procs j = s.procs j from upd_ne _ _ hji] at hj
      exact h j c' hj
  | loadPersistFail i n p wrote out hi =>
    exact h.of_move (o := none) hi (by simp) fun hh =>
      (hasInit_congr (s := s) (by simp) (by simp)).trans hh
  | loadExtendFail i n p after out hi =>
    exact h.of_move (o := none) hi (by simp) fun hh =>
      (hasInit_congr (s := s) (by simp) (by simp)).trans hh
  | undoRemove i c m n todo f out hi =>
    exact h.of_move (o := some ⟨c, .undoPins m todo (f || out.failed)⟩) hi
      (by simp) fun hh =>
      (hasInit_congr (s := s) (by simp) (by simp)).trans hh
  | loadAppend i n p hi =>
    exact h.of_move hi rfl fun hh =>
      hasInit_snoc_true hh (e := .load n p) rfl rfl rfl
  | unloadAppend i n p hi =>
    exact h.of_move hi rfl fun hh =>
      hasInit_snoc_true hh (e := .unload n p) rfl rfl rfl
  | purgeAppend i n q hi =>
    exact h.of_move hi rfl fun hh =>
      hasInit_snoc_true hh (e := .unload n q) rfl rfl rfl
  | rootAdd => exact h
  | rootDel => exact h
  | rootBring => exact h
  | rebootOk => intro j c hj; simp [booted] at hj
  | rebootFail => intro j c hj; simp [booted] at hj
  | undoAbort i c m todo f hi =>
    rcases hi with hi | hi <;> exact h.of_move hi rfl id
  | undoRefuse i c m todo f hi =>
    rcases hi with hi | hi <;> exact h.of_move hi rfl id
  | bailStart i c hi => exact h.of_move hi rfl id
  | bailActed i c hi => exact h.of_move hi rfl id
  | kill i c hi => exact h.of_move hi rfl id
  | lockUndo i c m todo hi => exact h.of_move hi rfl id
  | lockSkip i c hi => exact h.of_move hi rfl id
  | undoKeep i c m n todo f hi => exact h.of_move hi rfl id
  | undoPinsDone i c m f todo hi => exact h.of_move hi rfl id
  | undoArchKeep i c m k todo f hi => exact h.of_move hi rfl id
  | undoArchRemove i c m k todo f ok hi => exact h.of_move hi rfl id
  | undoArchDone i c m f hi => exact h.of_move hi rfl id
  | loadMkdir i n p hi => exact h.of_move hi rfl id
  | loadAttach i n p b d hi => exact h.of_move hi rfl id
  | loadAttachFail i n p b hi => exact h.of_move hi rfl id
  | loadXattr i n p hi => exact h.of_move hi rfl id
  | loadXattrFail i n p removed hi => exact h.of_move hi rfl id
  | loadXattrIgnore i n p hi => exact h.of_move hi rfl id
  | loadPersist i n p hi => exact h.of_move hi rfl id
  | loadExtend i n p hi => exact h.of_move hi rfl id
  | loadAppendFail i n p hi => exact h.of_move hi rfl id
  | unloadGone i n p ok hi => exact h.of_move hi rfl id
  | unloadExtend i n p d hi => exact h.of_move hi rfl id
  | unloadExtendFail i n p d after hi => exact h.of_move hi rfl id
  | unloadAppendFail i n p hi => exact h.of_move hi rfl id
  | detach i c hi => exact h.of_move hi rfl id
  | detachFail i c hi => exact h.of_move hi rfl id
  | unlinkArch i c ok hi => exact h.of_move hi rfl id
  | purgeRead i n e hi => exact h.of_move hi rfl id
  | purgeArchOnly i n e hi => exact h.of_move hi rfl id
  | purgeExtend i n q hi => exact h.of_move hi rfl id
  | purgeExtendFail i n q after hi => exact h.of_move hi rfl id
  | purgeAppendFail i n q hi => exact h.of_move hi rfl id

/-! ### The theorems -/

/-- What every reachable state of `C` satisfies. -/
structure Inv (s : State Name Payload) : Prop where
  lock : LockInv s.procs s.lock
  reg : RegInv s
  wf : WF s
  gate : GateInv s

theorem inv_s0 : Inv (s0 : State Name Payload) := by
  refine ⟨LockInv.empty,
    ⟨fun r hr => (by cases hr), [], ?_, ?_, Or.inl ⟨rfl, ?_⟩⟩,
    ⟨fun n d h => ?_, fun n p h => ?_, fun i c h => ?_⟩, fun i c h => ?_⟩
  · simp [bootEvs, s0]
  · simp [bootEvs, s0]
  · intro i c h; simp [s0] at h
  · simp [s0] at h
  · simp [bootEvs, fold, s0] at h
  · simp [s0] at h
  · simp [s0] at h

theorem inv_step {s s' : State Name Payload} (h : Inv s) (hs : Step C s s') :
    Inv s' :=
  ⟨lockInv_step h.lock hs, regInv_step h.lock h.reg hs,
    wf_step h.lock h.reg.1 h.wf hs, gateInv_step h.gate hs⟩

theorem reach_inv {s : State Name Payload} (h : Reach C s) : Inv s := by
  induction h with
  | init => exact inv_s0
  | step _ hs ih => exact inv_step ih hs

/-- `image_enter()` admits upatch commands only in a boot whose init
record is on the log. -/
theorem commands_need_init {s : State Name Payload} (h : Reach C s) {i : Nat}
    {c : Proc Name Payload} (hi : s.procs i = some c) : hasInit s = true :=
  (reach_inv h).gate i c hi

/-- Once an upatch command's undo pass is done, every pin directory holds
one link, of the payload its xattr names and this boot's measured set
holds, and every labeled archive file shirudo wrote is one the measured
set holds. -/
theorem undo_pass_sound {s : State Name Payload} (h : Reach C s) {i : Nat}
    {c : Cmd Name Payload} (hi : s.procs i = some ⟨c, .acted⟩) :
    measuredBoot s = some (fold (bootEvs s)) ∧
    (∀ n d, s.pins n = some d →
      ∃ q, d.links = [q] ∧ d.xattr = some q ∧ fold (bootEvs s) n = some q) ∧
    (∀ k e, s.arch k = some e → e.labeled = true → e.byRoot = false →
      fold (bootEvs s) e.name = some e.payload) := by
  obtain ⟨hI1, -, hP⟩ := (reach_inv h).wf
  obtain ⟨hinit, hg, ha⟩ := hP i _ hi
  refine ⟨by simp [measuredBoot, hinit], fun n d hd => ?_, ha⟩
  obtain ⟨q, hq, hm⟩ := hg n d hd
  exact ⟨q, (hI1 n d hd).2 q hq, hq, hm⟩

/-- No name ever holds two links: nothing is loaded twice under one
name. -/
theorem loaded_once {s : State Name Payload} (h : Reach C s) :
    ∀ n d, s.pins n = some d → d.links.length ≤ 1 :=
  fun n d hd => (reach_inv h).wf.1 n d hd |>.1

/-- Whatever this boot's records hold as loaded runs: the name is pinned
with one link of that payload, under the xattr that names it. -/
theorem recorded_runs {s : State Name Payload} (h : Reach C s) :
    ∀ n p, fold (bootEvs s) n = some p → s.pins n = some ⟨[p], some p⟩ :=
  (reach_inv h).wf.2.1

/-- After a reboot whose `init` completes, the loaded upatches are
exactly the labeled archive files whose last record in the log is a load
of that name with that payload, each loaded once with its xattr, and the
new boot's measured set is exactly what was loaded. -/
theorem init_restores_exactly {s : State Name Payload} (h : Reach C s)
    {ks : List Name}
    (hks : ∀ k, s.arch k ≠ none → k ∈ ks) {pins : Pins Name Payload}
    {set : List (Name × Payload)}
    (hr : restore C.filter (measuredLog s) s.arch ks = some (pins, set))
    {s' : State Name Payload}
    (hs' : s' = booted s pins [.init set]
      (s.log ++ [⟨s.boot + 1, .init set⟩]) 0) :
    Step C s s' ∧
    (∀ n p, s'.pins n = some ⟨[p], some p⟩ ↔
      Wanted (measuredLog s) s.arch n p) ∧
    (∀ n, s'.pins n = none ↔ ∀ p, ¬ Wanted (measuredLog s) s.arch n p) ∧
    (∀ n d, s'.pins n = some d → ∃ p, d = ⟨[p], some p⟩) ∧
    (∃ m, measuredBoot s' = some m ∧
      ∀ n p, m n = some p ↔ Wanted (measuredLog s) s.arch n p) := by
  subst hs'
  have hbound := (reach_inv h).reg.1
  obtain ⟨hp, hset⟩ := restore_exact (measuredLog s) s.arch ks hks hr
  have hfun : ∀ n p q, Wanted (measuredLog s) s.arch n p →
      Wanted (measuredLog s) s.arch n q → p = q := by
    rintro n p q ⟨_, _, _, _, _, _, hp⟩ ⟨_, _, _, _, _, _, hq⟩
    rw [hp] at hq; cases hq; rfl
  have hbe := bootEvs_booted_new hbound pins [.init set] 0 (.init set)
  refine ⟨Step.rebootOk s ks pins set hks hr, fun n p => ?_, fun n => ?_,
    fun n d hd => ?_, ⟨fold [.init set],
      by simp [measuredBoot, hasInit, hbe, Ev.isInit], fun n p => ?_⟩⟩
  · show pins n = _ ↔ _
    rcases hp n with ⟨hn, hw⟩ | ⟨q, hn, hw⟩
    · rw [hn]; exact ⟨fun h => (by cases h), fun h => absurd h (hw p)⟩
    · rw [hn]
      constructor
      · intro h; cases h; exact hw
      · intro h; rw [hfun n q p hw h]
  · show pins n = none ↔ _
    rcases hp n with ⟨hn, hw⟩ | ⟨q, hn, hw⟩
    · exact ⟨fun _ => hw, fun _ => hn⟩
    · rw [hn]; exact ⟨fun h => (by cases h), fun h => absurd hw (h q)⟩
  · show ∃ p, d = _
    rcases hp n with ⟨hn, -⟩ | ⟨q, hn, -⟩
    · rw [show pins n = some d from hd] at hn; cases hn
    · rw [show pins n = some d from hd] at hn; cases hn; exact ⟨q, rfl⟩
  · rw [fold_init, hset n]
    rcases hp n with ⟨hn, hw⟩ | ⟨q, hn, hw⟩
    · rw [hn]; exact ⟨fun h => (by cases h), fun h => absurd h (hw p)⟩
    · rw [hn]
      constructor
      · intro h; cases h; exact hw
      · intro h; simp [hfun n q p hw h]

/-- This boot's records on the log are always a sublist of the
register's events: the log never shows an event the register lacks, nor
two events in another order than the register took them. -/
theorem log_sublist_register {s : State Name Payload} (h : Reach C s) :
    List.Sublist (bootEvs s) s.reg := by
  obtain ⟨-, X, hX, -, hd⟩ := (reach_inv h).reg
  rcases hd with ⟨hr, -⟩ | ⟨-, -, e, -, -, hr⟩
  · rw [hr]; exact hX
  · rw [hr]; exact hX.trans (List.sublist_append_left X [e])

/-- Once the lock is released, the register holds this boot's records and
`lost` more: the events whose append failed, whose extend failed after the
TPM took it, or whose process was killed between the two. -/
theorem register_length {s : State Name Payload} (h : Reach C s)
    (hfree : s.lock = none) :
    s.reg.length = (bootEvs s).length + s.lost := by
  have hi := reach_inv h
  obtain ⟨-, X, -, hlen, hd⟩ := hi.reg
  rcases hd with ⟨hr, -⟩ | ⟨i, c, e, hc, he, -⟩
  · rw [hr]; exact hlen
  · have := noInflight_of_free hi.lock hfree i c hc
    rw [he] at this; cases this

/-- Once the lock is released, the register and the log agree on this
boot's events exactly when no event went without its append. -/
theorem register_eq_log_iff {s : State Name Payload} (h : Reach C s)
    (hfree : s.lock = none) : s.reg = bootEvs s ↔ s.lost = 0 := by
  have hlen := register_length h hfree
  constructor
  · intro he; rw [he] at hlen; omega
  · intro h0
    rw [h0, Nat.add_zero] at hlen
    exact ((log_sublist_register h).eq_of_length hlen.symm).symm

/-- A disagreement is always detectable: with the register's hash and
the event encoding collision resistant as `Shirudo.Chain` assumes, the
replay of this boot's records differs from the register. -/
theorem replay_differs {D : Type} (H : D → D → D) (z : D)
    (enc : Ev Name Payload → D)
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d) (hz : ∀ a b, H a b ≠ z)
    (henc : ∀ a b, enc a = enc b → a = b) {s : State Name Payload}
    (hne : s.reg ≠ bootEvs s) :
    Chain.register H z (s.reg.map enc).reverse ≠
      Chain.register H z ((bootEvs s).map enc).reverse := by
  intro heq
  have h1 := Chain.register_injective H z hH hz _ _ heq
  have h2 : s.reg.map enc = (bootEvs s).map enc := by
    simpa using congrArg List.reverse h1
  exact hne (Chain.map_injective enc (fun a b h => henc a b h) _ _ h2)

/-! ### Variants that fail

Each variant drops one part of the protocol, and a sequence of steps from
a fresh install breaks the theorem that part carries. Names and payloads
are numbers here. -/

/-- The first boot: `init` with an empty archive. -/
theorem reach_boot1 (V : Variant) :
    Reach V (booted (s0 : State Nat Nat) (fun _ => none) [.init []]
      ([] ++ [⟨0 + 1, .init []⟩]) 0) :=
  Reach.step Reach.init
    (Step.rebootOk (s0 : State Nat Nat) [] (fun _ => none) []
      (fun _ h => absurd rfl h) rfl)

/-- Without the lock, `undo_pass_sound` fails: one load's undo pass lists
no pins, another load pins name 2, and the first pass ends with that
unrecorded pin left. -/
theorem undo_pass_needs_lock :
    ¬ ∀ s : State Nat Nat, Reach { lock := false } s → ∀ i c,
      s.procs i = some ⟨c, .acted⟩ → ∀ n d, s.pins n = some d →
        ∃ q, d.xattr = some q ∧ fold (bootEvs s) n = some q := by
  intro H
  have r1 := reach_boot1 { lock := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.spawn _ 1 (.load 2 5) rfl (fun _ => rfl))
  have r4 := r3.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inl rfl) rfl rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.lockUndo _ 1 (.load 2 5) _ []
    rfl rfl (Or.inl rfl) rfl rfl (fun _ h => absurd rfl h))
  have r6 := r5.step (.undoPinsDone _ 1 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r7 := r6.step (.undoArchDone _ 1 _ _ _ rfl (Or.inl rfl))
  have r8 := r7.step (.loadMkdir _ 1 2 5 rfl (fun _ h => by cases h))
  have r9 := r8.step (.loadAttach _ 1 2 5 _ _ rfl rfl)
  have r10 := r9.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r11 := r10.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  obtain ⟨q, hq, -⟩ := H _ r11 0 _ rfl 2 ⟨[5], none⟩ rfl
  cases hq

/-- Without the lock, the register and the log disagree with every
append done: two loads extend, extend, append, append, and the log
replays their events in the other order. -/
theorem log_needs_lock :
    ¬ ∀ s : State Nat Nat, Reach { lock := false } s → s.lock = none →
      (s.reg = bootEvs s ↔ s.lost = 0) := by
  intro H
  have r1 := reach_boot1 { lock := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.spawn _ 1 (.load 2 5) rfl (fun _ => rfl))
  have r4 := r3.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inl rfl) rfl rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.lockUndo _ 1 (.load 2 5) _ []
    rfl rfl (Or.inl rfl) rfl rfl (fun _ h => absurd rfl h))
  have r6 := r5.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r7 := r6.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  have r8 := r7.step (.undoPinsDone _ 1 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r9 := r8.step (.undoArchDone _ 1 _ _ _ rfl (Or.inl rfl))
  have r10 := r9.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r11 := r10.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r12 := r11.step (.loadXattr _ 0 1 5 rfl)
  have r13 := r12.step (.loadPersist _ 0 1 5 rfl)
  have r14 := r13.step (.loadMkdir _ 1 2 5 rfl (fun _ h => by cases h))
  have r15 := r14.step (.loadAttach _ 1 2 5 _ _ rfl rfl)
  have r16 := r15.step (.loadXattr _ 1 2 5 rfl)
  have r17 := r16.step (.loadPersist _ 1 2 5 rfl)
  have r18 := r17.step (.loadExtend _ 0 1 5 rfl rfl)
  have r19 := r18.step (.loadExtend _ 1 2 5 rfl rfl)
  have r20 := r19.step (.loadAppend _ 1 2 5 rfl)
  have r21 := r20.step (.loadAppend _ 0 1 5 rfl)
  have h := (H _ r21 rfl).2 rfl
  change [Ev.init [], .load 1 5, .load 2 5] =
    [Ev.init [], .load 2 5, .load 1 5] at h
  simp at h

/-- Without the undo pass, `undo_pass_sound` fails: a load killed between
its pins and its extend stays pinned past the next command's lock. -/
theorem undo_pass_needs_undo :
    ¬ ∀ s : State Nat Nat, Reach { undo := false } s → ∀ i c,
      s.procs i = some ⟨c, .acted⟩ → ∀ n d, s.pins n = some d →
        ∃ q, d.xattr = some q ∧ fold (bootEvs s) n = some q := by
  intro H
  have r1 := reach_boot1 { undo := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.lockSkip _ 0 (.load 1 5) rfl rfl
    (Or.inr rfl) (Or.inl rfl))
  have r4 := r3.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r5 := r4.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r6 := r5.step (.kill _ 0 _ rfl)
  have r7 := r6.step (.spawn _ 1 (.load 2 6) rfl (fun _ => rfl))
  have r8 := r7.step (.lockSkip _ 1 (.load 2 6) rfl rfl
    (Or.inr rfl) (Or.inl rfl))
  obtain ⟨q, hq, -⟩ := H _ r8 1 _ rfl 1 ⟨[5], none⟩ rfl
  cases hq

/-- Without the refusal, `loaded_once` fails: a load is killed between its
pins and its payload xattr, the next load of the name cannot read this
boot's records and goes on, reuses the directory, and its links, under
other names than the first load's, attach beside them. -/
theorem undo_needs_refusal :
    ¬ ∀ s : State Nat Nat, Reach { refuse := false } s →
      ∀ n d, s.pins n = some d → d.links.length ≤ 1 := by
  intro H
  have r1 := reach_boot1 { refuse := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inr rfl) rfl rfl (fun _ h => absurd rfl h))
  have r4 := r3.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  have r6 := r5.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r7 := r6.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r8 := r7.step (.kill _ 0 _ rfl)
  have r9 := r8.step (.spawn _ 1 (.load 1 7) rfl (fun _ => rfl))
  have r10 := r9.step (.lockSkip _ 1 (.load 1 7) rfl rfl
    (Or.inr rfl) (Or.inr rfl))
  have r11 := r10.step (.loadMkdir _ 1 1 7 rfl (fun _ h => by cases h; rfl))
  have r12 := r11.step (.loadAttach _ 1 1 7 _ _ rfl rfl)
  have := H _ r12 1 ⟨[7, 5], none⟩ rfl
  simp at this

/-- Without the gate and the refusal, `loaded_once` fails in a boot whose
`init` stopped before its record: every undo pass finds no record and goes
on, a load killed between its pins and its payload xattr stays, and a
second load of the name attaches beside it. Either part alone keeps it
out: the gate admits no upatch command into such a boot, and the refusal
stops one at `-ENOENT`. -/
theorem failed_init_needs_gate_or_refusal :
    ¬ ∀ s : State Nat Nat, Reach { gate := false, refuse := false } s →
      ∀ n d, s.pins n = some d → d.links.length ≤ 1 := by
  intro H
  have r1 := Reach.step (V := { gate := false, refuse := false }) Reach.init
    (Step.rebootFail (s0 : State Nat Nat) (fun _ => none) [] false
      (fun _ _ h => by cases h))
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun h => by cases h))
  have r3 := r2.step (.lockSkip _ 0 (.load 1 5) rfl rfl
    (Or.inr rfl) (Or.inr rfl))
  have r4 := r3.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r5 := r4.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r6 := r5.step (.kill _ 0 _ rfl)
  have r7 := r6.step (.spawn _ 1 (.load 1 7) rfl (fun h => by cases h))
  have r8 := r7.step (.lockSkip _ 1 (.load 1 7) rfl rfl
    (Or.inr rfl) (Or.inr rfl))
  have r9 := r8.step (.loadMkdir _ 1 1 7 rfl (fun _ h => by cases h; rfl))
  have r10 := r9.step (.loadAttach _ 1 1 7 _ _ rfl rfl)
  have := H _ r10 1 ⟨[7, 5], none⟩ rfl
  simp at this

/-- Without the undo of a load whose payload xattr cannot be written,
`recorded_runs` fails: the load is recorded, the next command's undo pass
reads its directory as unrecorded and detaches it, with no unload on
record. With no process left and the register and the log agreeing, the
records say name 1 runs payload 5, and nothing does. -/
theorem xattr_needs_undo :
    ¬ ∀ s : State Nat Nat, Reach { xattrUndo := false } s →
      (∀ i, s.procs i = none) → s.reg = bootEvs s →
      ∀ n p, fold (bootEvs s) n = some p → s.pins n ≠ none := by
  intro H
  have r1 := reach_boot1 { xattrUndo := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inr rfl) rfl rfl (fun _ h => absurd rfl h))
  have r4 := r3.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  have r6 := r5.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r7 := r6.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r8 := r7.step (.loadXattrIgnore _ 0 1 5 rfl rfl)
  have r9 := r8.step (.loadPersist _ 0 1 5 rfl)
  have r10 := r9.step (.loadExtend _ 0 1 5 rfl rfl)
  have r11 := r10.step (.loadAppend _ 0 1 5 rfl)
  have r12 := r11.step (.spawn _ 1 (.load 2 6) rfl (fun _ => rfl))
  have r13 := r12.step (.lockUndo _ 1 (.load 2 6) _ [1]
    rfl rfl (Or.inr rfl) rfl rfl (fun n h => by
      by_cases hn : n = 1
      · simp [hn]
      · exact absurd (by simp [State.go, State.exit, booted, upd, hn]) h))
  have r14 := r13.step (.undoRemove _ 1 _ _ 1 [] _ .ok rfl rfl)
  have r15 := r14.step (.undoPinsDone _ 1 _ _ _ [] rfl (fun k h => by
    by_cases hk : k = 1
    · subst hk; exact absurd rfl h
    · exact absurd
        (by simp [State.go, State.exit, State.undoLoad, booted, s0, upd, hk])
        h))
  have r16 := r15.step (.undoArchDone _ 1 _ _ _ rfl (Or.inl rfl))
  have r17 := r16.step (.bailActed _ 1 _ rfl)
  refine H _ r17 (fun i => ?_) rfl 1 5 rfl rfl
  by_cases h0 : i = 0
  · subst h0; rfl
  · by_cases h1 : i = 1
    · subst h1; rfl
    · simp [State.go, State.exit, State.undoLoad, booted, upd, h0, h1]

/-- Without the lock across the purge, `recorded_runs` fails: a live
revocation purges name 1, records the unload and releases the lock; a
load of name 1 under another key takes it, its undo pass removes the pins
the purge's record took off the records, and it pins and archives payload
6; the
purge's `remove_pin_dir()` and `unlink()` then take that load's pins and
archive, and the load records itself. With no process left and the
register and the log agreeing, the records say name 1 runs payload 6, and
nothing does. -/
theorem purge_needs_lock :
    ¬ ∀ s : State Nat Nat, Reach { purgeLock := false } s →
      (∀ i, s.procs i = none) → s.reg = bootEvs s →
      ∀ n p, fold (bootEvs s) n = some p → s.pins n ≠ none := by
  intro H
  have r1 := reach_boot1 { purgeLock := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inr rfl) rfl rfl (fun _ h => absurd rfl h))
  have r4 := r3.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  have r6 := r5.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r7 := r6.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r8 := r7.step (.loadXattr _ 0 1 5 rfl)
  have r9 := r8.step (.loadPersist _ 0 1 5 rfl)
  have r10 := r9.step (.loadExtend _ 0 1 5 rfl rfl)
  have r11 := r10.step (.loadAppend _ 0 1 5 rfl)
  have r12 := r11.step (.spawn _ 9 (.purge 1) rfl (fun _ => rfl))
  have r13 := r12.step (.purgeRead _ 9 1 _ rfl rfl rfl (fun h => by cases h)
    (fun h => by cases h))
  have r14 := r13.step (.purgeExtend _ 9 1 _ rfl (fun h => by cases h)
    (fun _ => Or.inr rfl) rfl)
  have r15 := r14.step (.purgeAppend _ 9 1 _ rfl)
  have r16 := r15.step (.spawn _ 1 (.load 1 6) rfl (fun _ => rfl))
  have r17 := r16.step (.lockUndo _ 1 (.load 1 6) _ [1]
    rfl rfl (Or.inr rfl) rfl rfl (fun n h => by
      by_cases hn : n = 1
      · simp [hn]
      · exact absurd (by simp [State.go, State.exit, booted, upd, hn]) h))
  have r18 := r17.step (.undoRemove _ 1 _ _ 1 [] _ .ok rfl rfl)
  have r19 := r18.step (.undoPinsDone _ 1 _ _ _ [] rfl (fun k h => by
    by_cases hk : k = 1
    · subst hk; exact absurd rfl h
    · exact absurd
        (by simp [State.go, State.exit, State.undoLoad, booted, s0, upd, hk])
        h))
  have r20 := r19.step (.undoArchDone _ 1 _ _ _ rfl (Or.inl rfl))
  have r21 := r20.step (.loadMkdir _ 1 1 6 rfl (fun _ h => by cases h))
  have r22 := r21.step (.loadAttach _ 1 1 6 _ _ rfl rfl)
  have r23 := r22.step (.loadXattr _ 1 1 6 rfl)
  have r24 := r23.step (.loadPersist _ 1 1 6 rfl)
  have r25 := r24.step (.detach _ 9 (.purge 1) rfl)
  have r26 := r25.step (.unlinkArch _ 9 (.purge 1) true rfl)
  have r27 := r26.step (.loadExtend _ 1 1 6 rfl rfl)
  have r28 := r27.step (.loadAppend _ 1 1 6 rfl)
  refine H _ r28 (fun i => ?_) rfl 1 6 rfl rfl
  by_cases h0 : i = 0
  · subst h0; rfl
  · by_cases h1 : i = 1
    · subst h1; rfl
    · by_cases h9 : i = 9
      · subst h9; rfl
      · simp [State.go, State.exit, State.undoLoad, booted, upd, h0, h1, h9]

/-- Without the `measured_holds()` filter, `init_restores_exactly` fails:
`init` restores the archive of a load killed before its extend, which no
record covers. -/
theorem init_needs_filter :
    ¬ ∀ s : State Nat Nat, Reach { filter := false } s → ∀ ks pins set,
      (∀ k, s.arch k ≠ none → k ∈ ks) →
      restore false (measuredLog s) s.arch ks = some (pins, set) →
      ∀ n p, pins n = some ⟨[p], some p⟩ →
        Wanted (measuredLog s) s.arch n p := by
  intro H
  have r1 := reach_boot1 { filter := false }
  have r2 := r1.step (.spawn _ 0 (.load 1 5) rfl (fun _ => rfl))
  have r3 := r2.step (.lockUndo _ 0 (.load 1 5) _ []
    rfl rfl (Or.inr rfl) rfl rfl (fun _ h => absurd rfl h))
  have r4 := r3.step (.undoPinsDone _ 0 _ _ _ [] rfl (fun _ h => absurd rfl h))
  have r5 := r4.step (.undoArchDone _ 0 _ _ _ rfl (Or.inl rfl))
  have r6 := r5.step (.loadMkdir _ 0 1 5 rfl (fun _ h => by cases h))
  have r7 := r6.step (.loadAttach _ 0 1 5 _ _ rfl rfl)
  have r8 := r7.step (.loadXattr _ 0 1 5 rfl)
  have r9 := r8.step (.loadPersist _ 0 1 5 rfl)
  have r10 := r9.step (.kill _ 0 _ rfl)
  obtain ⟨_, _, _, _, _, _, hm⟩ := H _ r10 [1] _ _ (fun k h => by
    change upd (fun _ => none) 1 (some (⟨1, 5, true, false⟩ : Entry Nat Nat)) k
      ≠ none at h
    by_cases hk : k = 1
    · simp [hk]
    · simp [upd, hk] at h) rfl 1 5 rfl
  change (none : Option Nat) = some 5 at hm
  cases hm

end Shirudo.UpatchLoad
