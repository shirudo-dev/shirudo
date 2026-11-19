-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Chain
import Shirudo.SemVer

/-!
The events of the measurement register, byte for byte as util/chain.c
hashes them. Every event is SHA-256 of a tag, its NUL and fixed fields:

- `chain_init_event()`: `"shirudo-init"`, the certificate set's digest,
  the digest of the listing of the restored set, one
  `"<payload hex> <name>\n"` line per upatch sorted by name, a Java
  upatch's line prefixed with `"java "`, and the upatch tree's root;
- `chain_upatch_event()`: `"shirudo-upatch"` for a load or
  `"shirudo-unload"` for an unload of a BPF upatch, `"shirudo-java"` or
  `"shirudo-java-unload"` for a Java one, the payload digest and the name
  cut at `strnlen(name, UPATCH_NAME_MAX)`;
- `chain_key_event()`: `"shirudo-key-revoke"` and the certificate's
  digest;
- `chain_tree_event()`: `"shirudo-tree"`, the operation's sequence
  number, as a `__u64` most significant byte first, and its digest.

`chain_fold()`, and the TPM's NV extend, set the register to SHA-256 of
the register and the event, from 32 zero bytes before the first extend.
`chain_history_step()` hashes `"shirudo-tree-history"`, its NUL, a
tree's history root and an operation's digest into the next history
root (`historyBytes`), a chain beside the register.

The model follows each function's buffer: `Fields.bytes` is what the C
hands SHA-256 for an event whose set is already hashed, `listing` the
string `chain_init_event()` builds, and `Event.digest` the event digest.
A byte is a `UInt8`, a digest 32 of them, a C string the bytes before its
NUL. testing/proofs/cbmc/chain-events.c checks that the C hashes exactly
`Fields.bytes` for every name of up to 8 bytes and of 255 to 257, every
payload, digest and sequence number, the init event of an empty set
included, `fold` for every register and event and `historyBytes` for
every root and digest.

On the domain the callers admit, upatch names that `upatch_name_valid()`
accepts of at most `UPATCH_NAME_MAX` bytes and sequence numbers a
`__s64` holds, `Fields.bytes` is injective (`bytes_injective`): the first
NUL ends the tag, no tag holds one and no two are equal, and every field
after it has a fixed length but the name, which runs to the end. The
listing is injective while no name holds a newline (`listing_injective`):
no hex digit is the `j` of `"java "`, so a Java line cannot pass for a
BPF one.
Outside that domain both fail: a name of more than `UPATCH_NAME_MAX`
bytes is cut (`upatch_cut`), and a name with a newline spells two
members (`listing_newline`). `qsort()` leaves a set whose names are
distinct in one order whatever order it came in (`sorts_unique`), so the
init event depends only on the upatches the set holds; with a name twice
it is `qsort()`'s choice (`sorts_tie`).

SHA-256 is a parameter. A function from byte strings onto 32-byte
digests is never injective, so the end theorem asks only that SHA-256
maps no two of the strings it was given to one digest and none to the
zero register (`replay_injective_on`). Then equal registers come from
the same typed events, in the same order. Read the other way
(`replay_collision`), two different histories that reach one register
hold a SHA-256 collision among the strings they hash, or a string that
hashes to 32 zero bytes: the result rests on SHA-256 alone.
`replay_injective` states it for an idealized injective hash, which no
function onto 32-byte digests is, so it holds of none.

`verify_sound` states it as `attest verify` uses it, for whatever
extended the register: the 32-byte values the TPM folded in were the
digests of the events the operator expects, unless SHA-256 collides on
the 64-byte strings of the two folds, so it asks nothing of the target's
events, nor that shirudo alone extended the register. `verify_events`
shows the digests name those events, loads and unloads of any name
`attest predict --event` takes, 1 to 256 bytes, included, and
`verify_history` puts the two together for a target that extended
events.
-/

namespace Shirudo.Events
open Shirudo

/-! ### Bytes, digests and tags -/

/-- `UPATCH_NAME_MAX` of include/shirudo/upatch.h. -/
def nameMax : Nat := 256

/-- The bytes of a C string literal before its NUL. -/
def ascii (s : String) : List UInt8 := s.toList.map fun c => c.toNat.toUInt8

/-- A SHA-256 digest, and every other 32-byte field of an event. -/
structure Digest where
  bytes : List UInt8
  length_eq : bytes.length = 32

theorem Digest.ext_bytes {a b : Digest} (h : a.bytes = b.bytes) : a = b := by
  cases a
  cases b
  cases h
  rfl

/-- The register before its first extend: an NV extend index reads as
zeros of its digest's size until it is written. -/
def Digest.zero : Digest := ⟨List.replicate 32 0, by simp⟩

/-- The tags, as the callers pass them. -/
def tagInit : List UInt8 := ascii "shirudo-init"
def tagUpatch : List UInt8 := ascii "shirudo-upatch"
def tagUnload : List UInt8 := ascii "shirudo-unload"
def tagJava : List UInt8 := ascii "shirudo-java"
def tagJavaUnload : List UInt8 := ascii "shirudo-java-unload"
def tagKeyRevoke : List UInt8 := ascii "shirudo-key-revoke"
def tagTree : List UInt8 := ascii "shirudo-tree"
def tagHistory : List UInt8 := ascii "shirudo-tree-history"

/-- `strnlen(s, max)` of the C string whose bytes, up to its NUL, start
with `s`. -/
def strnlen (s : List UInt8) (max : Nat) : Nat :=
  min (s.takeWhile (· != 0)).length max

/-! ### What util/chain.c hashes -/

/-- An event as `chain_*_event()` hashes it: the init event's set is in
it as the digest of its listing. -/
inductive Fields where
  | init (cert setDigest treeRoot : Digest)
  | upatch (name : List UInt8) (payload : Digest)
  | unload (name : List UInt8) (payload : Digest)
  | javaLoad (name : List UInt8) (payload : Digest)
  | javaUnload (name : List UInt8) (payload : Digest)
  | keyRevoke (cert : Digest)
  | tree (seq : Int) (operation : Digest)

/-- `chain_init_event()`'s `tag` buffer: `"shirudo-init"` copied with its
NUL, then the certificate set's digest, the set's and the tree root. -/
def initBytes (cert setDigest treeRoot : Digest) : List UInt8 :=
  tagInit ++ [0] ++ cert.bytes ++ setDigest.bytes ++ treeRoot.bytes

/-- `chain_upatch_event()`'s buffer: `tag` and its NUL, the payload, and
the name up to `strnlen(name, UPATCH_NAME_MAX)`. -/
def upatchBytes (tag name : List UInt8) (payload : Digest) : List UInt8 :=
  tag ++ [0] ++ payload.bytes ++ name.take (strnlen name nameMax)

/-- `chain_key_event()`: what `sha256_2()` hashes, `tag` and its NUL, then
the certificate's digest. -/
def keyBytes (tag : List UInt8) (cert : Digest) : List UInt8 :=
  tag ++ [0] ++ cert.bytes

/-- `(__u64)seq`: C converts a negative `__s64` by adding 2^64. -/
def u64OfS64 (seq : Int) : Nat := (seq % 18446744073709551616).toNat

/-- The loop of `chain_tree_event()`: byte `i` is
`(__u8)(s >> (56 - 8 * i))`, the most significant first. -/
def be64 (s : Nat) : List UInt8 :=
  (List.range 8).map fun i => UInt8.ofNat (s >>> (56 - 8 * i))

/-- `chain_tree_event()`'s buffer: `"shirudo-tree"` with its NUL, the
sequence number and the operation's digest. -/
def treeBytes (seq : Int) (operation : Digest) : List UInt8 :=
  tagTree ++ [0] ++ be64 (u64OfS64 seq) ++ operation.bytes

/-- `chain_history_step()`'s buffer: `"shirudo-tree-history"` with its
NUL, the history root before the operation and the operation's digest.
It is no register event: a tree's history root is a chain of its own. -/
def historyBytes (prev operation : Digest) : List UInt8 :=
  tagHistory ++ [0] ++ prev.bytes ++ operation.bytes

/-- What the C hands SHA-256 for an event. -/
def Fields.bytes : Fields → List UInt8
  | .init c s r => initBytes c s r
  | .upatch n p => upatchBytes tagUpatch n p
  | .unload n p => upatchBytes tagUnload n p
  | .javaLoad n p => upatchBytes tagJava n p
  | .javaUnload n p => upatchBytes tagJavaUnload n p
  | .keyRevoke c => keyBytes tagKeyRevoke c
  | .tree s o => treeBytes s o

/-! ### The domain the callers admit -/

/-- A byte `upatch_name_valid()` accepts: `[A-Za-z0-9._-]`. -/
def nameChar (c : UInt8) : Bool :=
  (97 ≤ c && c ≤ 122) || (65 ≤ c && c ≤ 90) || (48 ≤ c && c ≤ 57) ||
    c == 46 || c == 95 || c == 45

/-- `NAME_MAX`, the longest name of a pin directory. -/
def pinMax : Nat := 255

/-- The length of `upatch_bpffs_name()` of util/paths.h, which spells each
dot in two bytes. -/
def pinLength (n : List UInt8) : Nat :=
  (n.map fun c => if c == 46 then 2 else 1).sum

/-- `upatch_name_valid()` of util/upatch.c: not empty, not starting with a
dot, only bytes of `nameChar`, and a pin directory name that fits. -/
def nameValid : List UInt8 → Bool
  | [] => false
  | c :: cs => c != 46 && (c :: cs).all nameChar &&
      decide (pinLength (c :: cs) ≤ pinMax)

/-- The names that reach `chain_upatch_event()` and `chain_init_event()`
on a target and in `attest verify`: what `upatch_name_valid()` accepts,
in a buffer of `UPATCH_NAME_MAX + 1` bytes. -/
def NameAdmitted (n : List UInt8) : Prop :=
  nameValid n = true ∧ n.length ≤ nameMax

/-- What the encoding needs of a name: a C string that `strnlen()` does
not cut. The names `attest predict` reads with
`attest_parse_name_digest()`, of 1 to 256 bytes before the first `=`,
fit too, though `upatch_name_valid()` need not accept them. -/
def NameFits (n : List UInt8) : Prop := 0 ∉ n ∧ n.length ≤ nameMax

/-- A sequence number a `__s64` holds. -/
def S64 (seq : Int) : Prop :=
  -9223372036854775808 ≤ seq ∧ seq < 9223372036854775808

/-- The events the encoding is injective on. -/
def Fields.Fits : Fields → Prop
  | .upatch n _ => NameFits n
  | .unload n _ => NameFits n
  | .javaLoad n _ => NameFits n
  | .javaUnload n _ => NameFits n
  | .tree s _ => S64 s
  | _ => True

theorem nameValid_mem {n : List UInt8} (h : nameValid n = true) :
    ∀ c ∈ n, nameChar c = true := by
  cases n with
  | nil => simp [nameValid] at h
  | cons c cs =>
    simp only [nameValid, Bool.and_eq_true, List.all_eq_true] at h
    exact h.1.2

theorem nameChar_ne {c : UInt8} (h : nameChar c = true) : c ≠ 0 ∧ c ≠ 10 := by
  constructor <;> (rintro rfl; exact absurd h (by decide))

theorem NameAdmitted.fits {n : List UInt8} (h : NameAdmitted n) :
    NameFits n :=
  ⟨fun h0 => (nameChar_ne (nameValid_mem h.1 0 h0)).1 rfl, h.2⟩

theorem NameAdmitted.no_newline {n : List UInt8} (h : NameAdmitted n) :
    10 ∉ n :=
  fun h10 => (nameChar_ne (nameValid_mem h.1 10 h10)).2 rfl

/-! ### Splitting the bytes -/

/-- Two strings that each run to a separator they do not hold, then go
on: the parts before and after it are equal. -/
theorem split_at (c : UInt8) :
    ∀ {a b r s : List UInt8}, c ∉ a → c ∉ b →
      a ++ c :: r = b ++ c :: s → a = b ∧ r = s
  | [], [], _, _, _, _, h => ⟨rfl, by simpa using h⟩
  | [], x :: b, _, _, _, hb, h => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd (h.1 ▸ List.mem_cons_self) hb
  | x :: a, [], _, _, ha, _, h => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd (h.1.symm ▸ List.mem_cons_self) ha
  | x :: a, y :: b, r, s, ha, hb, h => by
    simp only [List.cons_append, List.cons.injEq] at h
    have hrest := split_at c (a := a) (b := b) (r := r) (s := s)
      (fun hm => ha (List.mem_cons_of_mem x hm))
      (fun hm => hb (List.mem_cons_of_mem y hm)) h.2
    exact ⟨by rw [h.1, hrest.1], hrest.2⟩

theorem split_digest {a b : Digest} {r s : List UInt8}
    (h : a.bytes ++ r = b.bytes ++ s) : a = b ∧ r = s := by
  have h' := List.append_inj h (by rw [a.length_eq, b.length_eq])
  exact ⟨Digest.ext_bytes h'.1, h'.2⟩

theorem takeWhile_no_nul :
    ∀ l : List UInt8, 0 ∉ l → l.takeWhile (· != 0) = l
  | [], _ => rfl
  | x :: xs, h => by
    have hx : x ≠ 0 := fun hx => h (hx ▸ List.mem_cons_self)
    simp [hx,
      takeWhile_no_nul xs (fun hm => h (List.mem_cons_of_mem x hm))]

theorem strnlen_fits {n : List UInt8} (h : NameFits n) :
    n.take (strnlen n nameMax) = n := by
  rw [strnlen, takeWhile_no_nul n h.1, Nat.min_eq_left h.2]
  exact List.take_of_length_le (Nat.le_refl _)

theorem be64_length (s : Nat) : (be64 s).length = 8 := by
  simp [be64]

theorem ofNat_eq {a b : Nat} (h : UInt8.ofNat a = UInt8.ofNat b) :
    a % 256 = b % 256 := by
  have := congrArg UInt8.toNat h
  simpa using this

theorem be64_injective {s s' : Nat} (hs : s < 18446744073709551616)
    (hs' : s' < 18446744073709551616) (h : be64 s = be64 s') : s = s' := by
  simp only [be64, List.range, List.range.loop, List.map_cons, List.map_nil,
    List.cons.injEq, Nat.shiftRight_eq_div_pow] at h
  obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7, -⟩ := h
  have e0 := ofNat_eq h0
  have e1 := ofNat_eq h1
  have e2 := ofNat_eq h2
  have e3 := ofNat_eq h3
  have e4 := ofNat_eq h4
  have e5 := ofNat_eq h5
  have e6 := ofNat_eq h6
  have e7 := ofNat_eq h7
  simp only [Nat.reducePow, Nat.reduceMul, Nat.reduceSub, Nat.pow_zero,
    Nat.div_one] at e0 e1 e2 e3 e4 e5 e6 e7
  omega

theorem u64OfS64_lt (seq : Int) : u64OfS64 seq < 18446744073709551616 := by
  unfold u64OfS64
  omega

theorem u64OfS64_injective {a b : Int} (ha : S64 a) (hb : S64 b)
    (h : u64OfS64 a = u64OfS64 b) : a = b := by
  unfold u64OfS64 at h
  unfold S64 at ha hb
  omega

/-! ### The encoding is injective -/

/-- The tag of an event. -/
def Fields.tag : Fields → List UInt8
  | .init .. => tagInit
  | .upatch .. => tagUpatch
  | .unload .. => tagUnload
  | .javaLoad .. => tagJava
  | .javaUnload .. => tagJavaUnload
  | .keyRevoke .. => tagKeyRevoke
  | .tree .. => tagTree

/-- What follows the tag's NUL. -/
def Fields.body : Fields → List UInt8
  | .init c s r => c.bytes ++ s.bytes ++ r.bytes
  | .upatch n p => p.bytes ++ n.take (strnlen n nameMax)
  | .unload n p => p.bytes ++ n.take (strnlen n nameMax)
  | .javaLoad n p => p.bytes ++ n.take (strnlen n nameMax)
  | .javaUnload n p => p.bytes ++ n.take (strnlen n nameMax)
  | .keyRevoke c => c.bytes
  | .tree s o => be64 (u64OfS64 s) ++ o.bytes

theorem Fields.bytes_eq (f : Fields) : f.bytes = f.tag ++ 0 :: f.body := by
  cases f <;>
    simp [Fields.bytes, Fields.tag, Fields.body, initBytes, upatchBytes,
      keyBytes, treeBytes]

theorem Fields.tag_no_nul (f : Fields) : 0 ∉ f.tag := by
  cases f <;> simp only [Fields.tag] <;> decide

/-- A tag names one kind of event: no two kinds share a tag. -/
theorem Fields.tag_kind {f g : Fields} (h : f.tag = g.tag) :
    f.ctorIdx = g.ctorIdx := by
  cases f <;> cases g <;> first
    | rfl
    | exact absurd h (by simp only [Fields.tag]; decide)

theorem Fields.body_injective {f g : Fields} (hf : f.Fits) (hg : g.Fits)
    (hk : f.ctorIdx = g.ctorIdx) (h : f.body = g.body) : f = g := by
  cases f <;> cases g <;> simp only [Fields.ctorIdx, Nat.reduceEqDiff] at hk <;>
    simp only [Fields.body, List.append_assoc] at h
  case init.init c s r c' s' r' =>
    obtain ⟨hc, h⟩ := split_digest h
    obtain ⟨hs, hr⟩ := split_digest h
    rw [hc, hs, Digest.ext_bytes hr]
  case upatch.upatch n p n' p' =>
    obtain ⟨hp, hn⟩ := split_digest h
    rw [strnlen_fits hf, strnlen_fits hg] at hn
    rw [hn, hp]
  case unload.unload n p n' p' =>
    obtain ⟨hp, hn⟩ := split_digest h
    rw [strnlen_fits hf, strnlen_fits hg] at hn
    rw [hn, hp]
  case javaLoad.javaLoad n p n' p' =>
    obtain ⟨hp, hn⟩ := split_digest h
    rw [strnlen_fits hf, strnlen_fits hg] at hn
    rw [hn, hp]
  case javaUnload.javaUnload n p n' p' =>
    obtain ⟨hp, hn⟩ := split_digest h
    rw [strnlen_fits hf, strnlen_fits hg] at hn
    rw [hn, hp]
  case keyRevoke.keyRevoke c c' =>
    rw [Digest.ext_bytes h]
  case tree.tree s o s' o' =>
    have h' := List.append_inj h (by rw [be64_length, be64_length])
    have hs := u64OfS64_injective hf hg
      (be64_injective (u64OfS64_lt s) (u64OfS64_lt s') h'.1)
    rw [hs, Digest.ext_bytes h'.2]

/-- Two events whose names `strnlen()` does not cut, and whose sequence
numbers a `__s64` holds, hash the same bytes only when they are the same
event. -/
theorem bytes_injective_of_fits {f g : Fields} (hf : f.Fits) (hg : g.Fits)
    (h : f.bytes = g.bytes) : f = g := by
  rw [Fields.bytes_eq, Fields.bytes_eq] at h
  have ⟨ht, hb⟩ := split_at 0 f.tag_no_nul g.tag_no_nul h
  exact Fields.body_injective hf hg (Fields.tag_kind ht) hb

/-- The events the callers admit: names `upatch_name_valid()` accepts of
at most `UPATCH_NAME_MAX` bytes, sequence numbers of a `__s64`. -/
def Fields.Admitted : Fields → Prop
  | .upatch n _ => NameAdmitted n
  | .unload n _ => NameAdmitted n
  | .javaLoad n _ => NameAdmitted n
  | .javaUnload n _ => NameAdmitted n
  | .tree s _ => S64 s
  | _ => True

theorem Fields.Admitted.fits {f : Fields} (h : f.Admitted) : f.Fits := by
  cases f with
  | upatch n p => exact NameAdmitted.fits h
  | unload n p => exact NameAdmitted.fits h
  | javaLoad n p => exact NameAdmitted.fits h
  | javaUnload n p => exact NameAdmitted.fits h
  | tree s o => exact h
  | init => trivial
  | keyRevoke => trivial

/-- On the domain the callers admit, two events hash the same bytes only
when they are the same event: no tag or field of one kind can pass for
another's, and a load for an unload, nor one name, payload, certificate,
sequence number or digest for another. -/
theorem bytes_injective {f g : Fields} (hf : f.Admitted) (hg : g.Admitted)
    (h : f.bytes = g.bytes) : f = g :=
  bytes_injective_of_fits hf.fits hg.fits h

/-- Outside the domain: two names that agree on their first
`UPATCH_NAME_MAX` bytes hash alike, the longer one cut. -/
theorem upatch_cut (tag n : List UInt8) (x : UInt8) (p : Digest)
    (hn : NameFits n) (hlen : n.length = nameMax) (hx : x ≠ 0) :
    upatchBytes tag (n ++ [x]) p = upatchBytes tag n p := by
  have hw := takeWhile_no_nul (n ++ [x]) (by
    simp only [List.mem_append, List.mem_singleton, not_or]
    exact ⟨hn.1, fun h0 => hx h0.symm⟩)
  have hcut := strnlen_fits hn
  simp only [upatchBytes, strnlen, hw, List.length_append, List.length_singleton,
    hlen] at hcut ⊢
  rw [hcut]
  simp [nameMax, hlen]

/-! ### The init event's set -/

/-- A member of the restored set: `struct measured_upatch`, its payload
already hex-encoded by `hex_encode()`, and whether it is a Java upatch. -/
structure Member where
  name : List UInt8
  payload : Digest
  java : Bool

/-- `"0123456789abcdef"[n]` of `hex_encode()`. -/
def hexDigit (n : Nat) : UInt8 := (ascii "0123456789abcdef").getD n 0

/-- `hex_encode()` of util/hex.c: each byte as two lowercase digits, the
high nibble first. -/
def hexEncode (bs : List UInt8) : List UInt8 :=
  bs.flatMap fun b => [hexDigit (b.toNat >>> 4), hexDigit (b.toNat &&& 15)]

/-- `member_prefix()`: `"java "` for a Java member, nothing for a BPF
one. -/
def memberPrefix (m : Member) : List UInt8 :=
  if m.java then ascii "java " else []

/-- One line of the listing: `"%s%s %s\n"` of the prefix, the payload's
hex and the name. -/
def line (m : Member) : List UInt8 :=
  memberPrefix m ++ hexEncode m.payload.bytes ++ [32] ++ m.name ++ [10]

/-- The listing `chain_init_event()` hashes into the set's digest: the
lines of the set in the order `qsort()` left it. -/
def listing (set : List Member) : List UInt8 := set.flatMap line

theorem hexDigit_injective : ∀ a b : Fin 16,
    hexDigit a.val = hexDigit b.val → a = b := by
  decide

theorem hexByte_injective {a b : UInt8}
    (h : hexDigit (a.toNat >>> 4) = hexDigit (b.toNat >>> 4))
    (h' : hexDigit (a.toNat &&& 15) = hexDigit (b.toNat &&& 15)) : a = b := by
  have ha := a.toNat_lt
  have hb := b.toNat_lt
  have hand : ∀ n : Nat, n &&& 15 = n % 16 := fun n =>
    Nat.and_two_pow_sub_one_eq_mod n 4
  rw [hand, hand] at h'
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow] at h
  have hi := hexDigit_injective ⟨a.toNat / 2 ^ 4, by omega⟩
    ⟨b.toNat / 2 ^ 4, by omega⟩ h
  have hl := hexDigit_injective ⟨a.toNat % 16, by omega⟩
    ⟨b.toNat % 16, by omega⟩ h'
  simp only [Fin.mk.injEq] at hi hl
  exact UInt8.toNat_inj.mp (by omega)

theorem hexEncode_length (bs : List UInt8) :
    (hexEncode bs).length = 2 * bs.length := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    simp only [hexEncode, List.flatMap_cons, List.length_append,
      List.length_cons, List.length_nil] at ih ⊢
    rw [ih]
    omega

theorem hexEncode_injective :
    ∀ a b : List UInt8, hexEncode a = hexEncode b → a = b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [hexEncode] at h
  | _ :: _, [], h => by simp [hexEncode] at h
  | x :: xs, y :: ys, h => by
    simp only [hexEncode, List.flatMap_cons, List.cons_append, List.nil_append,
      List.cons.injEq] at h
    obtain ⟨h1, h2, h3⟩ := h
    rw [hexByte_injective h1 h2, hexEncode_injective xs ys h3]

theorem hexEncode_digest (d : Digest) : (hexEncode d.bytes).length = 64 := by
  rw [hexEncode_length, d.length_eq]

/-- No hex digit is the `j` that starts `"java "`. -/
theorem hexDigit_ne_j (n : Nat) : hexDigit n ≠ 106 := by
  by_cases h : n < 16
  · exact (by decide : ∀ a : Fin 16, hexDigit a.val ≠ 106) ⟨n, h⟩
  · have hl : (ascii "0123456789abcdef").length ≤ n := by
      simp [ascii]; omega
    simp only [hexDigit, List.getD_eq_getElem?_getD, List.getElem?_eq_none hl,
      Option.getD_none]
    decide

/-- A digest's hex starts with a hex digit. -/
theorem hexEncode_head (d : Digest) :
    ∃ x t, hexEncode d.bytes = x :: t ∧ x ≠ 106 := by
  have hl := d.length_eq
  cases hb : d.bytes with
  | nil => rw [hb] at hl; simp at hl
  | cons b bs =>
    exact ⟨hexDigit (b.toNat >>> 4), hexDigit (b.toNat &&& 15) :: hexEncode bs,
      by simp [hexEncode], hexDigit_ne_j _⟩

/-- Two lines that agree have the same prefix: a Java line starts with
`j`, a BPF line with a hex digit. -/
theorem line_prefix {m n : Member} {r s : List UInt8}
    (h : memberPrefix m ++ (hexEncode m.payload.bytes ++ r) =
      memberPrefix n ++ (hexEncode n.payload.bytes ++ s)) :
    m.java = n.java ∧ hexEncode m.payload.bytes ++ r =
      hexEncode n.payload.bytes ++ s := by
  obtain ⟨x, t, hx, hxj⟩ := hexEncode_head m.payload
  obtain ⟨y, u, hy, hyj⟩ := hexEncode_head n.payload
  cases hm : m.java <;> cases hn : n.java <;>
    simp only [memberPrefix, hm, hn, Bool.false_eq_true, ite_true, ite_false,
      List.nil_append] at h
  · exact ⟨rfl, h⟩
  · rw [hx] at h
    simp [ascii] at h
    exact absurd h.1 hxj
  · rw [hy] at h
    simp [ascii] at h
    exact absurd h.1.symm hyj
  · exact ⟨rfl, List.append_cancel_left h⟩

/-- While no name holds a newline, the listing spells one set: each line
is 64 hex digits, a space, and the name up to the newline. -/
theorem listing_injective :
    ∀ s t : List Member, (∀ m ∈ s, 10 ∉ m.name) → (∀ m ∈ t, 10 ∉ m.name) →
      listing s = listing t → s = t
  | [], [], _, _, _ => rfl
  | [], m :: _, _, _, h => by simp [listing, line] at h
  | m :: _, [], _, _, h => by simp [listing, line] at h
  | m :: ms, n :: ns, hs, ht, h => by
    simp only [listing, List.flatMap_cons, line, List.append_assoc] at h
    obtain ⟨hj, h⟩ := line_prefix h
    simp only [List.singleton_append] at h
    have h1 := List.append_inj h
      (by rw [hexEncode_digest, hexEncode_digest])
    have hp := Digest.ext_bytes (hexEncode_injective _ _ h1.1)
    have h1' := h1.2
    simp only [List.cons.injEq, true_and] at h1'
    have h2 := split_at 10 (hs m (by simp)) (ht n (by simp)) h1'
    have hrest := listing_injective ms ns
      (fun x hx => hs x (by simp [hx])) (fun x hx => ht x (by simp [hx])) h2.2
    cases m
    cases n
    simp only at hp h2 hj
    rw [hp, h2.1, hj, hrest]

/-- Outside the domain: a name holding a newline and the hex of another
payload makes one member spell two. -/
theorem listing_newline (p q : Digest) (a b : List UInt8) :
    listing [⟨a ++ 10 :: hexEncode q.bytes ++ 32 :: b, p, false⟩] =
      listing [⟨a, p, false⟩, ⟨b, q, false⟩] := by
  simp [listing, line, memberPrefix]

/-! ### The order `qsort()` leaves -/

/-- `member_cmp()`: `strcmp()` of the names. -/
def memberCmp (a b : Member) : Ordering :=
  SemVer.strcmp (a.name.map UInt8.toNat) (b.name.map UInt8.toNat)

/-- What `qsort()` with `member_cmp()` may leave of `set`: the same
members, none after one it compares above. -/
def Sorts (set out : List Member) : Prop :=
  out.Perm set ∧ out.Pairwise fun a b => memberCmp a b ≠ .gt

theorem strcmp_total : SemVer.TotalOrder SemVer.strcmp :=
  SemVer.lex_total SemVer.cmpNat_total

theorem memberCmp_eq {a b : Member} (h : memberCmp a b = .eq) :
    a.name = b.name := by
  have := (strcmp_total.eq_iff _ _).mp h
  exact Chain.map_injective UInt8.toNat (fun _ _ hxy => UInt8.toNat_inj.mp hxy)
    _ _ this

/-- In a list sorted by distinct names, each member compares below every
later one. -/
theorem sorted_strict {out : List Member}
    (hnd : (out.map Member.name).Nodup)
    (h : out.Pairwise fun a b => memberCmp a b ≠ .gt) :
    out.Pairwise fun a b => memberCmp a b = .lt := by
  have hne : out.Pairwise fun a b => a.name ≠ b.name := by
    have := List.pairwise_map.mp hnd
    exact this
  refine (h.and hne).imp ?_
  intro a b ⟨hgt, hn⟩
  cases hc : memberCmp a b
  · rfl
  · exact absurd (memberCmp_eq hc) hn
  · exact absurd hc hgt

theorem strict_unique :
    ∀ out out' : List Member, out.Perm out' →
      out.Pairwise (fun a b => memberCmp a b = .lt) →
      out'.Pairwise (fun a b => memberCmp a b = .lt) → out = out'
  | [], [], _, _, _ => rfl
  | [], _ :: _, hp, _, _ => absurd hp.length_eq (by simp)
  | _ :: _, [], hp, _, _ => absurd hp.length_eq (by simp)
  | a :: as, b :: bs, hp, h, h' => by
    rw [List.pairwise_cons] at h h'
    have hab : a = b := by
      apply Classical.byContradiction
      intro hne
      have ha : a ∈ bs := by
        have := hp.mem_iff.mp List.mem_cons_self
        rcases List.mem_cons.mp this with he | he
        · exact absurd he hne
        · exact he
      have hb : b ∈ as := by
        have := hp.mem_iff.mpr List.mem_cons_self
        rcases List.mem_cons.mp this with he | he
        · exact absurd he.symm hne
        · exact he
      have h1 : memberCmp b a = .gt := by
        have := h.1 b hb
        unfold memberCmp at this ⊢
        rw [strcmp_total.swap, this]
        rfl
      rw [h'.1 a ha] at h1
      cases h1
    subst hab
    rw [strict_unique as bs (List.Perm.cons_inv hp) h.2 h'.2]

/-- `chain_init_event()` sorts the set before it lists it: two sets of the
same upatches, each name once, in any order, give the same listing
whatever order `qsort()` leaves equal elements in, so the init event
depends only on which upatches the set holds. -/
theorem sorts_unique {s t out out' : List Member}
    (hnd : (s.map Member.name).Nodup) (hst : s.Perm t) (h : Sorts s out)
    (h' : Sorts t out') : out = out' := by
  have hnd1 : (out.map Member.name).Nodup := (h.1.map _).nodup_iff.mpr hnd
  have hnd2 : (out'.map Member.name).Nodup :=
    (h'.1.map _).nodup_iff.mpr ((hst.map _).nodup_iff.mp hnd)
  exact strict_unique out out' (h.1.trans (hst.trans h'.1.symm))
    (sorted_strict hnd1 h.2) (sorted_strict hnd2 h'.2)

/-- With a name twice, the order is `qsort()`'s: both orders of two
members of one name sort, and their listings differ unless the payloads
are equal. -/
theorem sorts_tie (n : List UInt8) (p q : Digest) :
    Sorts [⟨n, p, false⟩, ⟨n, q, false⟩] [⟨n, p, false⟩, ⟨n, q, false⟩] ∧
      Sorts [⟨n, p, false⟩, ⟨n, q, false⟩] [⟨n, q, false⟩, ⟨n, p, false⟩] ∧
      (listing [⟨n, p, false⟩, ⟨n, q, false⟩] =
        listing [⟨n, q, false⟩, ⟨n, p, false⟩] → p = q) := by
  have heq : memberCmp ⟨n, p, false⟩ ⟨n, q, false⟩ = .eq :=
    (strcmp_total.eq_iff _ _).mpr rfl
  have heq' : memberCmp ⟨n, q, false⟩ ⟨n, p, false⟩ = .eq :=
    (strcmp_total.eq_iff _ _).mpr rfl
  refine ⟨⟨List.Perm.refl _, by simp [heq]⟩,
    ⟨List.Perm.swap _ _ _, by simp [heq']⟩, fun h => ?_⟩
  simp only [listing, line, memberPrefix, List.flatMap_cons, List.flatMap_nil,
    List.append_nil, List.append_assoc, Bool.false_eq_true, ite_false,
    List.nil_append] at h
  have := List.append_inj h (by rw [hexEncode_digest, hexEncode_digest])
  exact Digest.ext_bytes (hexEncode_injective _ _ this.1)

/-! ### Typed events and the register -/

/-- An event the register measures, as the target means it: an init event
with its certificate set's digest, the restored set as `qsort()` left it
and the tree root; a load or an unload of a BPF or a Java upatch; a key
revocation; a tree operation. -/
inductive Event where
  | init (cert : Digest) (set : List Member) (treeRoot : Digest)
  | load (name : List UInt8) (payload : Digest)
  | unload (name : List UInt8) (payload : Digest)
  | javaLoad (name : List UInt8) (payload : Digest)
  | javaUnload (name : List UInt8) (payload : Digest)
  | keyRevoke (cert : Digest)
  | tree (seq : Int) (operation : Digest)

/-- The events the callers admit. -/
def Event.Admitted : Event → Prop
  | .init _ s _ => ∀ m ∈ s, NameAdmitted m.name
  | .load n _ => NameAdmitted n
  | .unload n _ => NameAdmitted n
  | .javaLoad n _ => NameAdmitted n
  | .javaUnload n _ => NameAdmitted n
  | .keyRevoke _ => True
  | .tree s _ => S64 s

/-- The events the operator can expect: `attest predict --event` takes a
load or an unload of a name of 1 to 256 bytes, those before the first
`=`, which need only fit, and a tree operation of a sequence number a
`__s64` holds; an init event's set passes `measured_set_add()`, whose
names `upatch_name_valid()` accepts. Every admitted event is one. -/
def Event.Predicted : Event → Prop
  | .init _ s _ => ∀ m ∈ s, NameAdmitted m.name
  | .load n _ => NameFits n
  | .unload n _ => NameFits n
  | .keyRevoke _ => True
  | .tree s _ => S64 s

theorem Event.Admitted.predicted {e : Event} (h : e.Admitted) :
    e.Predicted := by
  cases e with
  | init => exact h
  | load n p => exact NameAdmitted.fits h
  | unload n p => exact NameAdmitted.fits h
  | keyRevoke => trivial
  | tree s o => exact h

variable (sha : List UInt8 → Digest)

/-- What the C hashes for `e`, the init event's listing hashed into its
set digest. -/
def Event.fields : Event → Fields
  | .init c s r => .init c (sha (listing s)) r
  | .load n p => .upatch n p
  | .unload n p => .unload n p
  | .javaLoad n p => .javaLoad n p
  | .javaUnload n p => .javaUnload n p
  | .keyRevoke c => .keyRevoke c
  | .tree s o => .tree s o

/-- The event digest `chain_*_event()` gives. -/
def Event.digest (e : Event) : Digest := sha (e.fields sha).bytes

/-- `chain_fold()`, and the TPM's NV extend: the register and the event,
64 bytes, hashed. -/
def fold (r e : Digest) : Digest := sha (r.bytes ++ e.bytes)

/-- `chain_history_step()`: the step `Chain.historyRoot` folds from
`Digest.zero`. -/
def historyStep (prev operation : Digest) : Digest :=
  sha (historyBytes prev operation)

/-- The register after `events`, oldest first, as `attest predict` and
`attest verify` replay it and the TPM extends it. -/
def replay (events : List Event) : Digest :=
  events.foldl (fun r e => fold sha r (e.digest sha)) Digest.zero

theorem replay_eq_register (events : List Event) :
    replay sha events =
      Chain.register (fold sha) Digest.zero
        (events.map (Event.digest sha)).reverse := by
  rw [Chain.register_eq_foldl, List.reverse_reverse, List.foldl_map]
  rfl

/-- Every string an event hands SHA-256: its bytes, and an init event's
listing. -/
def Event.inputs (e : Event) : List (List UInt8) :=
  match e with
  | .init _ s _ => [listing s, (e.fields sha).bytes]
  | _ => [(e.fields sha).bytes]

/-- Every string SHA-256 is given on the way to `replay events`: each
event's, and each fold's 64 bytes. -/
def inputs (events : List Event) : List (List UInt8) :=
  events.flatMap (Event.inputs sha) ++
    (Chain.steps (fold sha) Digest.zero
      (events.map (Event.digest sha)).reverse).map
      fun p => p.1.bytes ++ p.2.bytes

theorem Event.admitted_fields {e : Event} (h : e.Admitted) :
    (e.fields sha).Admitted := by
  cases e with
  | init => trivial
  | load n p => exact h
  | unload n p => exact h
  | javaLoad n p => exact h
  | javaUnload n p => exact h
  | keyRevoke => trivial
  | tree s o => exact h

theorem Event.predicted_fits {e : Event} (h : e.Predicted) :
    (e.fields sha).Fits := by
  cases e with
  | init => trivial
  | load n p => exact h
  | unload n p => exact h
  | keyRevoke => trivial
  | tree s o => exact h

theorem Event.bytes_mem_inputs (e : Event) :
    (e.fields sha).bytes ∈ e.inputs sha := by
  cases e <;> simp [Event.inputs]

/-- Two events the operator can expect with one digest are the same
event, unless SHA-256 maps two different strings among those the events
hash to one digest. -/
theorem Event.digest_injective_on (a b : Event) (ha : a.Predicted)
    (hb : b.Predicted)
    (hsha : ∀ m ∈ a.inputs sha ++ b.inputs sha,
      ∀ m' ∈ a.inputs sha ++ b.inputs sha, sha m = sha m' → m = m')
    (h : a.digest sha = b.digest sha) : a = b := by
  have hbytes := hsha _ (List.mem_append_left _ (a.bytes_mem_inputs sha))
    _ (List.mem_append_right _ (b.bytes_mem_inputs sha)) h
  have hf := bytes_injective_of_fits (a.predicted_fits sha ha)
    (b.predicted_fits sha hb) hbytes
  cases a <;> cases b <;> simp only [Event.fields, reduceCtorEq] at hf
  case init.init c s r c' s' r' =>
    simp only [Fields.init.injEq] at hf
    obtain ⟨hc, hs, hr⟩ := hf
    have hl := hsha (listing s) (by simp [Event.inputs])
      (listing s') (by simp [Event.inputs]) hs
    have := listing_injective s s'
      (fun m hm => NameAdmitted.no_newline (ha m hm))
      (fun m hm => NameAdmitted.no_newline (hb m hm)) hl
    rw [hc, this, hr]
  all_goals
    first
    | (simp only [Fields.upatch.injEq] at hf; rw [hf.1, hf.2])
    | (simp only [Fields.unload.injEq] at hf; rw [hf.1, hf.2])
    | (simp only [Fields.javaLoad.injEq] at hf; rw [hf.1, hf.2])
    | (simp only [Fields.javaUnload.injEq] at hf; rw [hf.1, hf.2])
    | (simp only [Fields.keyRevoke.injEq] at hf; rw [hf])
    | (simp only [Fields.tree.injEq] at hf; rw [hf.1, hf.2])

/-- Equal registers come from the same admitted events, in the same order,
when SHA-256 maps no two different strings the two histories hash to one
digest and none of them to the zero register. -/
theorem replay_injective_on (l1 l2 : List Event)
    (h1 : ∀ e ∈ l1, e.Admitted) (h2 : ∀ e ∈ l2, e.Admitted)
    (hsha : ∀ m ∈ inputs sha l1 ++ inputs sha l2,
      ∀ m' ∈ inputs sha l1 ++ inputs sha l2, sha m = sha m' → m = m')
    (hzero : ∀ m ∈ inputs sha l1 ++ inputs sha l2, sha m ≠ Digest.zero)
    (h : replay sha l1 = replay sha l2) : l1 = l2 := by
  rw [replay_eq_register, replay_eq_register] at h
  have hsteps : ∀ (l : List Event) p,
      p ∈ Chain.steps (fold sha) Digest.zero
        (l.map (Event.digest sha)).reverse →
      p.1.bytes ++ p.2.bytes ∈ inputs sha l := by
    intro l p hp
    exact List.mem_append_right _ (List.mem_map.mpr ⟨p, hp, rfl⟩)
  have hevent : ∀ (l : List Event) e, e ∈ l → ∀ m ∈ e.inputs sha,
      m ∈ inputs sha l := by
    intro l e he m hm
    exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨e, he, hm⟩)
  have hregs := Chain.register_injective_on (fold sha) Digest.zero _ _
    (fun p hp q hq hpq => by
      have he := hsha _ (List.mem_append_left _ (hsteps l1 p hp))
        _ (List.mem_append_right _ (hsteps l2 q hq)) hpq
      obtain ⟨h1', h2'⟩ := split_digest he
      exact Prod.ext h1' (Digest.ext_bytes h2'))
    (fun p hp => by
      rcases List.mem_append.mp hp with hp | hp
      · exact hzero _ (List.mem_append_left _ (hsteps l1 p hp))
      · exact hzero _ (List.mem_append_right _ (hsteps l2 p hp)))
    h
  rw [List.reverse_inj] at hregs
  exact Chain.map_injective_on _ l1 l2
    (fun a ha b hb hab => Event.digest_injective_on sha a b
      (h1 a ha).predicted (h2 b hb).predicted
      (fun m hm m' hm' => hsha m
        (by
          rcases List.mem_append.mp hm with hm | hm
          · exact List.mem_append_left _ (hevent l1 a ha m hm)
          · exact List.mem_append_right _ (hevent l2 b hb m hm))
        m'
        (by
          rcases List.mem_append.mp hm' with hm' | hm'
          · exact List.mem_append_left _ (hevent l1 a ha m' hm')
          · exact List.mem_append_right _ (hevent l2 b hb m' hm')))
      hab)
    hregs

/-- Two different admitted histories that reach one register hold a
SHA-256 collision among the strings they hash, or a string that hashes to
the zero register. -/
theorem replay_collision (l1 l2 : List Event)
    (h1 : ∀ e ∈ l1, e.Admitted) (h2 : ∀ e ∈ l2, e.Admitted)
    (hne : l1 ≠ l2) (h : replay sha l1 = replay sha l2) :
    (∃ m ∈ inputs sha l1 ++ inputs sha l2,
      ∃ m' ∈ inputs sha l1 ++ inputs sha l2, m ≠ m' ∧ sha m = sha m') ∨
    ∃ m ∈ inputs sha l1 ++ inputs sha l2, sha m = Digest.zero := by
  apply Classical.byContradiction
  intro hno
  apply hne
  apply replay_injective_on sha l1 l2 h1 h2 _ _ h
  · intro m hm m' hm' he
    apply Classical.byContradiction
    intro hmm
    exact hno (Or.inl ⟨m, hm, m', hm', hmm, he⟩)
  · intro m hm hz
    exact hno (Or.inr ⟨m, hm, hz⟩)

/-- For an idealised SHA-256, injective and never the zero register,
equal registers come from the same admitted events in the same order. -/
theorem replay_injective (hsha : ∀ m m', sha m = sha m' → m = m')
    (hzero : ∀ m, sha m ≠ Digest.zero) (l1 l2 : List Event)
    (h1 : ∀ e ∈ l1, e.Admitted) (h2 : ∀ e ∈ l2, e.Admitted)
    (h : replay sha l1 = replay sha l2) : l1 = l2 :=
  replay_injective_on sha l1 l2 h1 h2 (fun m _ m' _ => hsha m m')
    (fun m _ => hzero m) h

/-- The 64-byte strings SHA-256 is given on the way from the zero
register to the fold of `ds`, oldest first. -/
def foldInputs (ds : List Digest) : List (List UInt8) :=
  (Chain.steps (fold sha) Digest.zero ds.reverse).map
    fun p => p.1.bytes ++ p.2.bytes

/-- What `attest verify` concludes. The evidence's records carry digests
`ds`: the init record's equals the init event the operator expects for
the certificates, set and tree root given, and each later record's
derives from its fields, so `ds` are the digests of `expected`. They
replay to the register the TPM certified. Whatever extended that
register, with whatever 32-byte values `hs`, those were the digests of
`expected` in that order, unless SHA-256 maps two different strings of
the two folds to one digest or one of them to the zero register. -/
theorem verify_sound (expected : List Event) (ds hs : List Digest)
    (value : Digest)
    (hderive : ds = expected.map (Event.digest sha))
    (hreplay : ds.foldl (fold sha) Digest.zero = value)
    (hcertified : hs.foldl (fold sha) Digest.zero = value)
    (hsha : ∀ m ∈ foldInputs sha ds ++ foldInputs sha hs,
      ∀ m' ∈ foldInputs sha ds ++ foldInputs sha hs,
        sha m = sha m' → m = m')
    (hzero : ∀ m ∈ foldInputs sha ds ++ foldInputs sha hs,
      sha m ≠ Digest.zero) :
    hs = expected.map (Event.digest sha) := by
  have hmem : ∀ (l : List Digest) p,
      p ∈ Chain.steps (fold sha) Digest.zero l.reverse →
      p.1.bytes ++ p.2.bytes ∈ foldInputs sha l :=
    fun l p hp => List.mem_map.2 ⟨p, hp, rfl⟩
  have h : Chain.register (fold sha) Digest.zero ds.reverse =
      Chain.register (fold sha) Digest.zero hs.reverse := by
    rw [Chain.register_eq_foldl, Chain.register_eq_foldl,
      List.reverse_reverse, List.reverse_reverse, hreplay, hcertified]
  have hregs := Chain.register_injective_on (fold sha) Digest.zero _ _
    (fun p hp q hq hpq => by
      have he := hsha _ (List.mem_append_left _ (hmem ds p hp))
        _ (List.mem_append_right _ (hmem hs q hq)) hpq
      obtain ⟨h1', h2'⟩ := split_digest he
      exact Prod.ext h1' (Digest.ext_bytes h2'))
    (fun p hp => by
      rcases List.mem_append.mp hp with hp | hp
      · exact hzero _ (List.mem_append_left _ (hmem ds p hp))
      · exact hzero _ (List.mem_append_right _ (hmem hs p hp)))
    h
  rw [List.reverse_inj] at hregs
  rw [← hregs, hderive]

/-- The digests name the events: two lists of events the operator can
expect with the same digests are the same list, unless SHA-256 maps two
different strings the events hash to one digest. -/
theorem verify_events (l1 l2 : List Event)
    (h1 : ∀ e ∈ l1, e.Predicted) (h2 : ∀ e ∈ l2, e.Predicted)
    (hsha : ∀ m ∈ l1.flatMap (Event.inputs sha) ++
        l2.flatMap (Event.inputs sha),
      ∀ m' ∈ l1.flatMap (Event.inputs sha) ++ l2.flatMap (Event.inputs sha),
        sha m = sha m' → m = m')
    (h : l1.map (Event.digest sha) = l2.map (Event.digest sha)) : l1 = l2 :=
  Chain.map_injective_on _ l1 l2
    (fun a ha b hb hab => Event.digest_injective_on sha a b (h1 a ha) (h2 b hb)
      (fun m hm m' hm' => hsha m
        (by
          rcases List.mem_append.mp hm with hm | hm
          · exact List.mem_append_left _ (List.mem_flatMap.2 ⟨a, ha, hm⟩)
          · exact List.mem_append_right _ (List.mem_flatMap.2 ⟨b, hb, hm⟩))
        m'
        (by
          rcases List.mem_append.mp hm' with hm' | hm'
          · exact List.mem_append_left _ (List.mem_flatMap.2 ⟨a, ha, hm'⟩)
          · exact List.mem_append_right _ (List.mem_flatMap.2 ⟨b, hb, hm'⟩)))
      hab)
    h

/-- `verify_sound` for a target that extended the register by events: it
measured exactly `expected`, in that order, unless SHA-256 collides on
the strings the two hash or maps a fold to the zero register. -/
theorem verify_history (expected history : List Event) (ds : List Digest)
    (value : Digest)
    (hexpected : ∀ e ∈ expected, e.Predicted)
    (hhistory : ∀ e ∈ history, e.Predicted)
    (hderive : ds = expected.map (Event.digest sha))
    (hreplay : ds.foldl (fold sha) Digest.zero = value)
    (hcertified : replay sha history = value)
    (hsha : ∀ m ∈ inputs sha expected ++ inputs sha history,
      ∀ m' ∈ inputs sha expected ++ inputs sha history,
        sha m = sha m' → m = m')
    (hzero : ∀ m ∈ inputs sha expected ++ inputs sha history,
      sha m ≠ Digest.zero) :
    expected = history := by
  have hin : ∀ (l : List Event) m,
      m ∈ foldInputs sha (l.map (Event.digest sha)) → m ∈ inputs sha l :=
    fun l m hm => List.mem_append_right _ hm
  have hev : ∀ (l : List Event) m, m ∈ l.flatMap (Event.inputs sha) →
      m ∈ inputs sha l :=
    fun l m hm => List.mem_append_left _ hm
  have hsub : ∀ m, m ∈ foldInputs sha ds ++
      foldInputs sha (history.map (Event.digest sha)) →
      m ∈ inputs sha expected ++ inputs sha history := by
    intro m hm
    rcases List.mem_append.mp hm with hm | hm
    · rw [hderive] at hm
      exact List.mem_append_left _ (hin expected m hm)
    · exact List.mem_append_right _ (hin history m hm)
  have hd := verify_sound sha expected ds (history.map (Event.digest sha))
    value hderive hreplay
    (by rw [← hcertified, replay, List.foldl_map])
    (fun m hm m' hm' => hsha m (hsub m hm) m' (hsub m' hm'))
    (fun m hm => hzero m (hsub m hm))
  refine verify_events sha expected history hexpected hhistory ?_ hd.symm
  intro m hm m' hm'
  have hsub' : ∀ x, x ∈ expected.flatMap (Event.inputs sha) ++
      history.flatMap (Event.inputs sha) →
      x ∈ inputs sha expected ++ inputs sha history := by
    intro x hx
    rcases List.mem_append.mp hx with hx | hx
    · exact List.mem_append_left _ (hev expected x hx)
    · exact List.mem_append_right _ (hev history x hx)
  exact hsha m (hsub' m hm) m' (hsub' m' hm')

end Shirudo.Events
