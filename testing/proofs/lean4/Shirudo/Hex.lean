-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The hex codec of rust/src/util/hex.rs. `encode_into()` writes each byte
as two lowercase digits, high nibble first. `nibble()` accepts either
case. `decode()` requires exactly two digits per output byte;
`decode_max()` also accepts a shorter even run.

The model below describes hex bytes and the former C length arithmetic.
The Kani comparisons cover the Rust encoding and decoding within their
stated bounds. The model's sizeMul and sizeAdd remain for the original
length theorems; Rust now uses checked multiplication and slice bounds.
-/

namespace Shirudo.Hex

/-- `SIZE_MAX`. -/
def sizeMax : Nat := 18446744073709551615

/-- The saturating product used by the former C length model. -/
def sizeMul (a b : Nat) : Nat := if a * b ≤ sizeMax then a * b else sizeMax

/-- The saturating sum used by the former C length model. -/
def sizeAdd (a b : Nat) : Nat := if a + b ≤ sizeMax then a + b else sizeMax

/-- The digit table `d` of `encode_into()`. -/
def table : List Nat :=
  [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x61, 0x62, 0x63, 0x64, 0x65, 0x66]

/-- What the loop of `encode_into()` writes for one byte:
`d[in[i] >> 4]` and `d[in[i] & 0xf]`. -/
def encodeByte (b : Nat) : List Nat :=
  [table.getD (b >>> 4) 0, table.getD (b &&& 0xf) 0]

/-- `encode_into()`, without its NUL. -/
def encode (bs : List Nat) : List Nat := bs.flatMap encodeByte

/-- `nibble()`; `none` is -1. -/
def nibble (c : Nat) : Option Nat :=
  if 0x30 ≤ c ∧ c ≤ 0x39 then some (c - 0x30)
  else if 0x61 ≤ c ∧ c ≤ 0x66 then some (c - 0x61 + 10)
  else if 0x41 ≤ c ∧ c ≤ 0x46 then some (c - 0x41 + 10)
  else none

/-- The loop of `decode()`: `(hi << 4) | lo` from each pair of digits,
refusing the first pair that holds anything else. The length check before
it leaves no single byte over. -/
def decodePairs : List Nat → Option (List Nat)
  | [] => some []
  | [_] => none
  | h :: l :: rest =>
    match nibble h, nibble l with
    | some hi, some lo => (decodePairs rest).map (((hi <<< 4) ||| lo) :: ·)
    | _, _ => none

/-- `hex_decode(hex, out, n)`; `none` is `-EINVAL`. -/
def decode (s : List Nat) (n : Nat) : Option (List Nat) :=
  if s.length ≠ sizeMul n 2 then none else decodePairs s

/-- `hex_decode_max(hex, out, cap, len)`; `none` is `-EINVAL`, and the
length of what it yields is `*len`. -/
def decodeMax (s : List Nat) (cap : Nat) : Option (List Nat) :=
  let n := min s.length (sizeAdd (sizeMul cap 2) 1)
  if n % 2 ≠ 0 then none else decode s (n / 2)

/-- A hex digit of either case. -/
def isHex (c : Nat) : Bool := (nibble c).isSome

/-- A lowercase hex digit. -/
def isLowerHex (c : Nat) : Prop := (0x30 ≤ c ∧ c ≤ 0x39) ∨ (0x61 ≤ c ∧ c ≤ 0x66)

/-- A digit in lowercase, any other byte as it is. -/
def lower (c : Nat) : Nat := if 0x41 ≤ c ∧ c ≤ 0x46 then c + 0x20 else c

/-! ### One byte and one pair -/

theorem shr4 (b : Nat) : b >>> 4 = b / 16 := by
  rw [Nat.shiftRight_eq_div_pow]

theorem and15 (b : Nat) : b &&& 0xf = b % 16 := by
  have := Nat.and_two_pow_sub_one_eq_mod b 4
  simpa using this

theorem table_lower : ∀ v, v < 16 → isLowerHex (table.getD v 0) := by
  unfold isLowerHex
  decide

theorem nibble_table : ∀ v, v < 16 → nibble (table.getD v 0) = some v := by
  decide

theorem pair_value : ∀ hi, hi < 16 → ∀ lo, lo < 16 →
    (hi <<< 4) ||| lo = hi * 16 + lo := by
  decide

theorem encodeByte_lower (b : Nat) (hb : b < 256) :
    ∀ c ∈ encodeByte b, isLowerHex c := by
  intro c hc
  simp only [encodeByte, List.mem_cons, List.not_mem_nil, or_false] at hc
  rcases hc with hc | hc <;> subst hc
  · exact table_lower _ (by rw [shr4]; omega)
  · exact table_lower _ (by rw [and15]; omega)

theorem decode_encodeByte (b : Nat) (hb : b < 256) :
    nibble (table.getD (b >>> 4) 0) = some (b >>> 4) ∧
      nibble (table.getD (b &&& 0xf) 0) = some (b &&& 0xf) ∧
      ((b >>> 4) <<< 4) ||| (b &&& 0xf) = b := by
  have h1 : b >>> 4 < 16 := by rw [shr4]; omega
  have h2 : b &&& 0xf < 16 := by rw [and15]; omega
  refine ⟨nibble_table _ h1, nibble_table _ h2, ?_⟩
  rw [pair_value _ h1 _ h2, shr4, and15]
  omega

theorem pair_byte (hi lo : Nat) (hhi : hi < 16) (hlo : lo < 16) :
    (hi <<< 4) ||| lo < 256 ∧
      encodeByte ((hi <<< 4) ||| lo) = [table.getD hi 0, table.getD lo 0] := by
  rw [pair_value hi hhi lo hlo]
  refine ⟨by omega, ?_⟩
  simp only [encodeByte, shr4, and15]
  have e1 : (hi * 16 + lo) / 16 = hi := by omega
  have e2 : (hi * 16 + lo) % 16 = lo := by omega
  rw [e1, e2]

theorem nibble_lt (c v : Nat) (h : nibble c = some v) : v < 16 := by
  unfold nibble at h
  split at h
  · simp only [Option.some.injEq] at h; omega
  · split at h
    · simp only [Option.some.injEq] at h; omega
    · split at h
      · simp only [Option.some.injEq] at h; omega
      · simp at h

theorem table_nibble (c v : Nat) (h : nibble c = some v) :
    table.getD v 0 = lower c := by
  unfold nibble at h
  unfold lower
  split at h
  · simp only [Option.some.injEq] at h
    subst h
    have hc : c - 0x30 < 10 := by omega
    rw [ite_eq_right (by omega)]
    have := (by decide : ∀ k, k < 10 → table.getD k 0 = k + 0x30) _ hc
    omega
  · split at h
    · simp only [Option.some.injEq] at h
      subst h
      rw [ite_eq_right (by omega)]
      have := (by decide : ∀ k, k < 6 → table.getD (k + 10) 0 = k + 0x61)
        (c - 0x61) (by omega)
      omega
    · split at h
      · simp only [Option.some.injEq] at h
        subst h
        rw [ite_eq_left (by omega)]
        have := (by decide : ∀ k, k < 6 → table.getD (k + 10) 0 = k + 0x61)
          (c - 0x41) (by omega)
        omega
      · simp at h

/-! ### Encoding -/

theorem encode_cons (b : Nat) (bs : List Nat) :
    encode (b :: bs) = encodeByte b ++ encode bs := by
  simp [encode]

/-- An encoding is twice as long as its input. -/
theorem length_encode (bs : List Nat) : (encode bs).length = 2 * bs.length := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    rw [encode_cons, List.length_append, ih]
    simp [encodeByte]
    omega

/-- An encoding of bytes is lowercase hex. -/
theorem encode_lower (bs : List Nat) (h : ∀ b ∈ bs, b < 256) :
    ∀ c ∈ encode bs, isLowerHex c := by
  induction bs with
  | nil => simp [encode]
  | cons b bs ih =>
    intro c hc
    rw [encode_cons, List.mem_append] at hc
    rcases hc with hc | hc
    · exact encodeByte_lower b (h b List.mem_cons_self) c hc
    · exact ih (fun b' m => h b' (List.mem_cons_of_mem b m)) c hc

theorem decodePairs_encode (bs : List Nat) (h : ∀ b ∈ bs, b < 256) :
    decodePairs (encode bs) = some bs := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    have ⟨hh, hl, hv⟩ := decode_encodeByte b (h b List.mem_cons_self)
    rw [encode_cons]
    simp only [encodeByte, List.cons_append, List.nil_append, decodePairs, hh, hl,
      ih (fun b' m => h b' (List.mem_cons_of_mem b m)), Option.map_some, hv]

theorem sizeMul_two (n : Nat) (h : 2 * n ≤ sizeMax) : sizeMul n 2 = 2 * n := by
  unfold sizeMul
  split <;> omega

/-- `decode()` takes back what `encode_into()` writes, for bytes of
every count whose encoding fits in memory. -/
theorem decode_encode (bs : List Nat) (h : ∀ b ∈ bs, b < 256)
    (hfit : 2 * bs.length ≤ sizeMax) :
    decode (encode bs) bs.length = some bs := by
  unfold decode
  rw [length_encode, sizeMul_two _ hfit]
  simp only [ne_eq, not_true_eq_false, ite_false]
  exact decodePairs_encode bs h

/-! ### Decoding -/

/-- The loop of `decode()` takes exactly the even runs of hex digits,
and yields bytes that encode back to the digits in lowercase. -/
theorem decodePairs_some : ∀ s : List Nat,
    (decodePairs s ≠ none ↔ s.length % 2 = 0 ∧ ∀ c ∈ s, isHex c) ∧
    ∀ bs, decodePairs s = some bs →
      bs.length * 2 = s.length ∧ (∀ b ∈ bs, b < 256) ∧ encode bs = s.map lower
  | [] => by simp [decodePairs, encode]
  | [c] => by simp [decodePairs]
  | h :: l :: rest => by
    have ih := decodePairs_some rest
    cases hh : nibble h with
    | none =>
      have : isHex h = false := by simp [isHex, hh]
      simp [decodePairs, hh]
      intro _ hm
      simp_all
    | some hi =>
      cases hl : nibble l with
      | none =>
        have : isHex l = false := by simp [isHex, hl]
        simp [decodePairs, hh, hl]
        intro _ _ hm
        simp_all
      | some lo =>
        have hhi := nibble_lt h hi hh
        have hlo := nibble_lt l lo hl
        have ⟨hlt, he⟩ := pair_byte hi lo hhi hlo
        have ihx : isHex h = true ∧ isHex l = true := by simp [isHex, hh, hl]
        simp only [decodePairs, hh, hl]
        constructor
        · rw [ne_eq, Option.map_eq_none_iff, ← ne_eq, ih.1]
          simp only [List.length_cons, List.mem_cons, forall_eq_or_imp, ihx,
            true_and]
          constructor
          · intro ⟨h1, h2⟩; exact ⟨by omega, h2⟩
          · intro ⟨h1, h2⟩; exact ⟨by omega, h2⟩
        · intro bs hbs
          cases hr : decodePairs rest with
          | none => simp [hr] at hbs
          | some bs' =>
            simp only [hr, Option.map_some, Option.some.injEq] at hbs
            subst hbs
            have ⟨h1, h2, h3⟩ := ih.2 bs' hr
            refine ⟨by simp; omega, ?_, ?_⟩
            · intro b hb
              simp only [List.mem_cons] at hb
              rcases hb with hb | hb
              · rw [hb]; exact hlt
              · exact h2 b hb
            · rw [encode_cons, he, h3, table_nibble h hi hh, table_nibble l lo hl]
              rfl

/-- `hex_decode(hex, out, n)` takes exactly the strings of `2 * n` hex
digits of either case, and yields `n` bytes that `encode_into()` writes
back as the digits in lowercase. -/
theorem decode_spec (s : List Nat) (n : Nat) (hs : s.length < sizeMax) :
    (decode s n ≠ none ↔ s.length = 2 * n ∧ ∀ c ∈ s, isHex c) ∧
    ∀ bs, decode s n = some bs →
      bs.length = n ∧ (∀ b ∈ bs, b < 256) ∧ encode bs = s.map lower := by
  have hm : s.length = sizeMul n 2 ↔ s.length = 2 * n := by
    unfold sizeMul
    split <;> omega
  have hp := decodePairs_some s
  unfold decode
  constructor
  · by_cases hl : s.length = sizeMul n 2
    · rw [ite_eq_right (fun e => e hl), hp.1, hm.1 hl]
      simp only [true_and]
      constructor
      · intro ⟨_, h⟩; exact h
      · intro h; exact ⟨by omega, h⟩
    · rw [ite_eq_left hl]
      simp only [ne_eq, not_true_eq_false, false_iff, not_and]
      intro e; exact absurd (hm.2 e) hl
  · intro bs h
    by_cases hl : s.length = sizeMul n 2
    · rw [ite_eq_right (fun e => e hl)] at h
      have ⟨h1, h2, h3⟩ := hp.2 bs h
      exact ⟨by have := hm.1 hl; omega, h2, h3⟩
    · rw [ite_eq_left hl] at h; simp at h

/-- Bytes are determined by their encoding: the decoding of any string is
the only input whose encoding is that string in lowercase. -/
theorem encode_injective (a b : List Nat) (ha : ∀ x ∈ a, x < 256)
    (hb : ∀ x ∈ b, x < 256) (h : encode a = encode b) : a = b := by
  have e := decodePairs_encode a ha
  rw [h, decodePairs_encode b hb] at e
  exact (Option.some.inj e).symm

/-- `hex_decode_max(hex, out, cap, len)` takes exactly the even runs of hex
digits of either case, none at all included, of at most `2 * cap` digits,
and yields half as many bytes as there are digits, which encode back to
the digits in lowercase. -/
theorem decodeMax_spec (s : List Nat) (cap : Nat) (hs : s.length < sizeMax) :
    (decodeMax s cap ≠ none ↔
      s.length % 2 = 0 ∧ s.length / 2 ≤ cap ∧ ∀ c ∈ s, isHex c) ∧
    ∀ bs, decodeMax s cap = some bs →
      bs.length * 2 = s.length ∧ (∀ b ∈ bs, b < 256) ∧
        encode bs = s.map lower := by
  have hn : min s.length (sizeAdd (sizeMul cap 2) 1) =
      if s.length ≤ 2 * cap then s.length else 2 * cap + 1 := by
    unfold sizeAdd sizeMul
    split <;> split <;> split <;> omega
  have hd := decode_spec s (s.length / 2) hs
  by_cases hok : s.length % 2 = 0 ∧ s.length ≤ 2 * cap
  · have e : decodeMax s cap = decode s (s.length / 2) := by
      unfold decodeMax
      simp only [hn, hok.2, ite_true]
      rw [ite_eq_right (by omega)]
    rw [e]
    constructor
    · rw [hd.1]
      constructor
      · intro ⟨_, h⟩; exact ⟨hok.1, by omega, h⟩
      · intro ⟨_, _, h⟩; exact ⟨by omega, h⟩
    · intro bs h
      have ⟨h1, h2, h3⟩ := hd.2 bs h
      exact ⟨by omega, h2, h3⟩
  · have e : decodeMax s cap = none := by
      unfold decodeMax
      simp only [hn]
      split
      · rw [ite_eq_left (by omega)]
      · rw [ite_eq_left (by omega)]
    rw [e]
    constructor
    · simp only [ne_eq, not_true_eq_false, false_iff, not_and]
      intro h1 h2; exact absurd ⟨h1, by omega⟩ hok
    · intro bs h; simp at h

end Shirudo.Hex
