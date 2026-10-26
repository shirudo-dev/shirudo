#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0033 -- util/tpm_wire: the policy digests the register is defined
# under, NV and object names, and the attestation structures the
# verifier parses, each against values computed independently here.

cd "$(dirname "$0")/.."
. ./test-lib.sh

H=helper/test-tpm-wire
Z=0000000000000000000000000000000000000000000000000000000000000000

py() { python3 -c "$1"; }
PUB=$(py 'import struct; print((struct.pack(">HHIHHHHHIH", 1, 11, 0x40000, 0, 16, 20, 11, 3072, 65537, 384) + bytes.fromhex("80" + "00"*382 + "01")).hex())')
MODULUS=$(py 'print("80" + "00"*382 + "01")')

test_expect_success 'the writer public area fixes RSA-3072, RSASSA and SHA-256' '
	[ "$(./$H writer-public "$MODULUS")" = "$PUB" ] &&
	zero=$(py "print(\"00\"*384)") &&
	even=$(py "print(\"80\" + \"00\"*383)") &&
	[ "$(./$H writer-public "$zero")" = "$(printf "%s" "$PUB" | cut -c1-48)$zero" ] &&
	[ "$(./$H writer-public "$even")" = "$(printf "%s" "$PUB" | cut -c1-48)$even" ] &&
	! ./$H writer-public 00 &&
	! ./$H writer-public "$PUB"
'

test_expect_success 'PolicyNvWritten(YES) = H(prev || CC || 01)' '
	want=$(py "import hashlib; print(hashlib.sha256(bytes(32) + bytes.fromhex(\"0000018f01\")).hexdigest())") &&
	[ "$(./$H nv-written $Z 1)" = "$want" ]
'

test_expect_success 'PolicyPCR folds the SHA-256 selection of PCR 15 and the digest' '
	d=$(py "print(\"ab\"*32)") &&
	want=$(py "import hashlib; print(hashlib.sha256(bytes(32) + bytes.fromhex(\"0000017f\") + bytes.fromhex(\"00000001000b03008000\") + bytes.fromhex(\"ab\"*32)).hexdigest())") &&
	[ "$(./$H pcr $Z 0x8000 $d)" = "$want" ]
'

test_expect_success 'PolicyOR starts from zero and folds both branches' '
	a=$(py "print(\"11\"*32)") && b=$(py "print(\"22\"*32)") &&
	want=$(py "import hashlib; print(hashlib.sha256(bytes(32) + bytes.fromhex(\"00000171\") + bytes.fromhex(\"11\"*32) + bytes.fromhex(\"22\"*32)).hexdigest())") &&
	[ "$(./$H or $a $b)" = "$want" ]
'

test_expect_success 'PolicySigned binds the writer Name and policy reference' '
	p=$(py "print(\"12\"*32)") &&
	want=$(py "import hashlib; name=bytes.fromhex(\"000b\")+hashlib.sha256(bytes.fromhex(\"$PUB\")).digest(); d=hashlib.sha256(bytes.fromhex(\"$p\")+bytes.fromhex(\"00000160\")+name).digest(); print(hashlib.sha256(d+b\"shirudo-nv-writer-v1\").hexdigest())") &&
	[ "$(./$H policy-signed $p $MODULUS)" = "$want" ]
'

test_expect_success 'PolicyCommandCode folds the authorized command as a u32' '
	p=$(py "print(\"34\"*32)") &&
	want=$(py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"34\"*32 + \"0000016c00000136\")).hexdigest())") &&
	[ "$(./$H command-code $p 0x136)" = "$want" ] &&
	[ "$(./$H command-code $p 0x137)" != "$want" ]
'

test_expect_success 'register final policy requires the writer and only NV_Extend' '
	a=$(py "print(\"11\"*32)") && b=$(py "print(\"22\"*32)") &&
	want=$(py "
import hashlib
digest = hashlib.sha256(bytes(32) + bytes.fromhex(\"00000171\" + \"11\"*32 + \"22\"*32)).digest()
name = bytes.fromhex(\"000b\") + hashlib.sha256(bytes.fromhex(\"$PUB\")).digest()
digest = hashlib.sha256(digest + bytes.fromhex(\"00000160\") + name).digest()
digest = hashlib.sha256(digest + b\"shirudo-nv-writer-v1\").digest()
print(hashlib.sha256(digest + bytes.fromhex(\"0000016c00000136\")).hexdigest())
") &&
	[ "$(./$H register-final $a $b $MODULUS)" = "$want" ] &&
	[ "$(./$H or $a $b)" != "$want" ]
'

test_expect_success 'register policy branches match independent vectors' '
	v9=$(py "print(\"cd\"*32)") && v11=$(py "print(\"ef\"*32)") &&
	out=$(./$H register-policy 0xa00 $v9 $v11) &&
	want=$(py "
import hashlib
def h(data):
    return hashlib.sha256(data).digest()
written = h(bytes(32) + bytes.fromhex(\"0000018f01\"))
unwritten = h(bytes(32) + bytes.fromhex(\"0000018f00\"))
values = h(bytes.fromhex(\"cd\"*32 + \"ef\"*32))
init = h(unwritten + bytes.fromhex(\"0000017f00000001000b03000a00\") + values)
policy = h(bytes(32) + bytes.fromhex(\"00000171\") + written + init)
print(written.hex())
print(init.hex())
print(policy.hex())
") &&
	[ "$out" = "$want" ]
'

test_expect_success 'NV_Extend cpHash includes both Names and the TPM2B event' '
	name=000b$(py "print(\"ab\"*32)") &&
	event=$(py "print(\"cd\"*32)") &&
	want=$(py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"00000136$name$name\"+\"0020\"+\"$event\")).hexdigest())") &&
	[ "$(./$H extend-cphash "$name" "$event")" = "$want" ]
'

test_expect_success 'writer authorization covers nonce, zero expiry, cpHash and reference' '
	cp=$(py "print(\"cd\"*32)") &&
	for length in 1 32 64; do
		nonce=$(py "print(\"ab\"*$length)") &&
		want=$(py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"$nonce\"+\"00000000\"+\"$cp\")+b\"shirudo-nv-writer-v1\").hexdigest())") &&
		[ "$(./$H writer-auth "$nonce" "$cp")" = "$want" ] || exit 1
	done &&
	! ./$H writer-auth "" "$cp"
'

test_expect_success 'NV name = 000b || H(TPMS_NV_PUBLIC)' '
	p=$(py "print(\"ef\"*32)") &&
	want=$(py "import hashlib; print(\"000b\" + hashlib.sha256(bytes.fromhex(\"01818e00\") + bytes.fromhex(\"000b\") + bytes.fromhex(\"0e060048\") + bytes.fromhex(\"0020\") + bytes.fromhex(\"ef\"*32) + bytes.fromhex(\"0020\")).hexdigest())") &&
	[ "$(./$H nv-name 0x01818e00 0x0e060048 $p)" = "$want" ]
'

test_expect_success 'a P-256 ECDSA public area parses and names itself' '
	x=$(py "print(\"33\"*32)") && y=$(py "print(\"44\"*32)") &&
	pub="0023000b000500320000001000180003000b0010" &&
	pub="0023000b00050032000000100018000b00030010""0020$x""0020$y" &&
	out=$(./$H ecc-public $pub) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "attrs=0x00050032 scheme=0x0018 hash=0x000b curve=0x0003" &&
	want=$(py "import hashlib; print(\"000b\" + hashlib.sha256(bytes.fromhex(\"$pub\")).hexdigest())") &&
	[ "$(./$H object-name $pub)" = "$want" ]
'

test_expect_success 'a public area with another curve or scheme is refused' '
	x=$(py "print(\"33\"*32)") && y=$(py "print(\"44\"*32)") &&
	./$H ecc-public "0023000b00050032000000100018000b00040010""0020$x""0020$y" | grep -qx "rc=-93"
'

test_expect_success 'an ECDSA signature yields r and s' '
	r=$(py "print(\"55\"*32)") && s=$(py "print(\"66\"*32)") &&
	out=$(./$H signature "0018000b0020$r""0020$s") &&
	echo "$out" | grep -qx "rc=0" &&
	[ "$(echo "$out" | sed -n 2p)" = "$r" ] &&
	[ "$(echo "$out" | sed -n 3p)" = "$s" ]
'

test_expect_success 'a quote attestation parses: signer, nonce, selection, digest' '
	name=$(py "print(\"000b\" + \"77\"*32)") && dg=$(py "print(\"88\"*32)") &&
	blob="ff544347""8018""0022$name""00046e6f6e63""0000000000000100""00000002""00000003""01""0000000000000004""00000001000b03fffa00""0020$dg" &&
	out=$(./$H attest $blob) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "type=0x8018 reset=2 restart=3 safe=1" &&
	echo "$out" | grep -qx "signer=$name" &&
	echo "$out" | grep -qx "extra=6e6f6e63" &&
	echo "$out" | grep -qx "mask=0x00faff" &&
	echo "$out" | grep -qx "pcr_digest=$dg"
'

test_expect_success 'an NV certification parses: index name, offset, contents' '
	name=$(py "print(\"000b\" + \"77\"*32)") && iname=$(py "print(\"000b\" + \"99\"*32)") &&
	val=$(py "print(\"aa\"*32)") &&
	blob="ff544347""8014""0022$name""0000""0000000000000100""00000002""00000003""00""0000000000000004""0022$iname""0000""0020$val" &&
	out=$(./$H attest $blob) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "index_name=$iname" &&
	echo "$out" | grep -qx "offset=0" &&
	echo "$out" | grep -qx "nv=$val"
'

test_expect_success 'a truncated or mis-tagged attestation is rejected' '
	./$H attest "ff54434780180022" | grep -qx "rc=-22" &&
	./$H attest "ff544348801800020000" | grep -qx "rc=-22"
'

test_expect_success 'the endorsement policy is PolicySecret over the endorsement hierarchy' '
	[ "$(./$H ek-policy)" = "$(py "import hashlib; h = hashlib.sha256(bytes(32) + bytes.fromhex(\"00000151\") + bytes.fromhex(\"4000000b\")).digest(); print(hashlib.sha256(h).hexdigest())")" ]
'

test_expect_success 'KDFa and KDFe derive as the TPM does' '
	key=$(py "print(\"11\" * 32)") &&
	name=000b$(py "print(\"22\" * 32)") &&
	[ "$(./$H kdfa $key STORAGE $name 16)" = "$(py "import hmac, hashlib; print(hmac.new(bytes.fromhex(\"$key\"), (1).to_bytes(4, \"big\") + b\"STORAGE\\0\" + bytes.fromhex(\"$name\") + (128).to_bytes(4, \"big\"), hashlib.sha256).hexdigest()[:32])")" ] &&
	[ "$(./$H kdfa $key INTEGRITY - 32)" = "$(py "import hmac, hashlib; print(hmac.new(bytes.fromhex(\"$key\"), (1).to_bytes(4, \"big\") + b\"INTEGRITY\\0\" + (256).to_bytes(4, \"big\"), hashlib.sha256).hexdigest())")" ] &&
	[ "$(./$H kdfe $key IDENTITY $name $name)" = "$(py "import hashlib; print(hashlib.sha256((1).to_bytes(4, \"big\") + bytes.fromhex(\"$key\") + b\"IDENTITY\\0\" + bytes.fromhex(\"$name\") * 2).hexdigest())")" ]
'

test_expect_success 'the credential blob is the TPM2B_ID_OBJECT of Part 1, 24.4' '
	seed=$(py "print(\"33\" * 32)") &&
	name=000b$(py "print(\"44\" * 32)") &&
	cred=$(py "print(\"55\" * 32)") &&
	blob=$(./$H credential $seed $name $cred) &&
	[ "${#blob}" = 136 ] &&
	[ "$(echo "$blob" | cut -c1-4)" = 0020 ] &&
	if py "import cryptography" 2>/dev/null; then
		[ "$blob" = "$(py "
import hmac, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
seed, name, cred = (bytes.fromhex(h) for h in (\"$seed\", \"$name\", \"$cred\"))
def kdfa(key, label, ctx, n):
    return hmac.new(key, (1).to_bytes(4, \"big\") + label + b\"\\0\" + ctx + (n * 8).to_bytes(4, \"big\"), hashlib.sha256).digest()[:n]
enc = Cipher(algorithms.AES(kdfa(seed, b\"STORAGE\", name, 16)), modes.CFB(bytes(16))).encryptor()
e = enc.update((32).to_bytes(2, \"big\") + cred) + enc.finalize()
mac = hmac.new(kdfa(seed, b\"INTEGRITY\", b\"\", 32), e + name, hashlib.sha256).digest()
print(((32).to_bytes(2, \"big\") + mac + e).hex())
")" ]
	else
		echo "python cryptography missing; blob format not cross-checked" >&2
	fi
'

test_done
