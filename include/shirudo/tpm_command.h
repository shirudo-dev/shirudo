/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TPM_COMMAND_H
#define SHIRUDO_TPM_COMMAND_H

/* The includer supplies types, __always_inline and a bounded kernel/user copy. */
enum shirudo_tpm_access {
	SHIRUDO_TPM_PUBLIC,
	SHIRUDO_TPM_RUNTIME,
	SHIRUDO_TPM_MALFORMED,
};

static __always_inline bool shirudo_tpm_allowed(enum shirudo_tpm_access access,
						bool runtime)
{
	return access != SHIRUDO_TPM_MALFORMED &&
	       (access == SHIRUDO_TPM_PUBLIC || runtime);
}

static __always_inline int
shirudo_tpm_word(const __u8 *command, __u32 length, __u32 offset,
		 __u32 width, __u32 *value)
{
	__u8 bytes[4] = {};

	if (offset > length || width > length - offset ||
	    SHIRUDO_TPM_COPY(bytes, command + offset, width))
		return -1;
	if (width == 2)
		*value = ((__u32)bytes[0] << 8) | bytes[1];
	else
		*value = ((__u32)bytes[0] << 24) | ((__u32)bytes[1] << 16) |
			 ((__u32)bytes[2] << 8) | bytes[3];
	return 0;
}

/*
 * systemd defines its NvPCRs (verity, hardware, login, cryptsetup, ...) in the
 * UAPI.19 Linux range from the initrd, before the guards attach, and anchors
 * each in PCR 9. Afterwards it only extends them, as root. Deleting and
 * recreating one would replace the register its anchor names, so every
 * mutation but an extension needs the full role.
 */
static __always_inline bool shirudo_tpm_nvpcr(__u32 index)
{
	return index >= 0x01d10200u && index <= 0x01d105ffu;
}

static __always_inline enum shirudo_tpm_access
shirudo_tpm_nv(__u32 index, bool extend)
{
	/*
	 * 0x01818e00 is Shirudo's measurement register (NV_INDEX), 0x01818e04
	 * the config NvPCR: its extensions are config events.
	 */
	if (index == 0x01818e00u || index == 0x01818e04u)
		return SHIRUDO_TPM_RUNTIME;
	if (shirudo_tpm_nvpcr(index) && !extend)
		return SHIRUDO_TPM_RUNTIME;
	return SHIRUDO_TPM_PUBLIC;
}

static __always_inline enum shirudo_tpm_access
shirudo_tpm_access(const __u8 *command, __u32 length, __u32 config_pcr)
{
	__u32 tag, declared, code, target, offset, size;

	if (!command || length < 10 || length > 4096 ||
	    shirudo_tpm_word(command, length, 0, 2, &tag) ||
	    (tag != 0x8001 && tag != 0x8002) ||
	    shirudo_tpm_word(command, length, 2, 4, &declared) || declared != length ||
	    shirudo_tpm_word(command, length, 6, 4, &code))
		return SHIRUDO_TPM_MALFORMED;
	switch (code) {
	case 0x00000121u: /* HierarchyControl */
	case 0x00000124u: /* ChangeEPS */
	case 0x00000125u: /* ChangePPS */
	case 0x00000126u: /* Clear */
	case 0x00000127u: /* ClearControl */
	case 0x00000128u: /* ClockSet */
	case 0x00000129u: /* HierarchyChangeAuth */
	case 0x0000012bu: /* PCR_Allocate */
	case 0x0000012cu: /* PCR_SetAuthPolicy */
	case 0x0000012du: /* PP_Commands */
	case 0x0000012eu: /* SetPrimaryPolicy */
	case 0x0000012fu: /* FieldUpgradeStart */
	case 0x00000130u: /* ClockRateAdjust */
	case 0x00000132u: /* NV_GlobalWriteLock */
	case 0x00000139u: /* DictionaryAttackLockReset */
	case 0x0000013au: /* DictionaryAttackParameters */
	case 0x0000013fu: /* SetAlgorithmSet */
	case 0x00000140u: /* SetCommandCodeAuditStatus */
	case 0x00000141u: /* FieldUpgradeData */
	case 0x00000145u: /* Shutdown */
	case 0x00000198u: /* ACT_SetTimeout */
		return SHIRUDO_TPM_RUNTIME;
	case 0x0000013cu: /* PCR_Event */
	case 0x0000013du: /* PCR_Reset */
	case 0x00000182u: /* PCR_Extend */
	case 0x00000183u: /* PCR_SetAuthValue */
	case 0x00000185u: /* EventSequenceComplete */
		if (shirudo_tpm_word(command, length, 10, 4, &target))
			return SHIRUDO_TPM_MALFORMED;
		if (target == config_pcr)
			return SHIRUDO_TPM_RUNTIME;
		/*
		 * Every other PCR belongs to the platform: systemd's
		 * pcrmachine and pcrfs extend PCR 15 as root, for example.
		 */
		return SHIRUDO_TPM_PUBLIC;
	case 0x0000011fu: /* NV_UndefineSpaceSpecial */
	case 0x0000013bu: /* NV_ChangeAuth */
		if (shirudo_tpm_word(command, length, 10, 4, &target))
			return SHIRUDO_TPM_MALFORMED;
		return shirudo_tpm_nv(target, false);
	case 0x00000122u: /* NV_UndefineSpace */
	case 0x00000134u: /* NV_Increment */
	case 0x00000135u: /* NV_SetBits */
	case 0x00000136u: /* NV_Extend */
	case 0x00000137u: /* NV_Write */
	case 0x00000138u: /* NV_WriteLock */
	case 0x0000014fu: /* NV_ReadLock */
		if (shirudo_tpm_word(command, length, 14, 4, &target))
			return SHIRUDO_TPM_MALFORMED;
		return shirudo_tpm_nv(target, code == 0x00000136u);
	case 0x0000012au: /* NV_DefineSpace */
		offset = 14;
		if (tag == 0x8002) {
			if (shirudo_tpm_word(command, length, offset, 4, &size) ||
			    size > length - 18)
				return SHIRUDO_TPM_MALFORMED;
			offset = 18 + size;
		}
		if (shirudo_tpm_word(command, length, offset, 2, &size) ||
		    size > length - offset - 2)
			return SHIRUDO_TPM_MALFORMED;
		offset += 2 + size;
		if (shirudo_tpm_word(command, length, offset, 2, &size) ||
		    size < 14 || size != length - offset - 2 ||
		    shirudo_tpm_word(command, length, offset + 2, 4, &target))
			return SHIRUDO_TPM_MALFORMED;
		return shirudo_tpm_nv(target, false);
	case 0x00000120u: /* EvictControl */
	case 0x00000131u: /* CreatePrimary */
	case 0x00000133u: /* GetCommandAuditDigest */
	case 0x0000013eu: /* SequenceComplete */
	case 0x00000142u: /* IncrementalSelfTest */
	case 0x00000143u: /* SelfTest */
	case 0x00000144u: /* Startup: already initialized before guards attach. */
	case 0x00000146u: /* StirRandom */
	case 0x00000147u: /* ActivateCredential */
	case 0x00000148u: /* Certify */
	case 0x00000149u: /* PolicyNV */
	case 0x0000014au: /* CertifyCreation */
	case 0x0000014bu: /* Duplicate */
	case 0x0000014cu: /* GetTime */
	case 0x0000014du: /* GetSessionAuditDigest */
	case 0x0000014eu: /* NV_Read */
	case 0x00000150u: /* ObjectChangeAuth */
	case 0x00000151u: /* PolicySecret */
	case 0x00000152u: /* Rewrap */
	case 0x00000153u: /* Create */
	case 0x00000154u: /* ECDH_ZGen */
	case 0x00000155u: /* MAC */
	case 0x00000156u: /* Import */
	case 0x00000157u: /* Load */
	case 0x00000158u: /* Quote */
	case 0x00000159u: /* RSA_Decrypt */
	case 0x0000015bu: /* MAC_Start */
	case 0x0000015cu: /* SequenceUpdate */
	case 0x0000015du: /* Sign */
	case 0x0000015eu: /* Unseal */
	case 0x00000160u: /* PolicySigned */
	case 0x00000161u: /* ContextLoad */
	case 0x00000162u: /* ContextSave */
	case 0x00000163u: /* ECDH_KeyGen */
	case 0x00000164u: /* EncryptDecrypt */
	case 0x00000165u: /* FlushContext */
	case 0x00000167u: /* LoadExternal */
	case 0x00000168u: /* MakeCredential */
	case 0x00000169u: /* NV_ReadPublic */
	case 0x0000016au: /* PolicyAuthorize */
	case 0x0000016bu: /* PolicyAuthValue */
	case 0x0000016cu: /* PolicyCommandCode */
	case 0x0000016du: /* PolicyCounterTimer */
	case 0x0000016eu: /* PolicyCpHash */
	case 0x0000016fu: /* PolicyLocality */
	case 0x00000170u: /* PolicyNameHash */
	case 0x00000171u: /* PolicyOR */
	case 0x00000172u: /* PolicyTicket */
	case 0x00000173u: /* ReadPublic */
	case 0x00000174u: /* RSA_Encrypt */
	case 0x00000176u: /* StartAuthSession */
	case 0x00000177u: /* VerifySignature */
	case 0x00000178u: /* ECC_Parameters */
	case 0x00000179u: /* FirmwareRead */
	case 0x0000017au: /* GetCapability */
	case 0x0000017bu: /* GetRandom */
	case 0x0000017cu: /* GetTestResult */
	case 0x0000017du: /* Hash */
	case 0x0000017eu: /* PCR_Read */
	case 0x0000017fu: /* PolicyPCR */
	case 0x00000180u: /* PolicyRestart */
	case 0x00000181u: /* ReadClock */
	case 0x00000184u: /* NV_Certify */
	case 0x00000186u: /* HashSequenceStart */
	case 0x00000187u: /* PolicyPhysicalPresence */
	case 0x00000188u: /* PolicyDuplicationSelect */
	case 0x00000189u: /* PolicyGetDigest */
	case 0x0000018au: /* TestParms */
	case 0x0000018bu: /* Commit */
	case 0x0000018cu: /* PolicyPassword */
	case 0x0000018du: /* ZGen_2Phase */
	case 0x0000018eu: /* EC_Ephemeral */
	case 0x0000018fu: /* PolicyNvWritten */
	case 0x00000190u: /* PolicyTemplate */
	case 0x00000191u: /* CreateLoaded */
	case 0x00000192u: /* PolicyAuthorizeNV */
	case 0x00000193u: /* EncryptDecrypt2 */
	case 0x00000194u: /* AC_GetCapability */
	case 0x00000195u: /* AC_Send */
	case 0x00000196u: /* Policy_AC_SendSelect */
	case 0x00000197u: /* CertifyX509 */
		return SHIRUDO_TPM_PUBLIC;
	default:
		/* Unknown/vendor commands need full runtime authority. */
		return SHIRUDO_TPM_RUNTIME;
	}
}

#endif /* SHIRUDO_TPM_COMMAND_H */
