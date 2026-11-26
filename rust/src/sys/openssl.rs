// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libcrypto and libssl calls neither the `openssl` crate wraps nor
//! `openssl-sys` declares, on `openssl-sys`'s types so that they take
//! what the crate's objects hold.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use openssl_sys::{
    ASN1_INTEGER, ASN1_OCTET_STRING, BIO, CMS_ContentInfo, EVP_MD, EVP_PKEY, EVP_PKEY_CTX,
    OPENSSL_STACK, SSL, SSL_CTX, X509, X509_NAME, X509_STORE,
};

/// An `X509_PUBKEY`.
pub enum X509Pubkey {}
/// A `CMS_SignerInfo`.
pub enum CmsSignerInfo {}
/// An `EVP_ENCODE_CTX`.
pub enum EvpEncodeCtx {}

pub const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x80;
pub const CMS_NO_SIGNING_TIME: c_uint = 0x40_0000;
pub const XN_FLAG_ONELINE: c_ulong = 0x82_031f;
pub const XN_FLAG_SPC_EQ: c_ulong = 0x80_0000;
pub const SSL_CB_HANDSHAKE_DONE: c_int = 0x20;
pub const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;

/// libssl's info callback.
pub type InfoCallback = unsafe extern "C" fn(ssl: *const SSL, kind: c_int, val: c_int);

unsafe extern "C" {
    pub fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);

    pub fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_get0_type_name(key: *const EVP_PKEY) -> *const c_char;
    /// libcrypto's own, which takes `label` over; openssl-sys has the
    /// EVP_PKEY_CTX_ctrl() form of the macro before OpenSSL 3 instead.
    pub fn EVP_PKEY_CTX_set0_rsa_oaep_label(
        ctx: *mut EVP_PKEY_CTX,
        label: *mut c_void,
        llen: c_int,
    ) -> c_int;

    pub fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509Pubkey;
    pub fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut u8) -> c_int;
    pub fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: c_int,
        flags: c_ulong,
    ) -> c_int;
    pub fn X509_NAME_oneline(a: *const X509_NAME, buf: *mut c_char, size: c_int) -> *mut c_char;
    pub fn X509_STORE_load_file(ctx: *mut X509_STORE, file: *const c_char) -> c_int;

    pub fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut OPENSSL_STACK;
    pub fn CMS_SignerInfo_cert_cmp(si: *mut CmsSignerInfo, cert: *mut X509) -> c_int;
    pub fn CMS_SignerInfo_get0_signer_id(
        si: *mut CmsSignerInfo,
        key: *mut *mut ASN1_OCTET_STRING,
        issuer: *mut *mut X509_NAME,
        serial: *mut *mut ASN1_INTEGER,
    ) -> c_int;
    pub fn CMS_add1_signer(
        cms: *mut CMS_ContentInfo,
        signer: *mut X509,
        pk: *mut EVP_PKEY,
        md: *const EVP_MD,
        flags: c_uint,
    ) -> *mut CmsSignerInfo;
    pub fn CMS_final(
        cms: *mut CMS_ContentInfo,
        data: *mut BIO,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;

    pub fn EVP_ENCODE_CTX_new() -> *mut EvpEncodeCtx;
    pub fn EVP_ENCODE_CTX_free(ctx: *mut EvpEncodeCtx);
    pub fn EVP_DecodeInit(ctx: *mut EvpEncodeCtx);
    pub fn EVP_DecodeUpdate(
        ctx: *mut EvpEncodeCtx,
        out: *mut u8,
        outl: *mut c_int,
        inp: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_DecodeFinal(ctx: *mut EvpEncodeCtx, out: *mut u8, outl: *mut c_int) -> c_int;

    pub fn SSL_group_to_name(s: *mut SSL, id: c_int) -> *const c_char;
    pub fn SSL_CTX_set_info_callback(ctx: *mut SSL_CTX, cb: Option<InfoCallback>);
}
