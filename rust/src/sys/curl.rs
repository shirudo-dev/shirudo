// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The part of libcurl's easy interface shirudo uses, with the values of
//! curl.h. An option takes a `c_long`, a `CurlOff`, a pointer or a
//! callback, as curl_easy_setopt(3) lists it, and nothing else; the
//! options util/curl.rs sets safely carry what they take in their type.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

/// A `CURL *` handle.
pub enum Curl {}

/// A `struct curl_slist`, which curl allocates and frees.
pub enum CurlSlist {}

/// A `CURLU *` URL handle.
pub enum CurlU {}

pub type CurlCode = c_int;
pub type CurlOff = i64;
pub type WriteCallback =
    unsafe extern "C" fn(ptr: *mut c_char, size: usize, nmemb: usize, ud: *mut c_void) -> usize;
/// The callback of `CURLOPT_READFUNCTION`, given room to fill.
pub type ReadCallback =
    unsafe extern "C" fn(buffer: *mut c_char, size: usize, n: usize, ud: *mut c_void) -> usize;
/// The callback of `CURLOPT_SSL_CTX_FUNCTION`, given the `SSL_CTX`.
pub type SslCtxCallback =
    unsafe extern "C" fn(curl: *mut Curl, ssl_ctx: *mut c_void, userptr: *mut c_void) -> CurlCode;
/// A `CURLUcode`.
pub type CurlUCode = c_int;
/// A `CURLUPart`.
pub type CurlUPart = c_int;

/// An option of `CURLOPTTYPE_LONG` or `CURLOPTTYPE_VALUES`, which takes
/// a long. Only this module makes one.
#[derive(Clone, Copy)]
pub struct LongOption(c_int);

/// An option of `CURLOPTTYPE_OFF_T`, which takes a curl_off_t, that
/// bounds no buffer of the caller's. Only this module makes one.
#[derive(Clone, Copy)]
pub struct OffOption(c_int);

/// An option of `CURLOPTTYPE_STRINGPOINT` whose string libcurl copies.
/// Only this module makes one.
#[derive(Clone, Copy)]
pub struct StrOption(c_int);

impl LongOption {
    pub const fn id(self) -> c_int {
        self.0
    }
}

impl OffOption {
    pub const fn id(self) -> c_int {
        self.0
    }
}

impl StrOption {
    pub const fn id(self) -> c_int {
        self.0
    }
}

pub const CURLE_OK: CurlCode = 0;
pub const CURL_GLOBAL_DEFAULT: c_long = 3;
pub const CURLE_SSL_CONNECT_ERROR: CurlCode = 35;
pub const CURLE_BAD_FUNCTION_ARGUMENT: CurlCode = 43;
pub const CURLE_SSL_CIPHER: CurlCode = 59;
pub const CURLE_FILESIZE_EXCEEDED: CurlCode = 63;
pub const CURLE_SSL_CACERT_BADFILE: CurlCode = 77;
pub const CURL_ERROR_SIZE: usize = 256;

pub const CURLOPT_TIMEOUT: LongOption = LongOption(13);
pub const CURLOPT_LOW_SPEED_LIMIT: LongOption = LongOption(19);
pub const CURLOPT_LOW_SPEED_TIME: LongOption = LongOption(20);
pub const CURLOPT_SSLVERSION: LongOption = LongOption(32);
pub const CURLOPT_NOBODY: LongOption = LongOption(44);
pub const CURLOPT_FAILONERROR: LongOption = LongOption(45);
pub const CURLOPT_UPLOAD: LongOption = LongOption(46);
pub const CURLOPT_POST: LongOption = LongOption(47);
pub const CURLOPT_FOLLOWLOCATION: LongOption = LongOption(52);
pub const CURLOPT_SSL_VERIFYPEER: LongOption = LongOption(64);
pub const CURLOPT_MAXREDIRS: LongOption = LongOption(68);
pub const CURLOPT_FORBID_REUSE: LongOption = LongOption(75);
pub const CURLOPT_CONNECTTIMEOUT: LongOption = LongOption(78);
pub const CURLOPT_HTTPGET: LongOption = LongOption(80);
pub const CURLOPT_SSL_VERIFYHOST: LongOption = LongOption(81);
pub const CURLOPT_NOSIGNAL: LongOption = LongOption(99);
pub const CURLOPT_UNRESTRICTED_AUTH: LongOption = LongOption(105);
pub const CURLOPT_SSL_SESSIONID_CACHE: LongOption = LongOption(150);
pub const CURLOPT_TIMEOUT_MS: LongOption = LongOption(155);

pub const CURLOPT_INFILESIZE_LARGE: OffOption = OffOption(30115);
pub const CURLOPT_MAXFILESIZE_LARGE: OffOption = OffOption(30117);

pub const CURLOPT_URL: StrOption = StrOption(10002);
pub const CURLOPT_USERPWD: StrOption = StrOption(10005);
pub const CURLOPT_USERAGENT: StrOption = StrOption(10018);
pub const CURLOPT_SSLCERT: StrOption = StrOption(10025);
pub const CURLOPT_CUSTOMREQUEST: StrOption = StrOption(10036);
pub const CURLOPT_CAINFO: StrOption = StrOption(10065);
pub const CURLOPT_SSLKEY: StrOption = StrOption(10087);
pub const CURLOPT_AWS_SIGV4: StrOption = StrOption(10305);
pub const CURLOPT_PROTOCOLS_STR: StrOption = StrOption(10318);
pub const CURLOPT_REDIR_PROTOCOLS_STR: StrOption = StrOption(10319);

// The options that point at the caller's memory, which libcurl keeps
// or calls back with until the handle goes: util/curl.rs sets each with
// what it points at.
pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLOPT_READDATA: c_int = 10009;
pub const CURLOPT_ERRORBUFFER: c_int = 10010;
pub const CURLOPT_POSTFIELDS: c_int = 10015;
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_HEADERDATA: c_int = 10029;
pub const CURLOPT_SSL_CTX_DATA: c_int = 10109;
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_READFUNCTION: c_int = 20012;
pub const CURLOPT_HEADERFUNCTION: c_int = 20079;
pub const CURLOPT_SSL_CTX_FUNCTION: c_int = 20108;
/// The size of what CURLOPT_POSTFIELDS points at, which libcurl reads.
pub const CURLOPT_POSTFIELDSIZE_LARGE: c_int = 30120;

/// The `CURLOPT_SSLVERSION` of TLS 1.3 at least.
pub const CURL_SSLVERSION_TLSV1_3: c_long = 7;
pub const CURLINFO_EFFECTIVE_URL: c_int = 0x100001;
pub const CURLINFO_RESPONSE_CODE: c_int = 0x200002;
pub const CURLUE_OK: CurlUCode = 0;
pub const CURLUE_NO_USER: CurlUCode = 11;
pub const CURLUE_NO_PASSWORD: CurlUCode = 12;
pub const CURLUE_NO_ZONEID: CurlUCode = 18;
pub const CURLU_DEFAULT_PORT: c_uint = 1 << 0;
pub const CURLU_DISALLOW_USER: c_uint = 1 << 5;
pub const CURLUPART_URL: CurlUPart = 0;
pub const CURLUPART_SCHEME: CurlUPart = 1;
pub const CURLUPART_USER: CurlUPart = 2;
pub const CURLUPART_PASSWORD: CurlUPart = 3;
pub const CURLUPART_HOST: CurlUPart = 5;
pub const CURLUPART_PORT: CurlUPart = 6;
pub const CURLUPART_ZONEID: CurlUPart = 10;

// The binaries link libcurl themselves; the crate's tests, which rustc
// links, name it.
#[cfg_attr(test, link(name = "curl"))]
unsafe extern "C" {
    pub fn curl_global_init(flags: c_long) -> CurlCode;
    pub fn curl_global_cleanup();
    pub fn curl_easy_init() -> *mut Curl;
    pub fn curl_easy_setopt(curl: *mut Curl, option: c_int, ...) -> CurlCode;
    pub fn curl_easy_perform(curl: *mut Curl) -> CurlCode;
    pub fn curl_easy_getinfo(curl: *mut Curl, info: c_int, ...) -> CurlCode;
    pub fn curl_easy_cleanup(curl: *mut Curl);
    pub fn curl_easy_strerror(code: CurlCode) -> *const c_char;
    pub fn curl_easy_escape(curl: *mut Curl, s: *const c_char, len: c_int) -> *mut c_char;
    pub fn curl_free(p: *mut c_void);
    pub fn curl_url() -> *mut CurlU;
    pub fn curl_url_cleanup(url: *mut CurlU);
    pub fn curl_url_set(
        url: *mut CurlU,
        what: CurlUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> CurlUCode;
    pub fn curl_url_get(
        url: *const CurlU,
        what: CurlUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> CurlUCode;
    pub fn curl_slist_append(list: *mut CurlSlist, s: *const c_char) -> *mut CurlSlist;
    pub fn curl_slist_free_all(list: *mut CurlSlist);
}
