// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! libcurl's easy handles, header lists and URLs, released when they go.
//! A handle borrows what libcurl keeps a pointer to across its transfers.
//! A list is scrubbed before it is freed: libcurl copies a line
//! curl_slist_append() takes, so a Basic or bearer authorization would
//! outlive the buffer its caller scrubbed, in freed heap memory.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::{self, NonNull};
use std::ffi::CString;

use crate::errno::{EINVAL, ENOMEM};
use crate::sys::curl::{
    CURL_ERROR_SIZE, CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLINFO_EFFECTIVE_URL,
    CURLINFO_RESPONSE_CODE, CURLOPT_ERRORBUFFER, CURLOPT_HEADERDATA, CURLOPT_HEADERFUNCTION,
    CURLOPT_HTTPHEADER, CURLOPT_POSTFIELDS, CURLOPT_POSTFIELDSIZE_LARGE, CURLOPT_READDATA,
    CURLOPT_READFUNCTION, CURLOPT_SSL_CTX_DATA, CURLOPT_SSL_CTX_FUNCTION, CURLOPT_WRITEDATA,
    CURLOPT_WRITEFUNCTION, CURLUE_OK, CURLUPART_URL, Curl, CurlCode, CurlOff, CurlSlist, CurlU,
    CurlUCode, CurlUPart, LongOption, OffOption, ReadCallback, SslCtxCallback, StrOption,
    WriteCallback, curl_easy_cleanup, curl_easy_escape, curl_easy_getinfo, curl_easy_init,
    curl_easy_perform, curl_easy_setopt, curl_easy_strerror, curl_free, curl_slist_append,
    curl_slist_free_all, curl_url, curl_url_cleanup, curl_url_get, curl_url_set,
};

/// A libcurl easy handle, cleaned up when it goes. libcurl keeps a
/// pointer to what a header list, a body or an error buffer option
/// points at, and reads or writes it until the handle goes: the handle
/// borrows those for `'a`.
pub(crate) struct Easy<'a> {
    handle: NonNull<Curl>,
    borrows: PhantomData<&'a mut ()>,
}

impl Easy<'static> {
    /// The handle libcurl hands a callback, to set options on and ask
    /// about, which is not cleaned up when it goes.
    ///
    /// # Safety
    ///
    /// `curl` is NULL or the handle whose transfer calls back, and what
    /// comes back is used only within the callback and never taken out
    /// of its `ManuallyDrop`.
    pub(crate) unsafe fn from_callback(curl: *mut Curl) -> Option<ManuallyDrop<Self>> {
        NonNull::new(curl).map(|handle| {
            ManuallyDrop::new(Easy {
                handle,
                borrows: PhantomData,
            })
        })
    }
}

impl<'a> Easy<'a> {
    /// A new handle, or -ENOMEM.
    pub(crate) fn new() -> Result<Self, c_int> {
        // SAFETY: a call that takes nothing.
        let handle = NonNull::new(unsafe { curl_easy_init() }).ok_or(-ENOMEM)?;

        Ok(Easy {
            handle,
            borrows: PhantomData,
        })
    }

    fn raw(&self) -> *mut Curl {
        self.handle.as_ptr()
    }

    pub(crate) fn set_long(&mut self, option: LongOption, value: c_long) -> CurlCode {
        // SAFETY: the handle, and an option that takes a long.
        unsafe { curl_easy_setopt(self.raw(), option.id(), value) }
    }

    pub(crate) fn set_off(&mut self, option: OffOption, value: CurlOff) -> CurlCode {
        // SAFETY: the handle, and an option that takes a curl_off_t.
        unsafe { curl_easy_setopt(self.raw(), option.id(), value) }
    }

    /// A string option, which libcurl copies before it returns.
    pub(crate) fn set_str(&mut self, option: StrOption, value: &CStr) -> CurlCode {
        // SAFETY: the handle, and a C string for an option whose string
        // libcurl copies.
        unsafe { curl_easy_setopt(self.raw(), option.id(), value.as_ptr()) }
    }

    /// The header lines each request sends, which libcurl does not copy.
    pub(crate) fn set_headers(&mut self, headers: &'a Slist) -> CurlCode {
        // SAFETY: the handle, and the list or NULL, which the handle
        // borrows for as long as it lives.
        unsafe { curl_easy_setopt(self.raw(), CURLOPT_HTTPHEADER, headers.0) }
    }

    /// The body a request sends, which libcurl reads in place: its
    /// address, then its size, so that libcurl reads no further.
    pub(crate) fn set_post_fields(&mut self, body: &'a [u8]) -> CurlCode {
        let Ok(len) = CurlOff::try_from(body.len()) else {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        };
        // SAFETY: the handle, and the body, which the handle borrows for
        // as long as it lives; libcurl reads the size set next of it.
        let pointer = unsafe { curl_easy_setopt(self.raw(), CURLOPT_POSTFIELDS, body.as_ptr()) };
        // SAFETY: the handle, and the body's size, which libcurl refuses
        // only below -1.
        let size = unsafe { curl_easy_setopt(self.raw(), CURLOPT_POSTFIELDSIZE_LARGE, len) };
        if pointer != CURLE_OK { pointer } else { size }
    }

    /// The buffer libcurl writes why a transfer failed into, which it may
    /// write until the handle goes.
    pub(crate) fn set_error_buffer(&mut self, buffer: &'a mut [u8; CURL_ERROR_SIZE]) -> CurlCode {
        // SAFETY: the handle, and CURL_ERROR_SIZE bytes, which the handle
        // borrows for as long as it lives.
        unsafe { curl_easy_setopt(self.raw(), CURLOPT_ERRORBUFFER, buffer.as_mut_ptr()) }
    }

    /// What a transfer receives, handed to `callback` with `data`.
    ///
    /// # Safety
    ///
    /// `callback` takes its last argument for what `data` points at, and
    /// `data` stays valid for as long as the handle lives, touched by
    /// nothing else while a transfer runs.
    pub(crate) unsafe fn set_write<T>(
        &mut self,
        callback: WriteCallback,
        data: *mut T,
    ) -> CurlCode {
        // SAFETY: the caller's callback and data, for a write callback.
        unsafe { self.set_callback(CURLOPT_WRITEFUNCTION, callback, CURLOPT_WRITEDATA, data) }
    }

    /// The response's header lines, handed to `callback` with `data`.
    ///
    /// # Safety
    ///
    /// As for set_write().
    pub(crate) unsafe fn set_header<T>(
        &mut self,
        callback: WriteCallback,
        data: *mut T,
    ) -> CurlCode {
        // SAFETY: the caller's callback and data, for a header callback.
        unsafe { self.set_callback(CURLOPT_HEADERFUNCTION, callback, CURLOPT_HEADERDATA, data) }
    }

    /// What a transfer sends, asked of `callback` with `data`.
    ///
    /// # Safety
    ///
    /// As for set_write().
    pub(crate) unsafe fn set_read<T>(&mut self, callback: ReadCallback, data: *mut T) -> CurlCode {
        // SAFETY: the caller's callback and data, for a read callback.
        unsafe { self.set_callback(CURLOPT_READFUNCTION, callback, CURLOPT_READDATA, data) }
    }

    /// # Safety
    ///
    /// `function` takes a callback of `callback`'s type and `data_option`
    /// the pointer it is called with, and the caller keeps set_write()'s
    /// contract for `callback` and `data`.
    unsafe fn set_callback<T>(
        &mut self,
        function: c_int,
        callback: WriteCallback,
        data_option: c_int,
        data: *mut T,
    ) -> CurlCode {
        // SAFETY: the handle, and a callback of the type `function` takes.
        let code = unsafe { curl_easy_setopt(self.raw(), function, callback) };
        if code != CURLE_OK {
            return code;
        }
        // SAFETY: the handle, and the data the caller keeps valid.
        unsafe { curl_easy_setopt(self.raw(), data_option, data.cast::<c_void>()) }
    }

    /// The SSL_CTX callback, called with `data` each time libcurl
    /// connects; the data is not set when the callback is refused.
    ///
    /// # Safety
    ///
    /// `callback` takes its last argument for what `data` points at, and
    /// `data` stays valid for as long as the handle lives.
    pub(crate) unsafe fn set_ssl_ctx(
        &mut self,
        callback: SslCtxCallback,
        data: *const c_void,
    ) -> CurlCode {
        // SAFETY: the handle, and an SSL_CTX callback.
        let code = unsafe { curl_easy_setopt(self.raw(), CURLOPT_SSL_CTX_FUNCTION, callback) };
        if code != CURLE_OK {
            return code;
        }
        // SAFETY: the handle, and the data the caller keeps valid.
        unsafe { curl_easy_setopt(self.raw(), CURLOPT_SSL_CTX_DATA, data) }
    }

    /// Runs a transfer as the options say: CURLE_OK, or why it failed.
    pub(crate) fn perform(&mut self) -> CurlCode {
        // SAFETY: the handle, whose options point at what it borrows and
        // at what the callers of the unsafe setters keep valid.
        unsafe { curl_easy_perform(self.raw()) }
    }

    /// The status of the last response, None when libcurl gives none.
    pub(crate) fn response_code(&self) -> Option<c_long> {
        let mut code: c_long = 0;
        // SAFETY: the handle, and room for the long the info is.
        let got = unsafe { curl_easy_getinfo(self.raw(), CURLINFO_RESPONSE_CODE, &raw mut code) };
        (got == CURLE_OK).then_some(code)
    }

    /// The URL the last transfer went to, which the handle keeps.
    pub(crate) fn effective_url(&self) -> Option<&CStr> {
        let mut url: *const c_char = ptr::null();
        // SAFETY: the handle, and room for the pointer the info is.
        let got = unsafe { curl_easy_getinfo(self.raw(), CURLINFO_EFFECTIVE_URL, &raw mut url) };
        if got != CURLE_OK || url.is_null() {
            return None;
        }
        // SAFETY: the handle's C string, which no call can change or free
        // while the handle is borrowed.
        Some(unsafe { CStr::from_ptr(url) })
    }

    /// `s` URL-encoded, None when libcurl cannot.
    pub(crate) fn escape(&self, s: &CStr) -> Option<Vec<u8>> {
        // SAFETY: the handle, and a C string, which a length of 0 has
        // libcurl measure.
        let escaped = unsafe { curl_easy_escape(self.raw(), s.as_ptr(), 0) };
        if escaped.is_null() {
            return None;
        }
        // SAFETY: the C string libcurl allocated.
        let bytes = unsafe { CStr::from_ptr(escaped) }.to_bytes().to_vec();
        // SAFETY: as above, freed once.
        unsafe { curl_free(escaped.cast()) };
        Some(bytes)
    }
}

impl Drop for Easy<'_> {
    fn drop(&mut self) {
        // SAFETY: the handle, cleaned up once.
        unsafe { curl_easy_cleanup(self.raw()) };
    }
}

/// What libcurl says `code` means.
pub(crate) fn strerror(code: CurlCode) -> &'static CStr {
    // SAFETY: libcurl's text for a code, a static C string for any code.
    unsafe { CStr::from_ptr(curl_easy_strerror(code)) }
}

/// A transfer's header lines, scrubbed and freed when it goes.
pub(crate) struct Slist(*mut CurlSlist);

impl Default for Slist {
    fn default() -> Self {
        Slist(ptr::null_mut())
    }
}

impl Slist {
    /// `line` appended: -EINVAL for a line with a NUL in it, or -ENOMEM.
    pub(crate) fn append(&mut self, line: &[u8]) -> c_int {
        let Ok(line) = CString::new(line) else {
            return -EINVAL;
        };
        // SAFETY: the list or NULL, and a C string, which curl copies.
        let next = unsafe { curl_slist_append(self.0, line.as_ptr()) };
        if next.is_null() {
            return -ENOMEM;
        }
        self.0 = next;
        0
    }

    /// The list as libcurl takes it, NULL while it is empty.
    #[cfg(any(test, shirudo_fuzz))]
    pub(crate) fn raw(&self) -> *mut CurlSlist {
        self.0
    }
}

impl Drop for Slist {
    fn drop(&mut self) {
        // SAFETY: the list or NULL, which no handle uses any more.
        unsafe { slist_scrub(self.0) };
        // SAFETY: as above, freed once.
        unsafe { curl_slist_free_all(self.0) };
    }
}

/// `struct curl_slist` of curl/curl.h, which libcurl declares public.
#[repr(C)]
struct Node {
    data: *mut c_char,
    next: *mut Node,
}

/// Zeroes the data of each entry of `headers`, terminators included.
///
/// # Safety
///
/// `headers` is NULL or a list curl_slist_append() built.
unsafe fn slist_scrub(headers: *mut CurlSlist) {
    let mut entry = headers.cast::<Node>();

    while !entry.is_null() {
        // SAFETY: an entry of the caller's list.
        let node = unsafe { &*entry };

        if !node.data.is_null() {
            // SAFETY: the entry's C string, its terminator included,
            // written a byte at a time so that no store is elided.
            unsafe {
                let len = crate::sys::libc::strlen(node.data) + 1;
                for i in 0..len {
                    core::ptr::write_volatile(node.data.add(i), 0);
                }
            }
        }
        entry = node.next;
    }
}

/// A URL libcurl parsed, freed when it goes.
pub(crate) struct Url(NonNull<CurlU>);

impl Url {
    /// `url` as libcurl parses it: -ENOMEM, or -EINVAL for a URL with a
    /// NUL in it or one libcurl refuses.
    pub(crate) fn parse(url: &[u8]) -> Result<Self, c_int> {
        Self::parse_with_flags(url, 0)
    }

    /// Parse a URL that cannot carry a username or password.
    pub(crate) fn parse_no_user(url: &[u8]) -> Result<Self, c_int> {
        Self::parse_with_flags(url, crate::sys::curl::CURLU_DISALLOW_USER)
    }

    fn parse_with_flags(url: &[u8], flags: c_uint) -> Result<Self, c_int> {
        // SAFETY: a call that takes nothing.
        let u = Url(NonNull::new(unsafe { curl_url() }).ok_or(-ENOMEM)?);
        let url = CString::new(url).map_err(|_| -EINVAL)?;
        // SAFETY: the handle, and a C string, which libcurl copies.
        if unsafe { curl_url_set(u.0.as_ptr(), CURLUPART_URL, url.as_ptr(), flags) } != CURLUE_OK {
            return Err(-EINVAL);
        }
        Ok(u)
    }

    /// The part `what` of the URL, or libcurl's exact error.
    pub(crate) fn part(&self, what: CurlUPart) -> Result<Vec<u8>, CurlUCode> {
        self.part_with_flags(what, 0)
    }

    /// The part `what` with libcurl URL-get flags, or its exact error.
    pub(crate) fn part_with_flags(
        &self,
        what: CurlUPart,
        flags: c_uint,
    ) -> Result<Vec<u8>, CurlUCode> {
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: the handle, and room for the C string libcurl allocates.
        let code = unsafe { curl_url_get(self.0.as_ptr(), what, &mut part, flags) };
        if part.is_null() {
            return if code == CURLUE_OK {
                Ok(Vec::new())
            } else {
                Err(code)
            };
        }
        let bytes = if code == CURLUE_OK {
            // SAFETY: libcurl returned a C string for a successful get.
            unsafe { CStr::from_ptr(part) }.to_bytes().to_vec()
        } else {
            Vec::new()
        };
        // SAFETY: what libcurl allocated, freed once.
        unsafe { curl_free(part.cast()) };
        if code == CURLUE_OK {
            Ok(bytes)
        } else {
            Err(code)
        }
    }
}

impl Drop for Url {
    fn drop(&mut self) {
        // SAFETY: the handle, freed once.
        unsafe { curl_url_cleanup(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
