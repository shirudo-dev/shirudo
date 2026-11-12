// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * OCI distribution client: libcurl supplies HTTP/TLS, this file owns
 * registry auth, blob and manifest transfer, and reference parsing.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_oci.h"
#include "crypto.h"
#include "curl.h"
#include "hex.h"
#include "io.h"
#include "seal.h"
#include "json.h"
#include "log.h"
#include "malloc.h"

void bpm_copy_string(char *dst, size_t dst_sz, const char *src)
{
	size_t len;

	if (!dst_sz)
		return;
	if (!src)
		src = "";
	len = strlen(src);
	if (len >= dst_sz)
		len = dst_sz - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static bool bpm_component_ok(const char *s, bool plus)
{
	const __u8 *p = (const __u8 *)s;

	if (!s || !*s || strlen(s) >= BPM_MAX_NAME || s[0] == '.')
		return false;
	for (; *p; p++) {
		if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
		      (plus && *p == '+')))
			return false;
	}
	return true;
}

bool bpm_name_ok(const char *s)
{
	return bpm_component_ok(s, false);
}

bool bpm_version_ok(const char *s)
{
	return bpm_component_ok(s, true);
}

static int bpm_buffer_append(struct bpm_buffer *b, const void *data, size_t len)
{
	size_t want;
	__u8 *p;

	if (len >= BPM_MAX_HTTP_BODY - b->len)
		return -E2BIG;
	want = b->len + len;
	if (want + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 4096;

		while (cap <= want) {
			if (cap > BPM_MAX_HTTP_BODY / 2) {
				cap = BPM_MAX_HTTP_BODY;
				break;
			}
			cap *= 2;
		}
		p = xreallocarray(b->data, b->cap, cap, 1);
		if (!p)
			return -ENOMEM;
		b->data = p;
		b->cap = cap;
	}
	memcpy(b->data + b->len, data, len);
	b->len += len;
	b->data[b->len] = '\0';
	return 0;
}

void bpm_oci_client_clear(struct bpm_oci_client *c)
{
	memzero_explicit(c, sizeof(*c));
}

void bpm_buffer_free(struct bpm_buffer *b)
{
	xfree(b->data, b->cap);
	*b = (struct bpm_buffer){};
}

static size_t bpm_write_memory(void *ptr, size_t size, size_t nmemb, void *ud)
{
	struct bpm_http_response *r = ud;
	size_t n = size * nmemb;

	if (bpm_buffer_append(&r->body, ptr, n))
		return 0;
	return n;
}

/* A download bounded by the size its manifest declares. */
struct bpm_file_sink {
	int		fd;
	int		err;
	__u64		room;
	bool		overflow;
};

static size_t bpm_write_file(void *ptr, size_t size, size_t nmemb, void *ud)
{
	struct bpm_file_sink *s = ud;
	size_t n = size * nmemb;

	if (n > s->room) {
		s->overflow = true;
		return 0;
	}
	s->room -= n;
	s->err = write_complete(s->fd, ptr, n);
	return s->err ? 0 : n;
}

/* The descriptor is the caller's: a body is restarted in place. */
static int sink_restart(struct bpm_file_sink *s, int fd, __u64 room)
{
	if (ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0)
		return -errno;
	*s = (struct bpm_file_sink){ .fd = fd, .room = room };
	return 0;
}

static size_t bpm_header(void *ptr, size_t size, size_t nmemb, void *ud)
{
	struct bpm_http_response *r = ud;
	char line[4096];
	size_t n = size * nmemb;
	char *v;

	if (n >= sizeof(line))
		return n;
	memcpy(line, ptr, n);
	line[n] = '\0';
	if (!strncasecmp(line, "WWW-Authenticate:", 17)) {
		v = line + 17;
		while (isspace((__u8)*v))
			v++;
		if (strscpy(r->www_auth, v, sizeof(r->www_auth)) < 0)
			r->www_auth[0] = '\0';
	} else if (!strncasecmp(line, "Content-Type:", 13)) {
		v = line + 13;
		while (isspace((__u8)*v))
			v++;
		v[strcspn(v, " ;\r\n")] = '\0';
		bpm_copy_string(r->content_type, sizeof(r->content_type), v);
	} else if (!strncasecmp(line, "Location:", 9)) {
		v = line + 9;
		while (isspace((__u8)*v))
			v++;
		v[strcspn(v, "\r\n")] = '\0';
		bpm_copy_string(r->location, sizeof(r->location), v);
	}
	return n;
}

static int base64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

static int decode_basic(const char *in, char *user, size_t usz,
			char *pass, size_t psz)
{
	__u8 out[BPM_OCI_BASIC_RAW_SIZE];
	int bits = -8, ret = -EINVAL, x;
	size_t n = 0;
	__u32 val = 0;
	char *colon;

	for (; *in && *in != '"' && n < sizeof(out); in++) {
		if (isspace((__u8)*in) || *in == '=')
			continue;
		x = base64_value((__u8)*in);
		if (x < 0)
			goto out;
		/* No more than 12 bits are ever pending. */
		val = ((val << 6) | (__u32)x) & 0xfff;
		bits += 6;
		if (bits >= 0) {
			out[n++] = (__u8)((val >> bits) & 0xff);
			bits -= 8;
		}
	}
	if (n >= sizeof(out)) {
		ret = -E2BIG;
		goto out;
	}
	out[n] = '\0';
	if (memchr(out, '\0', n))
		goto out;
	colon = memchr(out, ':', n);
	if (!colon || (size_t)(colon - (char *)out) >= usz ||
	    n - (size_t)(colon - (char *)out) - 1 >= psz)
		goto out;
	memcpy(user, out, (size_t)(colon - (char *)out));
	user[colon - (char *)out] = '\0';
	memcpy(pass, colon + 1, n - (size_t)(colon - (char *)out) - 1);
	pass[n - (size_t)(colon - (char *)out) - 1] = '\0';
	ret = 0;
out:
	memzero_explicit(out, sizeof(out));
	return ret;
}

static int encode_basic(const char *user, const char *pass,
			char *out, size_t out_sz)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char raw[BPM_OCI_BASIC_RAW_SIZE];
	size_t len, need, i, o = 0;
	int ret = 0;

	if (strsprintf(raw, sizeof(raw), "%s:%s", user, pass) < 0) {
		ret = -E2BIG;
		goto out;
	}
	len = strlen(raw);
	need = 4 * ((len + 2) / 3) + 1;
	if (need > out_sz) {
		ret = -ENOSPC;
		goto out;
	}
	for (i = 0; i < len; i += 3) {
		__u32 v = (__u8)raw[i] << 16;

		if (i + 1 < len)
			v |= (__u8)raw[i + 1] << 8;
		if (i + 2 < len)
			v |= (__u8)raw[i + 2];
		out[o++] = alphabet[(v >> 18) & 63];
		out[o++] = alphabet[(v >> 12) & 63];
		out[o++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
		out[o++] = i + 2 < len ? alphabet[v & 63] : '=';
	}
	out[o] = '\0';
out:
	memzero_explicit(raw, sizeof(raw));
	return ret;
}

static int load_registry_auth(const char *registry, struct bpm_oci_client *c)
{
	const char *authfile = getenv("REGISTRY_AUTH_FILE");
	const char *username = getenv("BPM_OCI_USERNAME");
	const char *password = getenv("BPM_OCI_PASSWORD");
	const char *docker = getenv("DOCKER_CONFIG");
	char path[PATH_MAX];
	char needle[BPM_MAX_ENDPOINT + 8];
	__u8 *body = NULL;
	size_t body_len = 0;
	char *p, *end, *auth;
	int ret;

	if (username && password) {
		if (strscpy(c->username, username, sizeof(c->username)) < 0 ||
		    strscpy(c->password, password, sizeof(c->password)) < 0)
			return -E2BIG;
		return 0;
	}
	if (!authfile && docker) {
		if (strsprintf(path, sizeof(path), "%s/config.json", docker) < 0)
			return -ENAMETOOLONG;
		authfile = path;
	}
	if (!authfile) {
		const char *home = getenv("HOME");

		if (!home)
			home = "/root";
		if (strsprintf(path, sizeof(path), "%s/.docker/config.json",
			       home) < 0)
			return -ENAMETOOLONG;
		authfile = path;
	}
	if (strsprintf(needle, sizeof(needle), "\"%s\"", registry) < 0)
		return -ENAMETOOLONG;
	ret = read_file(authfile, 4u * 1024u * 1024u, &body, &body_len);
	if (ret)
		return ret == -ENOENT ? 0 : ret;
	/*
	 * The auth file is local input; require the registry key and auth
	 * member to occur in the same JSON object before accepting
	 * credentials.
	 */
	p = strstr((char *)body, needle);
	if (!p) {
		xfree(body, body_len + 1);
		return 0;
	}
	end = strchr(p, '}');
	if (!end) {
		xfree(body, body_len + 1);
		return -EINVAL;
	}
	auth = strstr(p, "\"auth\"");
	if (!auth || auth > end) {
		xfree(body, body_len + 1);
		return 0;
	}
	auth = strchr(auth, ':');
	if (!auth) {
		xfree(body, body_len + 1);
		return -EINVAL;
	}
	auth++;
	while (*auth && isspace((__u8)*auth))
		auth++;
	if (*auth != '"') {
		xfree(body, body_len + 1);
		return -EINVAL;
	}
	ret = decode_basic(auth + 1, c->username, sizeof(c->username),
			   c->password, sizeof(c->password));
	xfree(body, body_len + 1);
	return ret;
}

int bpm_oci_parse_endpoint(const char *endpoint, struct bpm_oci_client *c)
{
	const char *p, *scheme = getenv("BPM_OCI_SCHEME");
	char transport[16] = "https";

	if (!endpoint || strncmp(endpoint, "oci://", 6) != 0)
		return -EINVAL;
	p = endpoint + 6;
	if (!*p || strchr(p, '/') || strchr(p, '?') || strchr(p, '#') || strchr(p, '@'))
		return -EINVAL;
	if (scheme && *scheme) {
		if (strcmp(scheme, "https") && strcmp(scheme, "http")) {
			pr_err("bpm OCI: BPM_OCI_SCHEME must be https or http");
			return -EINVAL;
		}
		strscpy(transport, scheme, sizeof(transport));
	}
	if (strscpy(c->registry, p, sizeof(c->registry)) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(c->base_url, sizeof(c->base_url), "%s://%s", transport, p) < 0)
		return -ENAMETOOLONG;
	if (getenv("BPM_OCI_CA_FILE")) {
		const char *ca_file = getenv("BPM_OCI_CA_FILE");
		struct cert ca = {};

		if (strlen(ca_file) >= sizeof(c->ca_file))
			return -ENAMETOOLONG;
		bpm_copy_string(c->ca_file, sizeof(c->ca_file), ca_file);
		if (cert_read_file(c->ca_file, &ca) != 0) {
			pr_err("bpm OCI: BPM_OCI_CA_FILE is not a readable certificate");
			return -EINVAL;
		}
		cert_free(&ca);
	}
	if (c->ca_file[0]) {
		struct stat st;

		if (stat(c->ca_file, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
			pr_err("bpm OCI: BPM_OCI_CA_FILE must name a non-empty regular PEM file");
			return -EINVAL;
		}
	}
	c->tls_ca.path = c->ca_file;
	return load_registry_auth(c->registry, c);
}

/*
 * A registry that stops answering must not hold a timer's unit forever;
 * a slow transfer that still moves is left alone.
 */
static void bpm_curl_deadlines(CURL *curl)
{
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
}

static int curl_once_ex(struct bpm_oci_client *c, const char *method,
			const char *url, const char *accept,
			const char *content_type, const void *body, size_t body_len,
			const char *auth, struct bpm_http_response *r,
			struct bpm_file_sink *file, bool follow)
{
	struct curl_slist *headers = NULL, *next;
	char errbuf[CURL_ERROR_SIZE] = {};
	long status = 0;
	CURLcode cc;
	CURL *curl;

	if (accept) {
		char h[256];

		if (strsprintf(h, sizeof(h), "Accept: %s", accept) < 0)
			goto too_long;
		next = curl_slist_append(headers, h);
		if (!next)
			goto no_memory;
		headers = next;
	}
	if (content_type) {
		char h[256];

		if (strsprintf(h, sizeof(h), "Content-Type: %s",
			       content_type) < 0)
			goto too_long;
		next = curl_slist_append(headers, h);
		if (!next)
			goto no_memory;
		headers = next;
	}
	if (auth) {
		char h[8192];
		int n;

		n = strsprintf(h, sizeof(h), "Authorization: %s", auth);
		next = n < 0 ? NULL : curl_slist_append(headers, h);
		memzero_explicit(h, sizeof(h));
		if (n < 0)
			goto too_long;
		if (!next)
			goto no_memory;
		headers = next;
	}
	curl = curl_easy_init();
	if (!curl) {
		curl_slist_free_sensitive(headers);
		return -ENOMEM;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	if (!strcasecmp(method, "HEAD"))
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	bpm_curl_deadlines(curl);
	/*
	 * OCI registries commonly redirect blob GETs to a signed CDN URL.
	 * Follow only for blobs, never for manifest or upload calls.
	 */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow ? 1L : 0L);
	if (follow) {
		const char *redirect_protocols =
			!strncmp(c->base_url, "https://", 8) ? "https" : "http,https";

		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
#if LIBCURL_VERSION_NUM >= 0x075500
		curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, redirect_protocols);
#else
		curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
				 !strcmp(redirect_protocols, "https") ? CURLPROTO_HTTPS :
				 CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
		/* Keep Authorization restricted to the original registry host. */
		curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 0L);
	}
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	if (tls_curl_policy(curl, &c->tls_ca)) {
		pr_err("bpm OCI request %s: cannot apply TLS policy", url);
		curl_easy_cleanup(curl);
		curl_slist_free_sensitive(headers);
		return -EHOSTUNREACH;
	}
	if (body) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
	}
	if (file) {
		curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
				 (curl_off_t)file->room);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_file);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
	} else {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, r);
	}
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, bpm_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	r->status = status;
	if (cc != CURLE_OK) {
		pr_err("bpm OCI request %s: %s", url, errbuf[0] ? errbuf : curl_easy_strerror(cc));
		status = -1;
	}
	if (file && cc == CURLE_FILESIZE_EXCEEDED)
		file->overflow = true;
	curl_easy_cleanup(curl);
	curl_slist_free_sensitive(headers);
	tls_ca_cleanup(&c->tls_ca);
	return status < 0 ? -EHOSTUNREACH : 0;

too_long:
	curl_slist_free_sensitive(headers);
	return -E2BIG;
no_memory:
	curl_slist_free_sensitive(headers);
	return -ENOMEM;
}

static int curl_once(struct bpm_oci_client *c, const char *method,
		     const char *url, const char *accept, const char *auth,
		     struct bpm_http_response *r, struct bpm_file_sink *file,
		     bool follow)
{
	return curl_once_ex(c, method, url, accept, NULL, NULL, 0, auth, r, file,
			    follow);
}

static int parse_challenge(const char *header, char *realm, size_t rsz,
			   char *service, size_t ssz, char *scope, size_t zsz)
{
	const char *p;
	const char *q;

	if (!header || strncasecmp(header, "Bearer", 6) != 0)
		return -EINVAL;
	for (p = header + 6; *p;) {
		while (*p == ' ' || *p == ',')
			p++;
		if (!strncmp(p, "realm=\"", 7)) {
			p += 7;
			q = strchr(p, '"');
			if (!q)
				return -EINVAL;
			if ((size_t)(q - p) >= rsz)
				return -ENAMETOOLONG;
			memcpy(realm, p, q - p);
			realm[q - p] = 0;
			p = q + 1;
		} else if (!strncmp(p, "service=\"", 9)) {
			p += 9;
			q = strchr(p, '"');
			if (!q)
				return -EINVAL;
			if ((size_t)(q - p) >= ssz)
				return -ENAMETOOLONG;
			memcpy(service, p, q - p);
			service[q - p] = 0;
			p = q + 1;
		} else if (!strncmp(p, "scope=\"", 7)) {
			p += 7;
			q = strchr(p, '"');
			if (!q)
				return -EINVAL;
			if ((size_t)(q - p) >= zsz)
				return -ENAMETOOLONG;
			memcpy(scope, p, q - p);
			scope[q - p] = 0;
			p = q + 1;
		} else {
			p = strchr(p, ',');
			if (!p)
				break;
		}
	}
	return realm[0] ? 0 : -EINVAL;
}

/* The token in a token server's JSON answer, "token" or "access_token". */
static int token_from_body(const char *body, char *out, size_t out_sz)
{
	const char *token, *end;

	token = strstr(body, "\"token\"");
	if (!token)
		token = strstr(body, "\"access_token\"");
	if (token)
		token = strchr(token, ':');
	if (!token)
		return -EINVAL;
	token++;
	while (*token && isspace((__u8)*token))
		token++;
	if (*token++ != '"')
		return -EINVAL;
	end = strchr(token, '"');
	if (!end || (size_t)(end - token) >= out_sz)
		return -EINVAL;
	/* It goes into a header line as it is: no line break, no escape. */
	for (const char *p = token; p < end; p++) {
		if ((__u8)*p < 0x21 || *p == '\\' || (__u8)*p == 0x7f)
			return -EINVAL;
	}
	memcpy(out, token, end - token);
	out[end - token] = '\0';
	return 0;
}

static int get_bearer_token(struct bpm_oci_client *c, const char *challenge)
{
	const char *provided_token = getenv("BPM_OCI_BEARER_TOKEN");
	char realm[PATH_MAX] = {}, service[256] = {}, scope[512] = {};
	char url[PATH_MAX * 2];
	char basic[BPM_OCI_BASIC_ENCODED_SIZE];
	char auth_header[BPM_OCI_BASIC_HEADER_SIZE];
	CURL *curl = NULL;
	struct curl_slist *headers = NULL;
	struct bpm_http_response r = {};
	CURLcode cc;
	char *esc_service = NULL, *esc_scope = NULL;
	int ret = -EINVAL;

	if (provided_token && *provided_token) {
		if (strlen(provided_token) >= sizeof(c->token))
			return -E2BIG;
		bpm_copy_string(c->token, sizeof(c->token), provided_token);
		return 0;
	}
	if (parse_challenge(challenge, realm, sizeof(realm), service,
			    sizeof(service), scope, sizeof(scope)))
		return -EINVAL;
	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;
	esc_service = curl_easy_escape(curl, service, 0);
	esc_scope = curl_easy_escape(curl, scope, 0);
	if (!esc_service || !esc_scope)
		goto out;
	if (strsprintf(url, sizeof(url), "%s?service=%s&scope=%s", realm,
		       esc_service, esc_scope) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	if (c->username[0]) {
		ret = encode_basic(c->username, c->password, basic,
				   sizeof(basic));
		if (ret)
			goto out;
		if (strsprintf(auth_header, sizeof(auth_header),
			       "Authorization: Basic %s", basic) < 0) {
			ret = -E2BIG;
			goto out;
		}
		headers = curl_slist_append(headers, auth_header);
		if (!headers) {
			ret = -ENOMEM;
			goto out;
		}
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	/*
	 * The realm is the registry's to name and the credentials go there:
	 * over no weaker a transport than the registry's own.
	 */
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,
			 strncmp(c->base_url, "https://", 8) ? "http,https" :
							       "https");
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	bpm_curl_deadlines(curl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	if (tls_curl_policy(curl, &c->tls_ca)) {
		ret = -EINVAL;
		goto out;
	}
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
	if (cc != CURLE_OK) {
		ret = -EHOSTUNREACH;
		goto out;
	}
	if (r.status >= 300) {
		ret = -EACCES;
		goto out;
	}
	/* curl never calls the write callback for an empty body. */
	if (!r.body.data)
		goto out;
	ret = token_from_body((char *)r.body.data, c->token, sizeof(c->token));
out:
	memzero_explicit(basic, sizeof(basic));
	memzero_explicit(auth_header, sizeof(auth_header));
	curl_free(esc_service);
	curl_free(esc_scope);
	curl_easy_cleanup(curl);
	curl_slist_free_sensitive(headers);
	tls_ca_cleanup(&c->tls_ca);
	bpm_buffer_free(&r.body);
	return ret;
}

static int get_memory(struct bpm_oci_client *c, const char *url,
		      const char *accept, struct bpm_buffer *out, bool follow)
{
	struct bpm_http_response r = {};
	char auth[BPM_OCI_AUTH_VALUE_SIZE];
	int ret;

	ret = curl_once(c, "GET", url, accept, NULL, &r, NULL, follow);
	if (ret)
		goto out;
	if (r.status == 401 && r.www_auth[0]) {
		if (!strncasecmp(r.www_auth, "Bearer", 6)) {
			ret = get_bearer_token(c, r.www_auth);
			if (!ret && strsprintf(auth, sizeof(auth), "Bearer %s",
					       c->token) < 0)
				ret = -E2BIG;
		} else if (!strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
			char encoded[BPM_OCI_BASIC_ENCODED_SIZE];

			ret = encode_basic(c->username, c->password, encoded, sizeof(encoded));
			if (!ret && strsprintf(auth, sizeof(auth), "Basic %s",
					       encoded) < 0)
				ret = -E2BIG;
			memzero_explicit(encoded, sizeof(encoded));
		} else {
			ret = -EACCES;
		}
		if (!ret) {
			bpm_buffer_free(&r.body);
			r = (struct bpm_http_response){};
			ret = curl_once(c, "GET", url, accept, auth, &r, NULL,
					follow);
		}
		memzero_explicit(auth, sizeof(auth));
		if (ret)
			goto out;
	}
	if (!ret && (r.status < 200 || r.status >= 300))
		ret = r.status == 404 ? -ENOENT : -EACCES;
	if (!ret) {
		*out = r.body;
		r.body.data = NULL;
	}
out:
	bpm_buffer_free(&r.body);
	return ret;
}

int bpm_oci_get_memory(struct bpm_oci_client *c, const char *url,
		       const char *accept, struct bpm_buffer *out)
{
	return get_memory(c, url, accept, out, false);
}

int bpm_oci_get_blob(struct bpm_oci_client *c, const char *url,
		     const char *accept, struct bpm_buffer *out)
{
	return get_memory(c, url, accept, out, true);
}

int bpm_oci_get_file(struct bpm_oci_client *c, const char *url,
		     const char *accept, int fd, __s64 size)
{
	struct bpm_http_response r = {};
	struct bpm_file_sink sink = {};
	char auth[BPM_OCI_AUTH_VALUE_SIZE];
	int ret;

	if (size < 0 || fd < 0)
		return -EINVAL;
	if ((__u64)size > BPM_MAX_PACKAGE_BYTES)
		return -EFBIG;
	ret = sink_restart(&sink, fd, (__u64)size);
	if (ret)
		return ret;
	ret = curl_once(c, "GET", url, accept, NULL, &r, &sink, true);
	if (!ret && r.status == 401 && r.www_auth[0] && !strncasecmp(r.www_auth, "Bearer", 6)) {
		ret = sink_restart(&sink, fd, (__u64)size);
		if (!ret)
			ret = get_bearer_token(c, r.www_auth);
		if (!ret && strsprintf(auth, sizeof(auth), "Bearer %s",
				       c->token) < 0)
			ret = -E2BIG;
		if (!ret) {
			bpm_buffer_free(&r.body);
			r = (struct bpm_http_response){};
			ret = curl_once(c, "GET", url, accept, auth, &r, &sink, true);
		}
	} else if (!ret && r.status == 401 && r.www_auth[0] &&
		   !strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
		char encoded[BPM_OCI_BASIC_ENCODED_SIZE];

		ret = sink_restart(&sink, fd, (__u64)size);
		if (!ret)
			ret = encode_basic(c->username, c->password, encoded,
					   sizeof(encoded));
		if (!ret && strsprintf(auth, sizeof(auth), "Basic %s",
				       encoded) < 0)
			ret = -E2BIG;
		memzero_explicit(encoded, sizeof(encoded));
		if (!ret) {
			bpm_buffer_free(&r.body);
			r = (struct bpm_http_response){};
			ret = curl_once(c, "GET", url, accept, auth, &r, &sink, true);
		}
	}
	memzero_explicit(auth, sizeof(auth));
	/* A failed write ends the transfer too; it, not the transfer, is the cause. */
	if (sink.overflow)
		ret = -EFBIG;
	else if (sink.err)
		ret = sink.err;
	if (!ret && (r.status < 200 || r.status >= 300))
		ret = r.status == 404 ? -ENOENT : -EACCES;
	bpm_buffer_free(&r.body);
	return ret;
}

/*
 * A request helper for OCI uploads. Unlike the download helpers above, it
 * preserves the response headers (notably Location) and supports a request
 * body while still retrying once after a registry authentication challenge.
 */
static int bpm_oci_request(struct bpm_oci_client *c, const char *method,
			   const char *url, const char *accept,
			   const char *content_type, const void *body,
			   size_t body_len, struct bpm_http_response *r)
{
	char auth[BPM_OCI_AUTH_VALUE_SIZE] = {};
	int ret;

	*r = (struct bpm_http_response){};
	ret = curl_once_ex(c, method, url, accept, content_type, body, body_len,
			   NULL, r, NULL, false);
	if (ret)
		return ret;
	if (r->status == 401 && r->www_auth[0]) {
		if (!strncasecmp(r->www_auth, "Bearer", 6)) {
			ret = get_bearer_token(c, r->www_auth);
			if (!ret && strsprintf(auth, sizeof(auth), "Bearer %s",
					       c->token) < 0)
				ret = -E2BIG;
		} else if (!strncasecmp(r->www_auth, "Basic", 5) && c->username[0]) {
			char encoded[BPM_OCI_BASIC_ENCODED_SIZE];

			ret = encode_basic(c->username, c->password, encoded,
					   sizeof(encoded));
			if (!ret && strsprintf(auth, sizeof(auth), "Basic %s",
					       encoded) < 0)
				ret = -E2BIG;
			memzero_explicit(encoded, sizeof(encoded));
		} else {
			ret = -EACCES;
		}
		if (!ret) {
			bpm_buffer_free(&r->body);
			*r = (struct bpm_http_response){};
			ret = curl_once_ex(c, method, url, accept, content_type,
					   body, body_len, auth, r, NULL,
					   false);
		}
		memzero_explicit(auth, sizeof(auth));
		if (ret)
			return ret;
	}
	if (r->status < 200 || r->status >= 300) {
		if (r->status != 404) {
			if (r->body.data && r->body.len) {
				size_t n = min(r->body.len, 512U);

				pr_err("bpm OCI request %s: HTTP %ld: %.*s", url,
				       r->status, (int)n, r->body.data);
			} else {
				pr_err("bpm OCI request %s: HTTP %ld", url, r->status);
			}
		}
		return r->status == 404 ? -ENOENT : -EACCES;
	}
	return 0;
}

struct desc_sink {
	struct bpm_descriptor *items;
	int n, max;
	struct bpm_descriptor scratch;
	char package_name[BPM_MAX_NAME];
};

static int on_descriptor(void *ud)
{
	struct desc_sink *s = ud;
	__u8 digest[32];

	if (s->n >= s->max)
		return -E2BIG;
	/* The registry wrote this: a layer is all three or none. */
	if (!s->scratch.media[0] || s->scratch.size < 0 ||
	    sha256_digest_decode(s->scratch.digest, digest))
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	memset(&s->scratch, 0, sizeof(s->scratch));
	s->scratch.size = -1;
	return 0;
}

int bpm_oci_get_signed(struct bpm_oci_client *c, const char *repository,
		       const struct bpm_descriptor *layers, int n_layers,
		       const char *payload_media, const char *sig_media,
		       struct bpm_buffer *payload, struct bpm_buffer *sig)
{
	int n_payload = 0, n_sig = 0, i, ret;
	char url[PATH_MAX], hex[65];

	for (i = 0; i < n_layers; i++) {
		struct bpm_buffer *dst;
		int *seen;

		if (!strcmp(layers[i].media, payload_media)) {
			dst = payload;
			seen = &n_payload;
		} else if (!strcmp(layers[i].media, sig_media)) {
			dst = sig;
			seen = &n_sig;
		} else {
			continue;
		}
		if ((*seen)++)
			return -EINVAL;
		ret = bpm_oci_url(c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			return ret;
		ret = bpm_oci_get_blob(c, url, layers[i].media, dst);
		if (ret)
			return ret;
		if ((layers[i].size >= 0 && (__s64)dst->len != layers[i].size) ||
		    bpm_sha256_hex(dst->data, dst->len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex))
			return -EKEYREJECTED;
	}
	return payload->data && sig->data ? 0 : -EINVAL;
}

int bpm_oci_parse_manifest(const __u8 *body, size_t len,
			   struct bpm_descriptor *layers, int max_layers,
			   int *n_layers, char *package_name,
			   size_t package_name_sz)
{
	struct desc_sink sink = { .items = layers, .max = max_layers };
	struct json_array arr = { on_descriptor, &sink };
	struct json_field layer_annotations[1], manifest_annotations[1];
	struct json_field sub[4], root[3];
	__s64 schema = 0;

	sink.scratch.size = -1;
	memset(sub, 0, sizeof(sub));
	sub[0] = (struct json_field){ .key = "mediaType", .type = JSON_T_STRING,
		.dst = sink.scratch.media, .dst_cap = sizeof(sink.scratch.media) };
	sub[1] = (struct json_field){ .key = "digest", .type = JSON_T_STRING,
		.dst = sink.scratch.digest, .dst_cap = sizeof(sink.scratch.digest) };
	sub[2] = (struct json_field){ .key = "size", .type = JSON_T_INT,
		.dst = &sink.scratch.size };
	layer_annotations[0] = (struct json_field){
		.key = "org.opencontainers.image.title", .type = JSON_T_STRING,
		.dst = sink.scratch.title, .dst_cap = sizeof(sink.scratch.title) };
	sub[3] = (struct json_field){ .key = "annotations", .type = JSON_T_OBJECT,
		.sub = layer_annotations, .n_sub = ARRAY_SIZE(layer_annotations) };
	manifest_annotations[0] = (struct json_field){
		.key = "dev.shirudo.bpm.package.name", .type = JSON_T_STRING,
		.dst = sink.package_name, .dst_cap = sizeof(sink.package_name) };
	memset(root, 0, sizeof(root));
	root[0] = (struct json_field){ .key = "schemaVersion", .type = JSON_T_INT,
		.dst = &schema };
	root[1] = (struct json_field){ .key = "layers", .type = JSON_T_ARRAY,
		.dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	root[2] = (struct json_field){ .key = "annotations", .type = JSON_T_OBJECT,
		.sub = manifest_annotations, .n_sub = ARRAY_SIZE(manifest_annotations) };
	if (json_parse((const char *)body, len, root, ARRAY_SIZE(root)) ||
	    !root[0].seen || schema != 2 || !root[1].seen)
		return -EINVAL;
	*n_layers = sink.n;
	if (package_name && package_name_sz)
		bpm_copy_string(package_name, package_name_sz, sink.package_name);
	return 0;
}

bool bpm_package_name_ok(const char *s)
{
	const __u8 *p = (const __u8 *)s;

	if (!s || !isalnum((__u8)*p))
		return false;
	for (; *p; p++) {
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return false;
	}
	return strlen(s) < BPM_MAX_NAME;
}

int bpm_oci_parse_pull_ref(const char *raw, struct bpm_oci_client *c,
			   char *repository, size_t repository_sz,
			   char *tag, size_t tag_sz)
{
	const char *p, *slash, *colon, *last_slash;
	char endpoint[BPM_MAX_ENDPOINT];
	char normalized[PATH_MAX];

	if (!raw || strlen(raw) >= sizeof(normalized))
		return -EINVAL;
	bpm_trim(raw, normalized, sizeof(normalized));
	if (strncmp(normalized, "oci://", 6))
		return -EINVAL;
	p = normalized + 6;
	if (!*p || strchr(p, '@') || strchr(p, '?') || strchr(p, '#'))
		return -EINVAL;
	slash = strchr(p, '/');
	if (!slash || slash == p)
		return -EINVAL;
	last_slash = strrchr(p, '/');
	colon = strrchr(p, ':');
	if (!colon || colon <= last_slash || colon == last_slash + 1 || !colon[1])
		return -EINVAL;
	if ((size_t)(slash - p) >= sizeof(endpoint) - 6 ||
	    (size_t)(colon - slash - 1) >= repository_sz ||
	    strlen(colon + 1) >= tag_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, slash - p);
	endpoint[6 + (slash - p)] = '\0';
	memcpy(repository, slash + 1, colon - slash - 1);
	repository[colon - slash - 1] = '\0';
	bpm_copy_string(tag, tag_sz, colon + 1);
	if (strstr(repository, "//") || strchr(repository, '?') ||
	    strchr(repository, '#') || strchr(repository, ':'))
		return -EINVAL;
	for (const char *part = repository; *part;) {
		const char *end = strchr(part, '/');

		if (!end)
			end = part + strlen(part);
		if (end == part || (end - part == 2 && !strncmp(part, "..", 2)))
			return -EINVAL;
		part = *end ? end + 1 : end;
	}
	if (!bpm_package_name_ok(strrchr(repository, '/') ?
				 strrchr(repository, '/') + 1 : repository) ||
	    !bpm_version_ok(tag) || !isalnum((__u8)tag[0]))
		return -EINVAL;
	return bpm_oci_parse_endpoint(endpoint, c);
}

int bpm_oci_parse_push_repo(const char *raw, struct bpm_oci_client *c,
			    char *repository, size_t repository_sz)
{
	char normalized[PATH_MAX], endpoint[BPM_MAX_ENDPOINT];
	const char *p, *slash;

	if (!raw || strlen(raw) >= sizeof(normalized))
		return -EINVAL;
	bpm_trim(raw, normalized, sizeof(normalized));
	if (strncmp(normalized, "oci://", 6))
		return -EINVAL;
	p = normalized + 6;
	slash = strchr(p, '/');
	if (!*p || !slash || slash == p || !slash[1] || strchr(p, '@') ||
	    strchr(p, '?') || strchr(p, '#'))
		return -EINVAL;
	if ((size_t)(slash - p) >= sizeof(endpoint) - 6 ||
	    strlen(slash + 1) >= repository_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, slash - p);
	endpoint[6 + (slash - p)] = '\0';
	bpm_copy_string(repository, repository_sz, slash + 1);
	if (strchr(repository, ':') || strstr(repository, "//") ||
	    strstr(repository, ".."))
		return -EINVAL;
	for (const char *part = repository; *part;) {
		const char *end = strchr(part, '/');

		if (!end)
			end = part + strlen(part);
		if (end == part || (end - part == 1 && part[0] == '.') ||
		    (end - part == 2 && !strncmp(part, "..", 2)))
			return -EINVAL;
		part = *end ? end + 1 : end;
	}
	if (!bpm_package_name_ok(strrchr(repository, '/') ?
				 strrchr(repository, '/') + 1 : repository))
		return -EINVAL;
	return bpm_oci_parse_endpoint(endpoint, c);
}

int bpm_oci_parse_tree_repo(const char *raw, struct bpm_oci_client *c,
			    char *repository, size_t repository_sz)
{
	char endpoint[BPM_MAX_ENDPOINT];
	const char *p, *slash;

	if (!raw || strncmp(raw, "oci://", 6))
		return -EINVAL;
	p = raw + 6;
	slash = strchr(p, '/');
	if (!slash || slash == p || !slash[1] || strchr(p, '?') ||
	    strchr(p, '#') || strchr(p, '@'))
		return -EINVAL;
	if ((size_t)(slash - p) + 6 >= sizeof(endpoint) ||
	    strlen(slash + 1) >= repository_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, (size_t)(slash - p));
	endpoint[6 + (size_t)(slash - p)] = '\0';
	bpm_copy_string(repository, repository_sz, slash + 1);
	if (strstr(repository, "..") || strstr(repository, "//") ||
	    strchr(repository, ':'))
		return -EINVAL;
	return bpm_oci_parse_endpoint(endpoint, c);
}

int bpm_trim(const char *in, char *out, size_t out_sz)
{
	const char *start = in, *end;
	int ret = 0;

	if (!out_sz)
		return -E2BIG;
	while (*start && isspace((__u8)*start))
		start++;
	end = start + strlen(start);
	while (end > start && isspace((__u8)end[-1]))
		end--;
	if ((size_t)(end - start) >= out_sz) {
		end = start + out_sz - 1;
		ret = -E2BIG;
	}
	memmove(out, start, end - start);
	out[end - start] = '\0';
	return ret;
}

int bpm_oci_url(const struct bpm_oci_client *c, const char *repo,
		const char *kind, const char *ref, char *out, size_t sz)
{
	if (strstr(repo, "..") || strstr(repo, "//") || strchr(repo, '?') ||
	    strchr(repo, '#') || strstr(ref, "..") || strchr(ref, '/') ||
	    strchr(ref, '?') || strchr(ref, '#'))
		return -EINVAL;
	if (strsprintf(out, sz, "%s/v2/%s/%s/%s", c->base_url, repo, kind, ref) < 0)
		return -ENAMETOOLONG;
	return 0;
}

int bpm_sha256_hex(const void *data, size_t len,
		   char *hex, size_t hex_sz)
{
	__u8 digest[CRYPTO_SHA256_LEN];

	if (hex_sz < 65 || sha256_buffer(data, len, digest) != 0)
		return -EINVAL;
	hex_encode(digest, sizeof(digest), hex);
	return 0;
}

bool bpm_digest_matches(const char *want, const char *hex)
{
	return want && !strncmp(want, "sha256:", 7) &&
		!strcasecmp(want + 7, hex);
}

static int upload_location(const struct bpm_oci_client *c, const char *location,
			   char *out, size_t out_sz)
{
	size_t base_len = strlen(c->base_url);

	if (!location || !*location)
		return -EINVAL;
	if (location[0] == '/') {
		if (strsprintf(out, out_sz, "%s%s", c->base_url, location) < 0)
			return -ENAMETOOLONG;
		return 0;
	}
	if (strncmp(location, c->base_url, base_len) ||
	    location[base_len] != '/')
		return -EPERM;
	if (strlen(location) >= out_sz)
		return -ENAMETOOLONG;
	bpm_copy_string(out, out_sz, location);
	return 0;
}

int bpm_oci_push_blob(struct bpm_oci_client *c, const char *repository,
		      const void *body, size_t body_len, const char *media,
		      struct bpm_descriptor *out)
{
	struct bpm_http_response r = {};
	char hex[65], digest[72], url[PATH_MAX], upload[PATH_MAX];
	char location[PATH_MAX];
	const char *sep;
	int ret;

	if (bpm_sha256_hex(body, body_len, hex, sizeof(hex)))
		return -EINVAL;
	if (strsprintf(digest, sizeof(digest), "sha256:%s", hex) < 0)
		return -ENAMETOOLONG;
	ret = bpm_oci_url(c, repository, "blobs", digest, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_request(c, "HEAD", url, NULL, NULL, NULL, 0, &r);
	bpm_buffer_free(&r.body);
	if (!ret) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (__s64)body_len;
		return 0;
	}
	if (ret != -ENOENT)
		return ret;

	ret = bpm_oci_url(c, repository, "blobs/uploads", "", url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_request(c, "POST", url, NULL, NULL, NULL, 0, &r);
	if (ret)
		goto out;
	if (r.status != 202 || !r.location[0]) {
		ret = r.status == 202 ? -EINVAL : -EACCES;
		goto out;
	}
	bpm_copy_string(location, sizeof(location), r.location);
	bpm_buffer_free(&r.body);
	r = (struct bpm_http_response){};
	ret = upload_location(c, location, upload, sizeof(upload));
	if (ret)
		goto out;
	sep = strchr(upload, '?') ? "&" : "?";
	if (strsprintf(url, sizeof(url), "%s%sdigest=%s", upload, sep, digest) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = bpm_oci_request(c, "PUT", url, NULL, "application/octet-stream",
			      body, body_len, &r);
	if (!ret && r.status != 201)
		ret = -EACCES;
	if (!ret) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (__s64)body_len;
	}
out:
	bpm_buffer_free(&r.body);
	return ret;
}

void bpm_oci_emit_descriptor(struct json_emit *e, const char *key,
			     const struct bpm_descriptor *d, const char *title)
{
	if (key)
		json_obj_open_key(e, key);
	else
		json_obj_open(e);
	json_kv_string(e, "mediaType", d->media);
	json_kv_string(e, "digest", d->digest);
	json_kv_int(e, "size", d->size);
	if (title) {
		json_obj_open_key(e, "annotations");
		json_kv_string(e, "org.opencontainers.image.title", title);
		json_obj_close(e);
	}
	json_obj_close(e);
}

int bpm_oci_put_manifest(struct bpm_oci_client *c, const char *repository,
			 const char *reference, const __u8 *body,
			 size_t body_len, char *digest, size_t digest_sz)
{
	struct bpm_http_response r = {};
	char hex[65], url[PATH_MAX];
	int ret;

	if (bpm_sha256_hex(body, body_len, hex, sizeof(hex)) ||
	    strsprintf(digest, digest_sz, "sha256:%s", hex) < 0)
		return -ENAMETOOLONG;
	ret = bpm_oci_url(c, repository, "manifests", reference, url,
			  sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_request(c, "PUT", url, "application/vnd.oci.image.manifest.v1+json",
			      "application/vnd.oci.image.manifest.v1+json", body, body_len, &r);
	bpm_buffer_free(&r.body);
	return ret;
}
