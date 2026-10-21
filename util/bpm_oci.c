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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#include "bpm_oci.h"
#include "crypto.h"
#include "io.h"
#include "seal.h"
#include "json.h"
#include "log.h"
#include "macros.h"
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
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s || strlen(s) >= BPM_MAX_NAME || s[0] == '.')
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
		      (plus && *p == '+')))
			return false;
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
	unsigned char *p;

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

void bpm_buffer_free(struct bpm_buffer *b)
{
	if (b->data)
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

static size_t bpm_write_file(void *ptr, size_t size, size_t nmemb, void *ud)
{
	FILE *fp = ud;
	size_t n = size * nmemb;

	return fwrite(ptr, 1, n, fp);
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
		while (isspace((unsigned char)*v)) v++;
		bpm_copy_string(r->www_auth, sizeof(r->www_auth), v);
	} else if (!strncasecmp(line, "Content-Type:", 13)) {
		v = line + 13;
		while (isspace((unsigned char)*v)) v++;
		v[strcspn(v, " ;\r\n")] = '\0';
		bpm_copy_string(r->content_type, sizeof(r->content_type), v);
	} else if (!strncasecmp(line, "Location:", 9)) {
		v = line + 9;
		while (isspace((unsigned char)*v)) v++;
		v[strcspn(v, "\r\n")] = '\0';
		bpm_copy_string(r->location, sizeof(r->location), v);
	}
	return n;
}

static int base64_value(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

static int decode_basic(const char *in, char *user, size_t usz,
			char *pass, size_t psz)
{
	unsigned char out[BPM_OCI_BASIC_RAW_SIZE];
	size_t n = 0, i = 0;
	int val = 0, bits = -8, x;
	char *colon;

	for (; *in && *in != '"' && n < sizeof(out); in++) {
		if (isspace((unsigned char)*in) || *in == '=')
			continue;
		x = base64_value((unsigned char)*in);
		if (x < 0)
			return -EINVAL;
		val = (val << 6) | x;
		bits += 6;
		if (bits >= 0) {
			out[n++] = (unsigned char)((val >> bits) & 0xff);
			bits -= 8;
		}
	}
	if (n >= sizeof(out))
		return -E2BIG;
	out[n] = '\0';
	colon = memchr(out, ':', n);
	if (!colon || (size_t)(colon - (char *)out) >= usz ||
	    n - (size_t)(colon - (char *)out) - 1 >= psz)
		return -EINVAL;
	memcpy(user, out, (size_t)(colon - (char *)out));
	user[colon - (char *)out] = '\0';
	memcpy(pass, colon + 1, n - (size_t)(colon - (char *)out) - 1);
	pass[n - (size_t)(colon - (char *)out) - 1] = '\0';
	(void)i;
	return 0;
}

static int encode_basic(const char *user, const char *pass,
			char *out, size_t out_sz)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char raw[BPM_OCI_BASIC_RAW_SIZE];
	size_t len, need, i, o = 0;

	if (snprintf(raw, sizeof(raw), "%s:%s", user, pass) >= (int)sizeof(raw))
		return -E2BIG;
	len = strlen(raw);
	need = 4 * ((len + 2) / 3) + 1;
	if (need > out_sz)
		return -ENOSPC;
	for (i = 0; i < len; i += 3) {
		unsigned v = (unsigned char)raw[i] << 16;
		if (i + 1 < len) v |= (unsigned char)raw[i + 1] << 8;
		if (i + 2 < len) v |= (unsigned char)raw[i + 2];
		out[o++] = alphabet[(v >> 18) & 63];
		out[o++] = alphabet[(v >> 12) & 63];
		out[o++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
		out[o++] = i + 2 < len ? alphabet[v & 63] : '=';
	}
	out[o] = '\0';
	return 0;
}

static int load_registry_auth(const char *registry, struct bpm_oci_client *c)
{
	const char *authfile = getenv("REGISTRY_AUTH_FILE");
	const char *docker = getenv("DOCKER_CONFIG");
	char path[PATH_MAX];
	char needle[BPM_MAX_ENDPOINT + 8];
	unsigned char *body = NULL;
	size_t body_len = 0;
	char *p, *end, *auth;
	int rc;

	if (getenv("BPM_OCI_USERNAME") && getenv("BPM_OCI_PASSWORD")) {
		snprintf(c->username, sizeof(c->username), "%s", getenv("BPM_OCI_USERNAME"));
		snprintf(c->password, sizeof(c->password), "%s", getenv("BPM_OCI_PASSWORD"));
		return 0;
	}
	if (!authfile && docker) {
		if (snprintf(path, sizeof(path), "%s/config.json", docker) >= (int)sizeof(path))
			return -ENAMETOOLONG;
		authfile = path;
	}
	if (!authfile) {
		const char *home = getenv("HOME");
		if (!home) home = "/root";
		if (snprintf(path, sizeof(path), "%s/.docker/config.json", home) >= (int)sizeof(path))
			return -ENAMETOOLONG;
		authfile = path;
	}
	rc = shirudo_read_file(authfile, 4u * 1024u * 1024u, &body, &body_len);
	if (rc) return rc == -ENOENT ? 0 : rc;
	/*
	 * The auth file is local input; require the registry key and auth
	 * member to occur in the same JSON object before accepting
	 * credentials.
	 */
	snprintf(needle, sizeof(needle), "\"%s\"", registry);
	p = strstr((char *)body, needle);
	if (!p) { xfree(body, body_len + 1); return 0; }
	end = strchr(p, '}');
	if (!end) { xfree(body, body_len + 1); return -EINVAL; }
	auth = strstr(p, "\"auth\"");
	if (!auth || auth > end) { xfree(body, body_len + 1); return 0; }
	auth = strchr(auth, ':');
	if (!auth) { xfree(body, body_len + 1); return -EINVAL; }
	while (*++auth && isspace((unsigned char)*auth)) {}
	if (*auth != '"') { xfree(body, body_len + 1); return -EINVAL; }
	rc = decode_basic(auth + 1, c->username, sizeof(c->username),
			  c->password, sizeof(c->password));
	xfree(body, body_len + 1);
	return rc;
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
		snprintf(transport, sizeof(transport), "%s", scheme);
	}
	snprintf(c->registry, sizeof(c->registry), "%s", p);
	if (snprintf(c->base_url, sizeof(c->base_url), "%s://%s", transport, p) >=
	    (int)sizeof(c->base_url))
		return -ENAMETOOLONG;
	if (getenv("BPM_OCI_CA_FILE")) {
		const char *ca_file = getenv("BPM_OCI_CA_FILE");
		struct shirudo_cert ca = {};

		if (strlen(ca_file) >= sizeof(c->ca_file))
			return -ENAMETOOLONG;
		bpm_copy_string(c->ca_file, sizeof(c->ca_file), ca_file);
		if (shirudo_cert_read_file(c->ca_file, &ca) != 0) {
			pr_err("bpm OCI: BPM_OCI_CA_FILE is not a readable certificate");
			return -EINVAL;
		}
		shirudo_cert_free(&ca);
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

static int curl_once_ex(struct bpm_oci_client *c, const char *method,
			const char *url, const char *accept,
			const char *content_type, const void *body, size_t body_len,
			const char *auth, struct bpm_http_response *r, FILE *file)
{
	CURL *curl;
	struct curl_slist *headers = NULL;
	CURLcode cc;
	long status = 0;
	char errbuf[CURL_ERROR_SIZE] = {};

	curl = curl_easy_init();
	if (!curl) return -ENOMEM;
	if (accept) {
		char h[256];
		snprintf(h, sizeof(h), "Accept: %s", accept);
		headers = curl_slist_append(headers, h);
	}
	if (content_type) {
		char h[256];
		snprintf(h, sizeof(h), "Content-Type: %s", content_type);
		headers = curl_slist_append(headers, h);
	}
	if (auth) {
		char h[8192];
		snprintf(h, sizeof(h), "Authorization: %s", auth);
		headers = curl_slist_append(headers, h);
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	if (!strcasecmp(method, "HEAD"))
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	/*
	 * OCI registries commonly redirect blob GETs to a signed CDN URL.
	 * Follow only for file downloads, never for manifest or upload calls.
	 */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, file ? 1L : 0L);
	if (file) {
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
	if (shirudo_tls_curl_policy(curl, &c->tls_ca)) {
		pr_err("bpm OCI request %s: cannot apply TLS policy", url);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return -EHOSTUNREACH;
	}
	if (body) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
	}
	if (file) {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_file);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
	} else {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, r);
	}
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, bpm_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);
	if (auth && !strncmp(auth, "Basic ", 6)) {
		/* Header is already constructed; do not let curl negotiate or leak it. */
	}
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	r->status = status;
	if (cc != CURLE_OK) {
		pr_err("bpm OCI request %s: %s", url, errbuf[0] ? errbuf : curl_easy_strerror(cc));
		status = -1;
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	shirudo_tls_ca_cleanup(&c->tls_ca);
	return status < 0 ? -EHOSTUNREACH : 0;
}

static int curl_once(struct bpm_oci_client *c, const char *method,
			     const char *url, const char *accept, const char *auth,
			     struct bpm_http_response *r, FILE *file)
{
	return curl_once_ex(c, method, url, accept, NULL, NULL, 0, auth, r, file);
}

static int parse_challenge(const char *header, char *realm, size_t rsz,
			    char *service, size_t ssz, char *scope, size_t zsz)
{
	const char *p;
	const char *q;

	if (!header || strncasecmp(header, "Bearer", 6) != 0)
		return -EINVAL;
	for (p = header + 6; *p;) {
		while (*p == ' ' || *p == ',') p++;
		if (!strncmp(p, "realm=\"", 7)) {
			p += 7; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= rsz) return -ENAMETOOLONG;
			memcpy(realm, p, q - p); realm[q - p] = 0; p = q + 1;
		} else if (!strncmp(p, "service=\"", 9)) {
			p += 9; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= ssz) return -ENAMETOOLONG;
			memcpy(service, p, q - p); service[q - p] = 0; p = q + 1;
		} else if (!strncmp(p, "scope=\"", 7)) {
			p += 7; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= zsz) return -ENAMETOOLONG;
			memcpy(scope, p, q - p); scope[q - p] = 0; p = q + 1;
		} else {
			p = strchr(p, ','); if (!p) break;
		}
	}
	return realm[0] ? 0 : -EINVAL;
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
	char *token;
	int rc = -EINVAL;

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
	if (snprintf(url, sizeof(url), "%s?service=%s&scope=%s", realm,
		     esc_service, esc_scope) >= (int)sizeof(url)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (c->username[0]) {
		rc = encode_basic(c->username, c->password, basic,
				   sizeof(basic));
		if (rc)
			goto out;
		if (snprintf(auth_header, sizeof(auth_header),
			     "Authorization: Basic %s", basic) >=
		    (int)sizeof(auth_header)) {
			rc = -E2BIG;
			goto out;
		}
		headers = curl_slist_append(headers, auth_header);
		if (!headers) {
			rc = -ENOMEM;
			goto out;
		}
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	if (shirudo_tls_curl_policy(curl, &c->tls_ca)) {
		rc = -EINVAL;
		goto out;
	}
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
	if (cc != CURLE_OK) {
		rc = -EHOSTUNREACH;
		goto out;
	}
	if (r.status >= 300) {
		rc = -EACCES;
		goto out;
	}
	token = strstr((char *)r.body.data, "\"token\"");
	if (!token) token = strstr((char *)r.body.data, "\"access_token\"");
	if (!token || !(token = strchr(token, ':')))
		goto out;
	while (*++token && isspace((unsigned char)*token)) {}
	if (*token++ != '"')
		goto out;
	{
		char *end = strchr(token, '"');
		if (!end || (size_t)(end - token) >= sizeof(c->token))
			goto out;
		memcpy(c->token, token, end - token); c->token[end - token] = 0;
	}
	rc = 0;
out:
	curl_free(esc_service);
	curl_free(esc_scope);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	shirudo_tls_ca_cleanup(&c->tls_ca);
	bpm_buffer_free(&r.body);
	return rc;
}

int bpm_oci_get_memory(struct bpm_oci_client *c, const char *url,
			   const char *accept, struct bpm_buffer *out)
{
	struct bpm_http_response r = {};
	char auth[BPM_OCI_AUTH_VALUE_SIZE];
	int rc;

	rc = curl_once(c, "GET", url, accept, NULL, &r, NULL);
	if (rc) goto out;
	if (r.status == 401 && r.www_auth[0]) {
		if (!strncasecmp(r.www_auth, "Bearer", 6)) {
			rc = get_bearer_token(c, r.www_auth);
			if (rc) goto out;
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
		} else if (!strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
			char encoded[BPM_OCI_BASIC_ENCODED_SIZE];
			rc = encode_basic(c->username, c->password, encoded, sizeof(encoded));
			if (rc) goto out;
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
		} else { rc = -EACCES; goto out; }
		bpm_buffer_free(&r.body); r = (struct bpm_http_response){};
		rc = curl_once(c, "GET", url, accept, auth, &r, NULL);
	}
	if (!rc && (r.status < 200 || r.status >= 300)) rc = r.status == 404 ? -ENOENT : -EACCES;
	if (!rc) { *out = r.body; r.body.data = NULL; }
out:
	bpm_buffer_free(&r.body);
	return rc;
}

int bpm_oci_get_file(struct bpm_oci_client *c, const char *url,
			const char *accept, const char *path)
{
	struct bpm_http_response r = {};
	FILE *fp;
	char auth[BPM_OCI_AUTH_VALUE_SIZE];
	int rc;

	fp = fopen(path, "wb");
	if (!fp) return -errno;
	rc = curl_once(c, "GET", url, accept, NULL, &r, fp);
	if (!rc && r.status == 401 && r.www_auth[0] && !strncasecmp(r.www_auth, "Bearer", 6)) {
		fclose(fp); unlink(path); fp = fopen(path, "wb");
		if (!fp) {
			rc = -errno;
			bpm_buffer_free(&r.body);
			return rc;
		}
		rc = get_bearer_token(c, r.www_auth);
		if (!rc) {
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
			memset(&r, 0, sizeof(r));
			rc = curl_once(c, "GET", url, accept, auth, &r, fp);
		}
	} else if (!rc && r.status == 401 && r.www_auth[0] &&
		   !strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
		char encoded[BPM_OCI_BASIC_ENCODED_SIZE];
		fclose(fp); unlink(path); fp = fopen(path, "wb");
		if (!fp) {
			rc = -errno;
			bpm_buffer_free(&r.body);
			return rc;
		}
		rc = encode_basic(c->username, c->password, encoded, sizeof(encoded));
		if (!rc) {
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
			memset(&r, 0, sizeof(r));
			rc = curl_once(c, "GET", url, accept, auth, &r, fp);
		}
	}
	if (!rc && (r.status < 200 || r.status >= 300)) rc = r.status == 404 ? -ENOENT : -EACCES;
	if (fclose(fp) && !rc) rc = -EIO;
	bpm_buffer_free(&r.body);
	if (rc) unlink(path);
	return rc;
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
	int rc;

	*r = (struct bpm_http_response){};
	rc = curl_once_ex(c, method, url, accept, content_type, body, body_len,
			  NULL, r, NULL);
	if (rc)
		return rc;
	if (r->status == 401 && r->www_auth[0]) {
		if (!strncasecmp(r->www_auth, "Bearer", 6)) {
			rc = get_bearer_token(c, r->www_auth);
			if (rc)
				return rc;
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
		} else if (!strncasecmp(r->www_auth, "Basic", 5) && c->username[0]) {
			char encoded[BPM_OCI_BASIC_ENCODED_SIZE];

			rc = encode_basic(c->username, c->password, encoded,
					   sizeof(encoded));
			if (rc)
				return rc;
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
		} else {
			return -EACCES;
		}
		bpm_buffer_free(&r->body);
		*r = (struct bpm_http_response){};
		rc = curl_once_ex(c, method, url, accept, content_type, body,
				   body_len, auth, r, NULL);
		if (rc)
			return rc;
	}
	if (r->status < 200 || r->status >= 300)
	{
		if (r->status != 404) {
			if (r->body.data && r->body.len) {
				size_t n = r->body.len > 512 ? 512 : r->body.len;

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
	int n;
	struct bpm_descriptor scratch;
	char package_name[BPM_MAX_NAME];
};

static int on_descriptor(void *ud)
{
	struct desc_sink *s = ud;
	if (s->n >= BPM_MAX_ENTRIES) return -E2BIG;
	s->items[s->n++] = s->scratch;
	memset(&s->scratch, 0, sizeof(s->scratch));
	return 0;
}

int bpm_oci_parse_manifest(const unsigned char *body, size_t len,
			  struct bpm_descriptor *layers, int *n_layers,
			  char *package_name, size_t package_name_sz)
{
	struct desc_sink sink = { .items = layers };
	struct shirudo_json_array arr = { on_descriptor, &sink };
	struct shirudo_json_field layer_annotations[1], manifest_annotations[1];
	struct shirudo_json_field sub[4], root[3];
	int64_t schema = 0;

	memset(sub, 0, sizeof(sub));
	sub[0] = (struct shirudo_json_field){ .key = "mediaType", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.media, .dst_cap = sizeof(sink.scratch.media) };
	sub[1] = (struct shirudo_json_field){ .key = "digest", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.digest, .dst_cap = sizeof(sink.scratch.digest) };
	sub[2] = (struct shirudo_json_field){ .key = "size", .type = SHIRUDO_JSON_T_INT,
		.dst = &sink.scratch.size };
	layer_annotations[0] = (struct shirudo_json_field){
		.key = "org.opencontainers.image.title", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.title, .dst_cap = sizeof(sink.scratch.title) };
	sub[3] = (struct shirudo_json_field){ .key = "annotations", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = layer_annotations, .n_sub = ARRAY_SIZE(layer_annotations) };
	manifest_annotations[0] = (struct shirudo_json_field){
		.key = "dev.shirudo.bpm.package.name", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.package_name, .dst_cap = sizeof(sink.package_name) };
	memset(root, 0, sizeof(root));
	root[0] = (struct shirudo_json_field){ .key = "schemaVersion", .type = SHIRUDO_JSON_T_INT,
		.dst = &schema };
	root[1] = (struct shirudo_json_field){ .key = "layers", .type = SHIRUDO_JSON_T_ARRAY,
		.dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	root[2] = (struct shirudo_json_field){ .key = "annotations", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = manifest_annotations, .n_sub = ARRAY_SIZE(manifest_annotations) };
	if (shirudo_json_parse((const char *)body, len, root, ARRAY_SIZE(root)) ||
	    !root[0].seen || schema != 2 || !root[1].seen)
		return -EINVAL;
	*n_layers = sink.n;
	if (package_name && package_name_sz)
		bpm_copy_string(package_name, package_name_sz, sink.package_name);
	return 0;
}

bool bpm_package_name_ok(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !isalnum((unsigned char)*p))
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return false;
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
		if (!end) end = part + strlen(part);
		if (end == part || (end - part == 2 && !strncmp(part, "..", 2)))
			return -EINVAL;
		part = *end ? end + 1 : end;
	}
	if (!bpm_package_name_ok(strrchr(repository, '/') ?
				 strrchr(repository, '/') + 1 : repository) ||
	    !bpm_version_ok(tag) || !isalnum((unsigned char)tag[0]))
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

void bpm_trim(const char *in, char *out, size_t out_sz)
{
	const char *start = in, *end;

	while (*start && isspace((unsigned char)*start))
		start++;
	end = start + strlen(start);
	while (end > start && isspace((unsigned char)end[-1]))
		end--;
	if ((size_t)(end - start) >= out_sz)
		end = start + out_sz - 1;
	memmove(out, start, end - start);
	out[end - start] = '\0';
}

int bpm_oci_url(const struct bpm_oci_client *c, const char *repo,
			const char *kind, const char *ref, char *out, size_t sz)
{
	if (strstr(repo, "..") || strstr(repo, "//") || strchr(repo, '?') || strchr(repo, '#') ||
	    strstr(ref, "..") || strchr(ref, '/') || strchr(ref, '?') || strchr(ref, '#')) return -EINVAL;
	if (snprintf(out, sz, "%s/v2/%s/%s/%s", c->base_url, repo, kind, ref) >= (int)sz) return -ENAMETOOLONG;
	return 0;
}

int bpm_sha256_hex(const void *data, size_t len,
			     char *hex, size_t hex_sz)
{
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	if (hex_sz < 65 || shirudo_sha256_buffer(data, len, digest) != 0)
		return -EINVAL;
	for (unsigned int i = 0; i < sizeof(digest); i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[64] = 0;
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
		if (snprintf(out, out_sz, "%s%s", c->base_url, location) >=
		    (int)out_sz)
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
	char location[PATH_MAX], *sep;
	int rc;

	if (bpm_sha256_hex(body, body_len, hex, sizeof(hex)))
		return -EINVAL;
	if (snprintf(digest, sizeof(digest), "sha256:%s", hex) >=
	    (int)sizeof(digest))
		return -ENAMETOOLONG;
	if ((rc = bpm_oci_url(c, repository, "blobs", digest, url,
				       sizeof(url))))
		return rc;
	rc = bpm_oci_request(c, "HEAD", url, NULL, NULL, NULL, 0, &r);
	bpm_buffer_free(&r.body);
	if (!rc) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (int64_t)body_len;
		return 0;
	}
	if (rc != -ENOENT)
		return rc;

	if ((rc = bpm_oci_url(c, repository, "blobs/uploads", "", url,
				       sizeof(url))))
		return rc;
	rc = bpm_oci_request(c, "POST", url, NULL, NULL, NULL, 0, &r);
	if (rc)
		goto out;
	if (r.status != 202 || !r.location[0]) {
		rc = r.status == 202 ? -EINVAL : -EACCES;
		goto out;
	}
	bpm_copy_string(location, sizeof(location), r.location);
	bpm_buffer_free(&r.body);
	r = (struct bpm_http_response){};
	if ((rc = upload_location(c, location, upload, sizeof(upload))))
		goto out;
	sep = strchr(upload, '?') ? "&" : "?";
	if (snprintf(url, sizeof(url), "%s%sdigest=%s", upload, sep, digest) >=
	    (int)sizeof(url)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	rc = bpm_oci_request(c, "PUT", url, NULL, "application/octet-stream",
			 body, body_len, &r);
	if (!rc && r.status != 201)
		rc = -EACCES;
	if (!rc) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (int64_t)body_len;
	}
out:
	bpm_buffer_free(&r.body);
	return rc;
}

void bpm_oci_emit_descriptor(struct shirudo_json_emit *e, const char *key,
			    const struct bpm_descriptor *d, const char *title)
{
	if (key)
		shirudo_json_obj_open_key(e, key);
	else
		shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "mediaType", d->media);
	shirudo_json_kv_string(e, "digest", d->digest);
	shirudo_json_kv_int(e, "size", d->size);
	if (title) {
		shirudo_json_obj_open_key(e, "annotations");
		shirudo_json_kv_string(e, "org.opencontainers.image.title", title);
		shirudo_json_obj_close(e);
	}
	shirudo_json_obj_close(e);
}

int bpm_oci_put_manifest(struct bpm_oci_client *c, const char *repository,
			    const char *reference, const unsigned char *body,
			    size_t body_len, char *digest, size_t digest_sz)
{
	struct bpm_http_response r = {};
	char hex[65], url[PATH_MAX];
	int rc;

	if (bpm_sha256_hex(body, body_len, hex, sizeof(hex)) ||
	    snprintf(digest, digest_sz, "sha256:%s", hex) >= (int)digest_sz)
		return -ENAMETOOLONG;
	if ((rc = bpm_oci_url(c, repository, "manifests", reference, url,
				       sizeof(url))))
		return rc;
	rc = bpm_oci_request(c, "PUT", url, "application/vnd.oci.image.manifest.v1+json",
			 "application/vnd.oci.image.manifest.v1+json", body, body_len, &r);
	bpm_buffer_free(&r.body);
	return rc;
}
