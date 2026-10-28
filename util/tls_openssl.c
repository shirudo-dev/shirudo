// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl TLS policy and trust-anchor glue for the OpenSSL-backed profile.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <curl/curl.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <shirudo/misc.h>

#include "config.h"
#include "crypto.h"
#include "image_config.h"
#include "io.h"
#include "log.h"

/* Hybrid-first exception list; default policy below remains hybrid-only. */
#define SHIRUDO_TLS_GROUPS	"*X25519MLKEM768:SecP256r1MLKEM768"
#define SHIRUDO_TLS_CLASSICAL_GROUPS \
	"*X25519MLKEM768:SecP256r1MLKEM768:X25519:secp256r1"

static bool numeric_dns_label(const char *label, size_t len)
{
	size_t i = 0;
	bool hex = len > 2 && label[0] == '0' &&
		   (label[1] == 'x' || label[1] == 'X');

	if (!len)
		return false;
	if (hex)
		i = 2;
	for (; i < len; i++) {
		__u8 c = label[i];

		if (c >= '0' && c <= '9')
			continue;
		if (hex && ((c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F')))
			continue;
		return false;
	}
	return !hex || i > 2;
}

static bool valid_dns_name(const char *name)
{
	size_t len = strlen(name), label_len = 0, label_start = 0;
	bool numeric_address = true;
	size_t i;

	if (!len || len > 253)
		return false;
	for (i = 0; i < len; i++) {
		__u8 c = name[i];

		if (c == '.') {
			if (!label_len || label_len > 63 || name[i - 1] == '-')
				return false;
			if (!numeric_dns_label(name + label_start, label_len))
				numeric_address = false;
			label_start = i + 1;
			label_len = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-') ||
		    (!label_len && c == '-'))
			return false;
		label_len++;
	}
	if (!label_len || label_len > 63 || name[len - 1] == '-')
		return false;
	if (!numeric_dns_label(name + label_start, label_len))
		numeric_address = false;
	return !numeric_address;
}

/*
 * Exceptions are exact DNS names from the active HTTPS URL. This also
 * checks redirected URLs, so each registry host must be opted in itself.
 */
static bool tls_classical_host_allowed(CURL *curl)
{
	struct shirudo_config cfg = {};
	const char *allowlist, *effective_url;
	CURLU *url = NULL;
	char *scheme = NULL, *host = NULL;
	size_t host_len;
	bool allowed = false;

	if (!shirudo_image_config_get(&cfg) && config_load(&cfg))
		return false;
	if (!cfg.tls_classical_hosts_valid ||
	    !cfg.tls_classical_hosts[0])
		return false;
	allowlist = cfg.tls_classical_hosts;
	if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url) !=
		    CURLE_OK ||
	    !effective_url)
		return false;
	url = curl_url();
	if (!url || curl_url_set(url, CURLUPART_URL, effective_url, 0) !=
		    CURLUE_OK ||
	    curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
	    strcasecmp(scheme, "https") ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK)
		goto out;
	host_len = strlen(host);
	if (host_len && host[host_len - 1] == '.')
		host[--host_len] = '\0';
	if (!valid_dns_name(host))
		goto out;

	while (*allowlist) {
		const char *end = strchr(allowlist, ',');
		size_t len = end ? (size_t)(end - allowlist) : strlen(allowlist);
		char entry[254];

		if (len < sizeof(entry)) {
			memcpy(entry, allowlist, len);
			entry[len] = '\0';
			if (valid_dns_name(entry) && !strncasecmp(host, entry, len) &&
			    host_len == len) {
				allowed = true;
				break;
			}
		}
		if (!end)
			break;
		allowlist = end + 1;
	}
out:
	if (host)
		curl_free(host);
	if (scheme)
		curl_free(scheme);
	if (url)
		curl_url_cleanup(url);
	return allowed;
}

static void shirudo_tls_info_callback(const SSL *ssl, int where, int ret)
{
	const char *group, *host;
	int group_id;

	(void)ret;
	if (!(where & SSL_CB_HANDSHAKE_DONE))
		return;
	group_id = SSL_get_negotiated_group((SSL *)ssl);
	group = group_id == NID_undef ? NULL :
		SSL_group_to_name((SSL *)ssl, group_id);
	if (group && (!strcasecmp(group, "X25519MLKEM768") ||
		      !strcasecmp(group, "SecP256r1MLKEM768")))
		return;
	host = SSL_get_servername((SSL *)ssl, TLSEXT_NAMETYPE_host_name);
	pr_warn("TLS non-hybrid key exchange with %s: %s",
		host ? host : "unknown host", group ? group : "unknown group");
}

void tls_ca_cleanup(struct shirudo_tls_ca *ca)
{
	if (ca)
		ca->impl = NULL;
}

static CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	const struct shirudo_tls_ca *ca = userptr;
	const char *path = ca ? ca->path : NULL;
	SSL_CTX *ctx = sslctx;
	X509 *cert;
	BIO *bio;
	const char *groups = SHIRUDO_TLS_GROUPS;
	int fd;

	if (tls_classical_host_allowed(curl)) {
		/* Keep this per-host policy from leaking through libcurl reuse. */
		if (curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
		    curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L) !=
			    CURLE_OK)
			return CURLE_SSL_CONNECT_ERROR;
		groups = SHIRUDO_TLS_CLASSICAL_GROUPS;
		SSL_CTX_set_info_callback(ctx, shirudo_tls_info_callback);
	}
	if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
	    SSL_CTX_set1_groups_list(ctx, groups) != 1) {
		ERR_clear_error();
		return CURLE_SSL_CIPHER;
	}
	if (!path || !path[0])
		return CURLE_OK;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return CURLE_SSL_CACERT_BADFILE;
	if (check_trusted(fd, path, false)) {
		close(fd);
		return CURLE_SSL_CACERT_BADFILE;
	}
	bio = BIO_new_fd(fd, BIO_CLOSE);
	if (!bio) {
		close(fd);
		return CURLE_SSL_CACERT_BADFILE;
	}
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!cert)
		return CURLE_SSL_CACERT_BADFILE;
	if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert) != 1)
		ERR_clear_error();
	X509_free(cert);
	return CURLE_OK;
}

int tls_curl_policy(CURL *curl, struct shirudo_tls_ca *ca)
{
	if (!curl)
		return -EINVAL;
	if (curl_easy_setopt(curl, CURLOPT_SSLVERSION,
			     (long)CURL_SSLVERSION_TLSv1_3) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
			     shirudo_sslctx_callback) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ca) != CURLE_OK)
		return -EINVAL;
	return 0;
}
