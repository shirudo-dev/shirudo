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
#include <shirudo/string.h>

#include "config.h"
#include "crypto.h"
#include "image_config.h"
#include "io.h"
#include "log.h"

/* Hybrid-first exception list; default policy below remains hybrid-only. */
#define TLS_GROUPS	"*X25519MLKEM768:SecP256r1MLKEM768"
#define TLS_CLASSICAL_GROUPS \
	"*X25519MLKEM768:SecP256r1MLKEM768:X25519:secp256r1"

/*
 * Exceptions are exact DNS names from the active HTTPS URL. This also
 * checks redirected URLs, so each registry host must be opted in itself.
 */
static bool tls_classical_host_allowed(CURL *curl)
{
	struct config cfg __cleanup(config_clear) = {};
	const char *allowlist, *effective_url;
	CURLU *url = NULL;
	char *scheme = NULL, *host = NULL;
	size_t host_len;
	bool allowed = false;

	if (!image_config_get(&cfg) && config_load(&cfg))
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
	if (!dns_name_valid(host))
		goto out;

	while (*allowlist) {
		const char *end = strchr(allowlist, ',');
		size_t len = end ? (size_t)(end - allowlist) : strlen(allowlist);
		char entry[254];

		if (len < sizeof(entry)) {
			memcpy(entry, allowlist, len);
			entry[len] = '\0';
			if (dns_name_valid(entry) && !strncasecmp(host, entry, len) &&
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
	curl_free(host);
	curl_free(scheme);
	curl_url_cleanup(url);
	return allowed;
}

static void tls_info_callback(const SSL *ssl, int where, int ret
			      __attribute__((__unused__)))
{
	const char *group, *host;
	int group_id;

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

void tls_ca_cleanup(struct tls_ca *ca)
{
	if (ca)
		ca->impl = NULL;
}

static CURLcode sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	const struct tls_ca *ca = userptr;
	const char *path = ca ? ca->path : NULL;
	SSL_CTX *ctx = sslctx;
	X509 *cert;
	BIO *bio;
	const char *groups = TLS_GROUPS;
	int fd;

	if (tls_classical_host_allowed(curl)) {
		/* Keep this per-host policy from leaking through libcurl reuse. */
		if (curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
		    curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L) !=
			    CURLE_OK)
			return CURLE_SSL_CONNECT_ERROR;
		groups = TLS_CLASSICAL_GROUPS;
		SSL_CTX_set_info_callback(ctx, tls_info_callback);
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

int tls_curl_policy(CURL *curl, struct tls_ca *ca)
{
	if (!curl)
		return -EINVAL;
	if (curl_easy_setopt(curl, CURLOPT_SSLVERSION,
			     (long)CURL_SSLVERSION_TLSv1_3) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
			     sslctx_callback) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ca) != CURLE_OK)
		return -EINVAL;
	return 0;
}
