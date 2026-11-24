// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>

#include "image_cache.h"
#include "image_cache_test.h"
#include "paths.h"
#include "unit.h"

#undef IMAGE_CACHE_DIR
#define IMAGE_CACHE_DIR "/tmp"

static char staging_path[PATH_MAX];
static pthread_t fetch_thread;
static atomic_bool sent_sigint;

int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags)
{
	return 0;
}

int __wrap_seal_label(const char *path)
{
	return strscpy(staging_path, path, sizeof(staging_path)) < 0 ? -E2BIG : 0;
}

/* Keep getaddrinfo busy after SIGINT to catch cleanup that waits for it. */
int getaddrinfo(const char *host, const char *service,
		const struct addrinfo *hints, struct addrinfo **result)
{
	struct timespec delay = { .tv_sec = 1 };

	if (strcmp(host, "image-cancel.invalid"))
		return EAI_NONAME;
	while (nanosleep(&delay, &delay) && errno == EINTR)
		;
	if (!atomic_exchange(&sent_sigint, true) &&
	    pthread_kill(fetch_thread, SIGINT))
		return EAI_SYSTEM;
	delay.tv_sec = 8;
	while (nanosleep(&delay, &delay) && errno == EINTR)
		;
	return EAI_AGAIN;
}

static int unexpected_verify(const struct config_image_open *image, void *ctx)
{
	EXPECT_TRUE(false);
	return -EINVAL;
}

/* Whether download_perform() catches SIGINT with this build of libcurl. */
static bool quick_exit_enabled(void)
{
#if LIBCURL_VERSION_NUM >= 0x075700
	const struct curl_version_info_data *version =
		curl_version_info(CURLVERSION_NOW);
	CURL *curl = curl_easy_init();
	bool enabled;

	if (!curl)
		return false;
	enabled = (version->features & CURL_VERSION_ASYNCHDNS) &&
		  curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L) == CURLE_OK;
#if LIBCURL_VERSION_NUM < 0x081400
	if (version->version_num >= 0x081400)
		enabled = false;
#endif
	curl_easy_cleanup(curl);
	return enabled;
#else
	return false;
#endif
}

static void interrupted_download_removes_staging(void)
{
	const struct curl_version_info_data *version =
		curl_version_info(CURLVERSION_NOW);
	struct sigaction action = { .sa_handler = SIG_DFL };
	struct config_update_target target = {};
	struct timespec before, after;
	sigset_t signals;
	int ret;

	if (version->ares || !quick_exit_enabled())
		unit_skip("requires libcurl's threaded resolver and quick cleanup");
	ASSERT_EQ(setenv("no_proxy", "*", 1), 0);
	sigemptyset(&action.sa_mask);
	ASSERT_EQ(sigaction(SIGINT, &action, NULL), 0);
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	ASSERT_EQ(sigprocmask(SIG_UNBLOCK, &signals, NULL), 0);
	fetch_thread = pthread_self();
	ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &before), 0);
	ret = image_cache_fetch("https://image-cancel.invalid/config", &target,
				unexpected_verify, NULL);
	ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &after), 0);
	EXPECT_EQ(ret, -EINTR);
	EXPECT_LT(after.tv_sec - before.tv_sec, 6);
	EXPECT_EQ(sigaction(SIGINT, NULL, &action), 0);
	EXPECT_TRUE(action.sa_handler == SIG_DFL);
	ASSERT_TRUE(staging_path[0]);
	EXPECT_EQ(access(staging_path, F_OK), -1);
	EXPECT_EQ(errno, ENOENT);
}

static void failed_download_removes_staging(void)
{
	struct sigaction action = { .sa_handler = SIG_DFL };
	struct config_update_target target = {};

	ASSERT_EQ(setenv("no_proxy", "*", 1), 0);
	sigemptyset(&action.sa_mask);
	ASSERT_EQ(sigaction(SIGINT, &action, NULL), 0);
	EXPECT_EQ(image_cache_fetch("https://image-fail.invalid/config", &target,
				    unexpected_verify, NULL), -EIO);
	ASSERT_TRUE(staging_path[0]);
	EXPECT_EQ(access(staging_path, F_OK), -1);
	EXPECT_EQ(errno, ENOENT);
}

static const struct unit_case cases[] = {
	UNIT_CASE(interrupted_download_removes_staging),
	UNIT_CASE(failed_download_removes_staging),
	{}
};

UNIT_SUITE(image_cache, cases);
