/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Serving the keys a user has published on github.
 *
 * A user with github = "login" is given the keys from that account as well as
 * any written out in the file.  The point of doing it here rather than in each
 * client is arithmetic: one machine fetches on a reload, instead of every
 * machine fetching at every login.
 *
 * Three decisions worth knowing about.
 *
 * The fetch happens when the configuration is read -- at start up and on HUP
 * -- and never while serving a request.  A directory that has to reach github
 * before it can answer is a directory that stops working when github does.
 *
 * The fetching itself is done by the system's own client, ftp(1) on NetBSD and
 * fetch(1) on FreeBSD, rather than by an HTTPS client of our own.  That keeps
 * the trust decisions where the administrator already made them: those tools
 * verify certificates by default, against whatever certificate authorities the
 * machine has been given, and no second opinion of ours can quietly disagree.
 *
 * What was fetched is cached on disk, and the cache is used when a fetch
 * fails.  Github being unreachable then means the keys are old rather than
 * gone, which is the difference between a slightly stale directory and a
 * fleet that cannot log in.
 */
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

/* Keys are not enormous, and a reply that is is not one. */
#define MAX_KEYS_BYTES (256 * 1024)

/*
 * A github login is letters, digits and hyphens.  This is checked before the
 * name reaches a command line or a file name, so the check is the security
 * boundary rather than a nicety.
 */
static int
valid_login(const char *login)
{
	size_t i;

	if (login == NULL || *login == '\0' || strlen(login) > 39)
		return 0;
	for (i = 0; login[i] != '\0'; i++) {
		if (!isalnum((unsigned char)login[i]) && login[i] != '-')
			return 0;
	}
	return 1;
}

/* Keep the lines that are keys and drop everything else. */
static void
collect_keys(const char *text, char ***vec, size_t *n)
{
	const char *line = text;

	while (line != NULL && *line != '\0') {
		const char *end = strchr(line, '\n');
		size_t len = (end != NULL) ? (size_t)(end - line) : strlen(line);
		char buf[8192];

		if (len > 0 && len < sizeof(buf)) {
			memcpy(buf, line, len);
			buf[len] = '\0';
			while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == ' '))
				buf[--len] = '\0';
			/*
			 * Every key type github serves begins with one of
			 * these.  Anything else -- an error page, a redirect
			 * notice, a proxy's apology -- is not a key and is not
			 * going into anybody's authorized_keys.
			 */
			if (strncmp(buf, "ssh-", 4) == 0 || strncmp(buf, "ecdsa-", 6) == 0 ||
			    strncmp(buf, "sk-ssh-", 7) == 0 || strncmp(buf, "sk-ecdsa-", 9) == 0)
				(void)stnsd_strings_add(vec, n, buf);
		}
		line = (end != NULL) ? end + 1 : NULL;
	}
}

/* Read the whole of a stream, up to the limit. */
static char *
slurp(FILE *fp)
{
	char *out = NULL;
	size_t len = 0, n;
	char buf[4096];

	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		char *grown;

		if (len + n + 1 > MAX_KEYS_BYTES)
			break;
		if ((grown = realloc(out, len + n + 1)) == NULL) {
			free(out);
			return NULL;
		}
		out = grown;
		memcpy(out + len, buf, n);
		len += n;
		out[len] = '\0';
	}
	return out;
}

static char *
cache_path(const stnsd_conf_t *c, const char *login)
{
	char path[1024];

	if (c->github_cache == NULL)
		return NULL;
	(void)snprintf(path, sizeof(path), "%s/%s", c->github_cache, login);
	return strdup(path);
}

static char *
read_cache(const stnsd_conf_t *c, const char *login)
{
	char *path, *text = NULL;
	FILE *fp;

	if ((path = cache_path(c, login)) == NULL)
		return NULL;
	if ((fp = fopen(path, "r")) != NULL) {
		text = slurp(fp);
		(void)fclose(fp);
	}
	free(path);
	return text;
}

/* Written beside and renamed, so a reader never sees half a file. */
static void
write_cache(const stnsd_conf_t *c, const char *login, const char *text)
{
	char tmp[1024];
	char *path;
	FILE *fp;

	if ((path = cache_path(c, login)) == NULL)
		return;
	(void)snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fp = fopen(tmp, "w")) != NULL) {
		int ok = fputs(text, fp) >= 0;

		if (fclose(fp) == 0 && ok) {
			if (rename(tmp, path) != 0)
				(void)unlink(tmp);
		} else {
			(void)unlink(tmp);
		}
	}
	free(path);
}

/*
 * Run the fetcher and hand back what it wrote.  A command that fails, or that
 * writes something with no key in it, counts as no answer at all: the caller
 * then falls back to the cache rather than replacing good keys with nothing.
 */
static char *
fetch(const stnsd_conf_t *c, const char *login)
{
	char url[1024], command[2048];
	char *text;
	FILE *fp;
	int status;

	(void)snprintf(url, sizeof(url), c->github_url, login);
	(void)snprintf(command, sizeof(command), "%s %s", c->github_fetcher, url);

	if ((fp = popen(command, "r")) == NULL) {
		stnsd_log(LOG_ERR, "stnsd: github: cannot run %s: %s", c->github_fetcher, strerror(errno));
		return NULL;
	}
	text = slurp(fp);
	status = pclose(fp);
	if (status != 0) {
		stnsd_log(LOG_WARNING, "stnsd: github: %s exited %d fetching %s", c->github_fetcher, status, url);
		free(text);
		return NULL;
	}
	return text;
}

/*
 * Give every user with a github login their published keys as well.
 *
 * Called after the configuration is read and before anything is served, so a
 * request never waits for github.  Returns STNSD_OK even when a fetch failed:
 * the keys written in the file are still good, and refusing to start over a
 * third party being down would be its own kind of outage.
 */
int
stnsd_github_resolve(stnsd_conf_t *c)
{
	size_t i, j;

	if (c->github_cache != NULL && mkdir(c->github_cache, 0700) != 0 && errno != EEXIST) {
		stnsd_log(LOG_WARNING, "stnsd: github: no cache in %s: %s", c->github_cache, strerror(errno));
		free(c->github_cache);
		c->github_cache = NULL;
	}

	for (i = 0; i < c->users.n; i++) {
		stnsd_entry_t *u = &c->users.v[i];
		char **keys = NULL;
		size_t nkeys = 0;
		char *text;
		int fresh = 1;

		if (u->github == NULL)
			continue;
		if (!valid_login(u->github)) {
			stnsd_log(LOG_ERR, "stnsd: github: [users.%s] github = \"%s\" is not a login", u->name,
			    u->github);
			continue;
		}

		if ((text = fetch(c, u->github)) == NULL) {
			text = read_cache(c, u->github);
			fresh = 0;
			if (text != NULL)
				stnsd_log(LOG_WARNING, "stnsd: github: using the cached keys for %s", u->github);
			else
				stnsd_log(LOG_ERR, "stnsd: github: no keys for %s and nothing cached", u->github);
		}
		if (text == NULL)
			continue;

		collect_keys(text, &keys, &nkeys);
		if (nkeys == 0) {
			stnsd_log(LOG_WARNING, "stnsd: github: nothing that looks like a key for %s", u->github);
			free(text);
			stnsd_strings_free(keys, nkeys);
			continue;
		}
		if (fresh)
			write_cache(c, u->github, text);
		free(text);

		/* The union of what the file says and what github says. */
		for (j = 0; j < u->nvalues; j++)
			(void)stnsd_strings_add(&keys, &nkeys, u->values[j]);
		stnsd_strings_uniq_sort(keys, &nkeys);
		stnsd_strings_free(u->values, u->nvalues);
		u->values = keys;
		u->nvalues = nkeys;
		u->values_present = 1;
	}
	return STNSD_OK;
}
