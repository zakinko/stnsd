/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Serving the keys a user has published on github.
 *
 * A user with github = "login" is given the keys from that account as well as
 * any written out in the file.  The point of doing it here rather than in each
 * client is arithmetic: one machine fetches hourly, instead of every machine
 * fetching at every login.
 *
 * Three decisions worth knowing about.
 *
 * The fetch happens when the configuration is read -- at start up and on HUP --
 * and then every github_refresh seconds, never while serving a request.  A
 * directory that has to reach github before it can answer is a directory that
 * stops working when github does.  The interval is there because otherwise a
 * key revoked upstream is served until somebody thinks to send a HUP, and the
 * list this file builds is only as good as the last time it was built.
 *
 * The fetching itself is done by the system's own client, ftp(1) on NetBSD and
 * fetch(1) on FreeBSD, rather than by an HTTPS client of our own.  That keeps
 * the trust decisions where the administrator already made them: those tools
 * verify certificates by default, against whatever certificate authorities the
 * machine has been given, and no second opinion of ours can quietly disagree.
 *
 * What was fetched is kept in two places, and both are read when a fetch
 * fails: in this process, so that a reload during an outage does not lose what
 * the previous generation was serving, and on disk, so that a restart does not
 * either.  Github being unreachable then means the keys are old rather than
 * gone, which is the difference between a slightly stale directory and a fleet
 * that cannot log in.
 *
 * The rule the whole file is arranged around: a fetch that fails never takes a
 * key away, and a fetch that succeeds is believed completely -- including when
 * it says there are no keys at all, which is what revoking the last one looks
 * like.  Confusing "github is down" with "the user removed their key" in
 * either direction is the way to get this wrong.
 */
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

/* Keys are not enormous, and a reply that is is not one. */
#define MAX_KEYS_BYTES (256 * 1024)

/*
 * The last body github gave us for each login, kept for as long as the process
 * lives.  A reload builds a fresh configuration and re-fetches; when that
 * fetch fails this is what the new configuration falls back to, so a HUP
 * during an outage cannot lose keys the old one was already serving.
 */
static struct {
	char *login;
	char *text;		/* NULL after a login is known to have no keys */
	int known;		/* whether github has answered for it at all */
} *seen;
static size_t nseen;

static int
remember(const char *login, const char *text)
{
	size_t i;
	void *grown;

	for (i = 0; i < nseen; i++) {
		if (strcmp(seen[i].login, login) == 0) {
			free(seen[i].text);
			seen[i].text = (text != NULL) ? strdup(text) : NULL;
			seen[i].known = 1;
			return STNSD_OK;
		}
	}
	if ((grown = realloc(seen, (nseen + 1) * sizeof(*seen))) == NULL)
		return STNSD_NG;
	seen = grown;
	if ((seen[nseen].login = strdup(login)) == NULL)
		return STNSD_NG;
	seen[nseen].text = (text != NULL) ? strdup(text) : NULL;
	seen[nseen].known = 1;
	nseen++;
	return STNSD_OK;
}

/* Returns 1 if github has answered for this login before, 0 if never. */
static int
recall(const char *login, const char **text)
{
	size_t i;

	for (i = 0; i < nseen; i++) {
		if (strcmp(seen[i].login, login) == 0) {
			*text = seen[i].text;
			return seen[i].known;
		}
	}
	return 0;
}

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
fetch(const stnsd_conf_t *c, const char *login, int *answered)
{
	char url[1024], command[2048];
	char *text;
	FILE *fp;
	int status;

	*answered = 0;
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
	/*
	 * An answer, which may legitimately be an empty one: the account has no
	 * keys, or its last one has just been revoked.  The caller has to know
	 * the difference between this and a fetch that never happened.
	 */
	*answered = 1;
	return text;
}

/* Nothing but blank lines: an answer, and the answer is "no keys". */
static int
is_blank(const char *text)
{
	if (text == NULL)
		return 1;
	while (*text != '\0') {
		if (!isspace((unsigned char)*text))
			return 0;
		text++;
	}
	return 1;
}

static void
forget_cache(const stnsd_conf_t *c, const char *login)
{
	char *path;

	if ((path = cache_path(c, login)) == NULL)
		return;
	(void)unlink(path);
	free(path);
}

/*
 * Remove cached bodies for logins nobody refers to any more.  A login changed
 * in the configuration, or a user deleted from it, would otherwise leave
 * somebody's public keys sitting in the directory for ever with nothing to
 * clear them.
 */
static void
sweep_cache(const stnsd_conf_t *c)
{
	struct dirent *de;
	DIR *dir;
	size_t i;

	if (c->github_cache == NULL || (dir = opendir(c->github_cache)) == NULL)
		return;
	while ((de = readdir(dir)) != NULL) {
		int wanted = 0;

		if (de->d_name[0] == '.' || !valid_login(de->d_name))
			continue;
		for (i = 0; i < c->users.n && !wanted; i++) {
			if (c->users.v[i].github != NULL && strcmp(c->users.v[i].github, de->d_name) == 0)
				wanted = 1;
		}
		if (!wanted) {
			forget_cache(c, de->d_name);
			stnsd_log(LOG_INFO, "stnsd: github: forgot the cached keys for %s, which nobody uses",
			    de->d_name);
		}
	}
	(void)closedir(dir);
}

/*
 * Give every user with a github login their published keys as well.
 *
 * Called after the configuration is read, and again every refresh interval,
 * always before anything is served rather than while answering.  The list is
 * rebuilt each time from the keys the file declared, so a key revoked upstream
 * does not survive in a list it was merged into an hour ago.
 *
 * Returns STNSD_OK even when a fetch failed: the keys written in the file are
 * still good, and refusing to start over a third party being down would be its
 * own kind of outage.
 */
int
stnsd_github_resolve(stnsd_conf_t *c)
{
	size_t i, j;
	int wanted = 0;

	for (i = 0; i < c->users.n; i++) {
		if (c->users.v[i].github != NULL)
			wanted = 1;
	}
	/*
	 * Nobody named a login, so there is nothing to fetch and no reason to
	 * make a directory under /var -- least of all during "stnsd -t", which
	 * is run to read a configuration and should not leave anything behind.
	 */
	if (!wanted)
		return STNSD_OK;

	if (c->github_cache != NULL && mkdir(c->github_cache, 0700) != 0 && errno != EEXIST) {
		stnsd_log(LOG_WARNING, "stnsd: github: no cache in %s: %s", c->github_cache, strerror(errno));
		free(c->github_cache);
		c->github_cache = NULL;
	}

	for (i = 0; i < c->users.n; i++) {
		stnsd_entry_t *u = &c->users.v[i];
		const char *remembered;
		char **keys = NULL;
		size_t nkeys = 0;
		char *text;
		int answered, fresh = 0;

		if (u->github == NULL)
			continue;
		if (!valid_login(u->github)) {
			stnsd_log(LOG_ERR, "stnsd: github: [users.%s] github = \"%s\" is not a login", u->name,
			    u->github);
			continue;
		}

		/*
		 * Keep what the file said the first time through.  Every later
		 * pass starts from it, so this is a replacement rather than an
		 * accumulation.
		 */
		if (u->own_values == NULL && u->nown == 0) {
			for (j = 0; j < u->nvalues; j++)
				(void)stnsd_strings_add(&u->own_values, &u->nown, u->values[j]);
			u->own_present = u->values_present;
		}

		text = fetch(c, u->github, &answered);
		if (answered && is_blank(text)) {
			/*
			 * Github answered, and the answer is that there are no
			 * keys.  That is what revoking the last one looks like,
			 * so it has to be believed and remembered -- otherwise
			 * the next failed fetch resurrects them from the cache.
			 */
			free(text);
			(void)remember(u->github, NULL);
			forget_cache(c, u->github);
			stnsd_log(LOG_INFO, "stnsd: github: %s publishes no keys", u->github);
			text = NULL;
			answered = 1;
			fresh = 1;
		} else if (answered) {
			fresh = 1;
		} else {
			/* No answer.  What we were serving, then what survived a restart. */
			if (recall(u->github, &remembered)) {
				text = (remembered != NULL) ? strdup(remembered) : NULL;
				answered = 1;
				stnsd_log(LOG_WARNING, "stnsd: github: keeping the keys we already had for %s",
				    u->github);
			} else if ((text = read_cache(c, u->github)) != NULL) {
				answered = 1;
				stnsd_log(LOG_WARNING, "stnsd: github: using the cached keys for %s", u->github);
			} else {
				stnsd_log(LOG_ERR, "stnsd: github: no keys for %s and nothing remembered",
				    u->github);
			}
		}

		if (text != NULL) {
			collect_keys(text, &keys, &nkeys);
			if (nkeys == 0) {
				/*
				 * An answer with nothing key-shaped in it is not
				 * an answer: an error page served with a 200, a
				 * proxy's apology.  Treat it as a failure so the
				 * cache is left alone.
				 */
				stnsd_log(LOG_WARNING, "stnsd: github: nothing that looks like a key for %s",
				    u->github);
				stnsd_strings_free(keys, nkeys);
				keys = NULL;
				nkeys = 0;
				fresh = 0;
			} else if (fresh) {
				(void)remember(u->github, text);
				write_cache(c, u->github, text);
			}
			free(text);
		}

		/* What the file said, plus whatever github has to add. */
		for (j = 0; j < u->nown; j++)
			(void)stnsd_strings_add(&keys, &nkeys, u->own_values[j]);
		if (nkeys > 0)
			stnsd_strings_uniq_sort(keys, &nkeys);
		stnsd_strings_free(u->values, u->nvalues);
		u->values = keys;
		u->nvalues = nkeys;
		u->values_present = (nkeys > 0) ? 1 : u->own_present;
	}

	sweep_cache(c);
	return STNSD_OK;
}
