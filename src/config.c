/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Reading stns.conf.
 *
 * The schema is upstream STNS's, so that a configuration can be moved between
 * the two servers unchanged: [users.<name>] and [groups.<name>] tables, with
 * port, [basic_auth] and [token_auth] beside them.
 */
#include <errno.h>
#include <glob.h>
#include <libgen.h>
#include <limits.h>

#include "stnsd.h"

/* How many include levels deep to follow before calling it a loop. */
#define MAX_INCLUDE_DEPTH 8

static char *
dup_str(const char *s)
{
	char *p;
	size_t len;

	if (s == NULL)
		return NULL;
	len = strlen(s) + 1;
	if ((p = malloc(len)) == NULL)
		return NULL;
	memcpy(p, s, len);
	return p;
}

/*
 * Read one string key.  An absent key leaves *dst NULL, which every caller
 * treats as "not given"; a key of the wrong type is an error rather than a
 * silent default, because this file is read once at start up by a program
 * whose whole job is to serve what is in it.
 */
static int
conf_str(toml_table_t *tab, const char *key, char **dst, char *errbuf, size_t errlen, const char *where)
{
	toml_datum_t d;

	*dst = NULL;
	if (tab == NULL)
		return STNSD_OK;
	d = toml_string_in(tab, key);
	if (d.ok) {
		*dst = d.u.s;
		return STNSD_OK;
	}
	if (toml_key_exists(tab, key)) {
		snprintf(errbuf, errlen, "%s%s is not a string", where, key);
		return STNSD_NG;
	}
	return STNSD_OK;
}

static int
conf_int(toml_table_t *tab, const char *key, int *dst, int def, char *errbuf, size_t errlen, const char *where)
{
	toml_datum_t d;

	*dst = def;
	if (tab == NULL)
		return STNSD_OK;
	d = toml_int_in(tab, key);
	if (d.ok) {
		if (d.u.i < INT_MIN || d.u.i > INT_MAX) {
			snprintf(errbuf, errlen, "%s%s is out of range", where, key);
			return STNSD_NG;
		}
		*dst = (int)d.u.i;
		return STNSD_OK;
	}
	if (toml_key_exists(tab, key)) {
		snprintf(errbuf, errlen, "%s%s is not an integer", where, key);
		return STNSD_NG;
	}
	return STNSD_OK;
}

static int
conf_bool(toml_table_t *tab, const char *key, int *dst, char *errbuf, size_t errlen, const char *where)
{
	toml_datum_t d;

	if (tab == NULL)
		return STNSD_OK;
	d = toml_bool_in(tab, key);
	if (d.ok) {
		*dst = d.u.b;
		return STNSD_OK;
	}
	if (toml_key_exists(tab, key)) {
		snprintf(errbuf, errlen, "%s%s is not true or false", where, key);
		return STNSD_NG;
	}
	return STNSD_OK;
}

/*
 * Read an array of strings.  present is set whenever the key is there at all,
 * empty or not: [] and absent are different answers on the wire.
 */
static int
conf_strings(toml_table_t *tab, const char *key, char ***vec, size_t *n, int *present, char *errbuf, size_t errlen,
    const char *where)
{
	toml_array_t *arr;
	int i;

	*vec = NULL;
	*n = 0;
	if (present != NULL)
		*present = 0;
	if (tab == NULL)
		return STNSD_OK;
	if ((arr = toml_array_in(tab, key)) == NULL) {
		if (toml_key_exists(tab, key)) {
			snprintf(errbuf, errlen, "%s%s is not an array", where, key);
			return STNSD_NG;
		}
		return STNSD_OK;
	}
	if (present != NULL)
		*present = 1;

	for (i = 0; i < toml_array_nelem(arr); i++) {
		toml_datum_t d = toml_string_at(arr, i);

		if (!d.ok) {
			snprintf(errbuf, errlen, "%s%s[%d] is not a string", where, key, i);
			return STNSD_NG;
		}
		if (stnsd_strings_add(vec, n, d.u.s) != STNSD_OK) {
			free(d.u.s);
			snprintf(errbuf, errlen, "out of memory");
			return STNSD_NG;
		}
		free(d.u.s);
	}
	return STNSD_OK;
}

static const char *const root_keys[] = {
	"port", "listen", "users", "groups", "basic_auth", "token_auth", "tls",
	"include", "allow_ips", "use_server_starter", "github", NULL
};

/*
 * Upstream's remaining keys, each with the reason it is not here.
 *
 * "unknown key 'redis'" would be a lie: it is not that we have never heard of
 * it, it is that this server does not do that.  Saying which is the difference
 * between an administrator fixing a typo and an administrator wondering
 * whether their configuration file is corrupt.
 */
static const struct {
	const char *key;
	const char *why;
} unsupported_keys[] = {
	{ "load_module", "load_module names a Go plugin, which stnsd cannot load; only the TOML backend is built in" },
	{ "module_path", "module_path goes with load_module, and stnsd has no plugin backends" },
	{ "modules", "[modules] configures the plugin backends, which stnsd does not have" },
	{ "redis", "[redis] selects the Redis backend; stnsd serves the TOML file only" },
	{ "ldap", "[ldap] configures upstream's LDAP interface, which stnsd does not serve" },
	{ NULL, NULL }
};
static const char *const user_keys[] = {
	"id", "name", "password", "group_id", "directory", "shell", "gecos", "keys", "link_users",
	"github", NULL
};
static const char *const group_keys[] = {
	"id", "name", "users", "link_groups", NULL
};

static int
reject_unknown(toml_table_t *tab, const char *const *known, char *errbuf, size_t errlen, const char *where)
{
	const char *key;
	int i, j;

	for (i = 0; (key = toml_key_in(tab, i)) != NULL; i++) {
		for (j = 0; known[j] != NULL; j++) {
			if (strcmp(known[j], key) == 0)
				break;
		}
		if (known[j] != NULL)
			continue;
		/* Only the root table has keys we know of and decline. */
		if (known == root_keys) {
			for (j = 0; unsupported_keys[j].key != NULL; j++) {
				if (strcmp(unsupported_keys[j].key, key) == 0) {
					snprintf(errbuf, errlen, "%s", unsupported_keys[j].why);
					return STNSD_NG;
				}
			}
		}
		snprintf(errbuf, errlen, "%sunknown key '%s'", where, key);
		return STNSD_NG;
	}
	return STNSD_OK;
}

/*
 * One [users.<name>] or [groups.<name>] table.
 *
 * The table's own name is the entry's name.  Upstream allows a "name" key as
 * well and then overwrites it with the table name; we accept it and do the
 * same, so that a configuration written for upstream loads here.
 */
static int
load_entry(toml_table_t *tab, const char *name, stnsd_entry_t *e, int is_user, char *errbuf, size_t errlen)
{
	char where[256];
	char *ignored;

	snprintf(where, sizeof(where), "[%s.%s] ", is_user ? "users" : "groups", name);

	memset(e, 0, sizeof(*e));
	if ((e->name = dup_str(name)) == NULL) {
		snprintf(errbuf, errlen, "out of memory");
		return STNSD_NG;
	}

	if (reject_unknown(tab, is_user ? user_keys : group_keys, errbuf, errlen, where) != STNSD_OK)
		return STNSD_NG;
	if (conf_int(tab, "id", &e->id, 0, errbuf, errlen, where) != STNSD_OK)
		return STNSD_NG;
	/*
	 * Upstream validates id with "required,gte=0", and Go's required means
	 * "not the zero value", so an id of 0 is rejected there.  Reject it
	 * here too rather than serving an entry upstream would refuse to.
	 */
	if (e->id <= 0) {
		snprintf(errbuf, errlen, "%sid is required and must be greater than zero", where);
		return STNSD_NG;
	}
	if (conf_str(tab, "name", &ignored, errbuf, errlen, where) != STNSD_OK)
		return STNSD_NG;
	free(ignored);

	if (is_user) {
		if (conf_str(tab, "github", &e->github, errbuf, errlen, where) != STNSD_OK ||
		    conf_str(tab, "password", &e->password, errbuf, errlen, where) != STNSD_OK ||
		    conf_str(tab, "directory", &e->directory, errbuf, errlen, where) != STNSD_OK ||
		    conf_str(tab, "shell", &e->shell, errbuf, errlen, where) != STNSD_OK ||
		    conf_str(tab, "gecos", &e->gecos, errbuf, errlen, where) != STNSD_OK)
			return STNSD_NG;
		if (conf_int(tab, "group_id", &e->group_id, 0, errbuf, errlen, where) != STNSD_OK)
			return STNSD_NG;
		if (conf_strings(tab, "keys", &e->values, &e->nvalues, &e->values_present, errbuf, errlen,
		    where) != STNSD_OK)
			return STNSD_NG;
		if (conf_strings(tab, "link_users", &e->links, &e->nlinks, NULL, errbuf, errlen, where) != STNSD_OK)
			return STNSD_NG;
	} else {
		if (conf_strings(tab, "users", &e->values, &e->nvalues, &e->values_present, errbuf, errlen,
		    where) != STNSD_OK)
			return STNSD_NG;
		if (conf_strings(tab, "link_groups", &e->links, &e->nlinks, NULL, errbuf, errlen, where) != STNSD_OK)
			return STNSD_NG;
	}
	return STNSD_OK;
}

static void
free_entry(stnsd_entry_t *e)
{
	free(e->name);
	free(e->github);
	stnsd_strings_free(e->own_values, e->nown);
	free(e->password);
	free(e->directory);
	free(e->shell);
	free(e->gecos);
	stnsd_strings_free(e->values, e->nvalues);
	stnsd_strings_free(e->links, e->nlinks);
	memset(e, 0, sizeof(*e));
}

/*
 * Every [users.*] or [groups.*] table, in the order the file lists them.
 *
 * The order matters more than it looks: a listing is served in this order, and
 * a file read twice must answer twice the same.  Upstream cannot promise that,
 * because it holds the entries in a Go map and iterates it, so its listings
 * come back shuffled.  Ours do not, which is the one place we are deliberately
 * better rather than merely equal.
 */
static int
load_entries(toml_table_t *root, const char *table, int is_user, stnsd_entries_t *out, char *errbuf, size_t errlen)
{
	stnsd_entry_t *grown;
	toml_table_t *parent;
	const char *name;
	size_t i;
	int n;

	if ((parent = toml_table_in(root, table)) == NULL)
		return STNSD_OK;

	for (n = 0; toml_key_in(parent, n) != NULL; n++)
		continue;
	if (n == 0)
		return STNSD_OK;

	/*
	 * Appended rather than assigned: with include, one table is built from
	 * several files, and each of them arrives here in turn.
	 */
	if ((grown = realloc(out->v, (out->n + (size_t)n) * sizeof(*out->v))) == NULL) {
		snprintf(errbuf, errlen, "out of memory");
		return STNSD_NG;
	}
	out->v = grown;
	memset(out->v + out->n, 0, (size_t)n * sizeof(*out->v));

	for (i = 0; (name = toml_key_in(parent, (int)i)) != NULL; i++) {
		toml_table_t *tab = toml_table_in(parent, name);

		if (tab == NULL) {
			snprintf(errbuf, errlen, "[%s.%s] is not a table", table, name);
			return STNSD_NG;
		}
		if (load_entry(tab, name, &out->v[out->n], is_user, errbuf, errlen) != STNSD_OK) {
			out->n++;
			return STNSD_NG;
		}
		out->n++;
	}
	return STNSD_OK;
}

/*
 * Once every file has been read: refuse the contradictions, resolve the links
 * and work out the id range.
 *
 * This waits for the last file because include means an entry in one file can
 * link to an entry in another, and because a duplicate is a duplicate whichever
 * file each half came from.  Upstream refuses a duplicate id and is right to:
 * two accounts sharing a uid is not a configuration anyone meant to write, and
 * which of them a lookup by id returns would be luck.  A duplicate name it
 * would silently keep the last of, having read them into a map; here that is
 * an error too, because one account definition quietly replacing another is
 * worse than being told.
 */
static int
finalise_entries(stnsd_entries_t *out, const char *table, char *errbuf, size_t errlen)
{
	size_t i, j;

	for (i = 0; i < out->n; i++) {
		for (j = i + 1; j < out->n; j++) {
			if (out->v[i].id == out->v[j].id) {
				snprintf(errbuf, errlen, "duplicate id %d in [%s.%s] and [%s.%s]", out->v[i].id,
				    table, out->v[i].name, table, out->v[j].name);
				return STNSD_NG;
			}
			if (strcmp(out->v[i].name, out->v[j].name) == 0) {
				snprintf(errbuf, errlen, "[%s.%s] is defined twice", table, out->v[i].name);
				return STNSD_NG;
			}
		}
	}
	stnsd_link_merge(out);
	stnsd_compute_id_range(out);
	return STNSD_OK;
}

static void
free_entries(stnsd_entries_t *e)
{
	size_t i;

	for (i = 0; i < e->n; i++)
		free_entry(&e->v[i]);
	free(e->v);
	memset(e, 0, sizeof(*e));
}

static const char *const basic_keys[] = { "user", "password", NULL };
static const char *const token_keys[] = { "tokens", NULL };
static const char *const tls_keys[] = { "cert", "key", "ca", NULL };
static const char *const github_keys[] = { "url", "fetcher", "cache", "refresh", NULL };

/*
 * Read the whole file.  On failure errbuf says what was wrong and nothing is
 * left allocated, so the caller must not call stnsd_config_free().
 *
 * Everything is checked here, at start up, rather than when a request arrives:
 * this is the moment an administrator is watching, and "stnsd -t" exists so
 * that the moment can be arranged before a reload.
 */
static int load_file(const char *path, stnsd_conf_t *c, char *errbuf, size_t errlen, int depth);

/*
 * include: read another file, or every file a pattern matches, into the same
 * configuration.
 *
 * A relative path is taken from the directory of the file that named it, which
 * is what makes a conf.d next to stns.conf work.  A pattern that matches
 * nothing is fine -- an empty conf.d is a normal state of affairs -- but a
 * plain path that is not there is a mistake worth stopping for, since somebody
 * meant to include something.
 */
static int
load_include(const char *including, const char *pattern, stnsd_conf_t *c, char *errbuf, size_t errlen, int depth)
{
	char resolved[PATH_MAX];
	char dirbuf[PATH_MAX];
	glob_t g;
	size_t i;
	int rc = STNSD_OK;

	if (depth >= MAX_INCLUDE_DEPTH) {
		snprintf(errbuf, errlen, "include is more than %d deep at %s; a loop?", MAX_INCLUDE_DEPTH, pattern);
		return STNSD_NG;
	}

	if (pattern[0] == '/') {
		(void)strlcpy(resolved, pattern, sizeof(resolved));
	} else {
		(void)strlcpy(dirbuf, including, sizeof(dirbuf));
		(void)snprintf(resolved, sizeof(resolved), "%s/%s", dirname(dirbuf), pattern);
	}

	memset(&g, 0, sizeof(g));
	switch (glob(resolved, 0, NULL, &g)) {
	case 0:
		break;
	case GLOB_NOMATCH:
		globfree(&g);
		if (strpbrk(pattern, "*?[") != NULL)
			return STNSD_OK;
		snprintf(errbuf, errlen, "include %s matches nothing", resolved);
		return STNSD_NG;
	default:
		globfree(&g);
		snprintf(errbuf, errlen, "include %s could not be expanded", resolved);
		return STNSD_NG;
	}

	for (i = 0; i < g.gl_pathc; i++) {
		if ((rc = load_file(g.gl_pathv[i], c, errbuf, errlen, depth + 1)) != STNSD_OK)
			break;
	}
	globfree(&g);
	return rc;
}

static int
load_file(const char *path, stnsd_conf_t *c, char *errbuf, size_t errlen, int depth)
{
	char parse_error[200];
	char *include = NULL;
	toml_table_t *root, *tab;
	FILE *fp;
	int rc = STNSD_NG;

	if ((fp = fopen(path, "r")) == NULL) {
		snprintf(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
		goto out;
	}
	root = toml_parse_file(fp, parse_error, sizeof(parse_error));
	(void)fclose(fp);
	if (root == NULL) {
		snprintf(errbuf, errlen, "%s: %s", path, parse_error);
		goto out;
	}

	if (reject_unknown(root, root_keys, errbuf, errlen, "") != STNSD_OK)
		goto out_toml;
	if (conf_int(root, "port", &c->port, c->port != 0 ? c->port : STNSD_DEFAULT_PORT, errbuf, errlen,
	    "") != STNSD_OK)
		goto out_toml;
	if (c->port <= 0 || c->port > 65535) {
		snprintf(errbuf, errlen, "port %d is out of range", c->port);
		goto out_toml;
	}
	if (conf_str(root, "listen", &c->listen, errbuf, errlen, "") != STNSD_OK)
		goto out_toml;

	if ((tab = toml_table_in(root, "basic_auth")) != NULL) {
		if (reject_unknown(tab, basic_keys, errbuf, errlen, "[basic_auth] ") != STNSD_OK)
			goto out_toml;
		if (conf_str(tab, "user", &c->basic_user, errbuf, errlen, "[basic_auth] ") != STNSD_OK ||
		    conf_str(tab, "password", &c->basic_password, errbuf, errlen, "[basic_auth] ") != STNSD_OK)
			goto out_toml;
		if (c->basic_user == NULL || c->basic_password == NULL) {
			snprintf(errbuf, errlen, "[basic_auth] needs both user and password");
			goto out_toml;
		}
	}
	if ((tab = toml_table_in(root, "token_auth")) != NULL) {
		size_t dummy = 0;

		if (reject_unknown(tab, token_keys, errbuf, errlen, "[token_auth] ") != STNSD_OK)
			goto out_toml;
		if (conf_strings(tab, "tokens", &c->tokens, &c->ntokens, NULL, errbuf, errlen,
		    "[token_auth] ") != STNSD_OK)
			goto out_toml;
		(void)dummy;
		if (c->ntokens == 0) {
			snprintf(errbuf, errlen, "[token_auth] tokens is empty, which would deny every request");
			goto out_toml;
		}
	}

	/*
	 * [tls] carries upstream's keys and upstream's meaning: cert and key
	 * serve TLS, and a ca additionally demands a client certificate signed
	 * by it.  Whether this build can honour that is tls.c's business.
	 */
	if ((tab = toml_table_in(root, "tls")) != NULL) {
		if (reject_unknown(tab, tls_keys, errbuf, errlen, "[tls] ") != STNSD_OK)
			goto out_toml;
		if (conf_str(tab, "cert", &c->tls_cert, errbuf, errlen, "[tls] ") != STNSD_OK ||
		    conf_str(tab, "key", &c->tls_key, errbuf, errlen, "[tls] ") != STNSD_OK ||
		    conf_str(tab, "ca", &c->tls_ca, errbuf, errlen, "[tls] ") != STNSD_OK)
			goto out_toml;
		/*
		 * Half a TLS configuration is refused here rather than at the
		 * first handshake.  A ca on its own is the dangerous one: it
		 * reads like "require client certificates" and would in fact
		 * do nothing at all, since without a cert and key there is no
		 * TLS to require them during.
		 */
		if ((c->tls_cert == NULL) != (c->tls_key == NULL)) {
			snprintf(errbuf, errlen, "[tls] needs both cert and key");
			goto out_toml;
		}
		if (c->tls_ca != NULL && c->tls_cert == NULL) {
			snprintf(errbuf, errlen, "[tls] ca does nothing without cert and key");
			goto out_toml;
		}
	}

	/*
	 * allow_ips is parsed here rather than at the first connection: a
	 * netmask nobody can parse should stop the server, not quietly refuse
	 * every client once it is running.
	 */
	{
		char **text = NULL;
		size_t ntext = 0, i;

		if (conf_strings(root, "allow_ips", &text, &ntext, NULL, errbuf, errlen, "") != STNSD_OK)
			goto out_toml;
		for (i = 0; i < ntext; i++) {
			stnsd_cidr_t *grown = realloc(c->allow, (c->nallow + 1) * sizeof(*grown));

			if (grown == NULL) {
				stnsd_strings_free(text, ntext);
				snprintf(errbuf, errlen, "out of memory");
				goto out_toml;
			}
			c->allow = grown;
			if (stnsd_cidr_parse(text[i], &c->allow[c->nallow]) != STNSD_OK) {
				snprintf(errbuf, errlen, "allow_ips: %s is not an address or a network", text[i]);
				stnsd_strings_free(text, ntext);
				goto out_toml;
			}
			c->nallow++;
		}
		stnsd_strings_free(text, ntext);
	}

	if (conf_bool(root, "use_server_starter", &c->use_server_starter, errbuf, errlen, "") != STNSD_OK)
		goto out_toml;

	/*
	 * [github].  The fetcher is the system's own client -- ftp(1) here,
	 * fetch(1) on the others -- because it already knows which certificate
	 * authorities this machine trusts, and both verify by default.
	 */
	if ((tab = toml_table_in(root, "github")) != NULL) {
		if (reject_unknown(tab, github_keys, errbuf, errlen, "[github] ") != STNSD_OK)
			goto out_toml;
		free(c->github_url);
		free(c->github_fetcher);
		free(c->github_cache);
		c->github_url = c->github_fetcher = c->github_cache = NULL;
		if (conf_str(tab, "url", &c->github_url, errbuf, errlen, "[github] ") != STNSD_OK ||
		    conf_str(tab, "fetcher", &c->github_fetcher, errbuf, errlen, "[github] ") != STNSD_OK ||
		    conf_str(tab, "cache", &c->github_cache, errbuf, errlen, "[github] ") != STNSD_OK)
			goto out_toml;
		if (conf_int(tab, "refresh", &c->github_refresh, STNSD_GITHUB_REFRESH, errbuf, errlen,
		    "[github] ") != STNSD_OK)
			goto out_toml;
		if (c->github_refresh < 0) {
			snprintf(errbuf, errlen, "[github] refresh cannot be negative");
			goto out_toml;
		}
		if (c->github_url != NULL && strstr(c->github_url, "%s") == NULL) {
			snprintf(errbuf, errlen, "[github] url needs a %%s, which is where the login goes");
			goto out_toml;
		}
	}

	if (load_entries(root, "users", 1, &c->users, errbuf, errlen) != STNSD_OK)
		goto out_toml;
	if (load_entries(root, "groups", 0, &c->groups, errbuf, errlen) != STNSD_OK)
		goto out_toml;

	if (conf_str(root, "include", &include, errbuf, errlen, "") != STNSD_OK)
		goto out_toml;

	rc = STNSD_OK;

out_toml:
	toml_free(root);
	/*
	 * The include is followed after this file is closed and its table
	 * freed, so a deep chain costs one parser at a time.
	 */
	if (rc == STNSD_OK && include != NULL)
		rc = load_include(path, include, c, errbuf, errlen, depth);
	free(include);
out:
	return rc;
}

/*
 * What [github] leaves unsaid.  The fetcher differs by platform because the
 * base systems differ: NetBSD has ftp(1) and nothing else that speaks HTTPS,
 * FreeBSD and DragonFly have fetch(1).  Both verify certificates unless told
 * not to, which is the reason to use them rather than to write another client.
 */
static int
set_github_defaults(stnsd_conf_t *c, char *errbuf, size_t errlen)
{
	static const struct { const char **field; const char *value; } defaults[] = {
		{ NULL, NULL }
	};

	(void)defaults;
	if (c->github_url == NULL && (c->github_url = dup_str("https://github.com/%s.keys")) == NULL)
		goto nomem;
	if (c->github_fetcher == NULL && (c->github_fetcher = dup_str(STNSD_GITHUB_FETCHER)) == NULL)
		goto nomem;
	if (c->github_cache == NULL && (c->github_cache = dup_str(STNSD_GITHUB_CACHE)) == NULL)
		goto nomem;
	/* Negative still means "no [github] table said anything about it". */
	if (c->github_refresh < 0)
		c->github_refresh = STNSD_GITHUB_REFRESH;
	return STNSD_OK;
nomem:
	snprintf(errbuf, errlen, "out of memory");
	return STNSD_NG;
}

/*
 * Read the configuration: the named file, whatever it includes, and then the
 * checks that can only be made once all of it is in.
 *
 * On failure nothing is left allocated and the caller must not call
 * stnsd_config_free().
 */
int
stnsd_config_load(const char *path, stnsd_conf_t *c, char *errbuf, size_t errlen)
{
	memset(c, 0, sizeof(*c));
	c->github_refresh = -1;		/* unset; set_github_defaults decides */
	if ((c->path = dup_str(path)) == NULL) {
		snprintf(errbuf, errlen, "out of memory");
		return STNSD_NG;
	}
	if (load_file(path, c, errbuf, errlen, 0) != STNSD_OK ||
	    set_github_defaults(c, errbuf, errlen) != STNSD_OK ||
	    finalise_entries(&c->users, "users", errbuf, errlen) != STNSD_OK ||
	    finalise_entries(&c->groups, "groups", errbuf, errlen) != STNSD_OK) {
		stnsd_config_free(c);
		return STNSD_NG;
	}
	return STNSD_OK;
}

void
stnsd_config_free(stnsd_conf_t *c)
{
	free(c->path);
	free(c->listen);
	free(c->basic_user);
	free(c->basic_password);
	free(c->github_url);
	free(c->github_fetcher);
	free(c->github_cache);
	free(c->tls_cert);
	free(c->tls_key);
	free(c->tls_ca);
	stnsd_strings_free(c->tokens, c->ntokens);
	free(c->allow);
	free_entries(&c->users);
	free_entries(&c->groups);
	memset(c, 0, sizeof(*c));
}
