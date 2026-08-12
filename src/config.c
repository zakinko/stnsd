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
#include <limits.h>

#include "stnsd.h"

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

static const char *const user_keys[] = {
	"id", "name", "password", "group_id", "directory", "shell", "gecos", "keys", "link_users", NULL
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
		if (known[j] == NULL) {
			snprintf(errbuf, errlen, "%sunknown key '%s'", where, key);
			return STNSD_NG;
		}
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
		if (conf_str(tab, "password", &e->password, errbuf, errlen, where) != STNSD_OK ||
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
	toml_table_t *parent;
	const char *name;
	size_t i, j;
	int n;

	memset(out, 0, sizeof(*out));
	if ((parent = toml_table_in(root, table)) == NULL)
		return STNSD_OK;

	for (n = 0; toml_key_in(parent, n) != NULL; n++)
		continue;
	if (n == 0)
		return STNSD_OK;
	if ((out->v = calloc((size_t)n, sizeof(*out->v))) == NULL) {
		snprintf(errbuf, errlen, "out of memory");
		return STNSD_NG;
	}

	for (i = 0; (name = toml_key_in(parent, (int)i)) != NULL; i++) {
		toml_table_t *tab = toml_table_in(parent, name);

		if (tab == NULL) {
			snprintf(errbuf, errlen, "[%s.%s] is not a table", table, name);
			return STNSD_NG;
		}
		if (load_entry(tab, name, &out->v[i], is_user, errbuf, errlen) != STNSD_OK) {
			out->n = i + 1;
			return STNSD_NG;
		}
		out->n = i + 1;
	}

	/*
	 * Upstream refuses to start on a duplicate id, and it is right to: two
	 * accounts sharing a uid is not a configuration anyone meant to write,
	 * and which of them a lookup by id returns would be luck.
	 */
	for (i = 0; i < out->n; i++) {
		for (j = i + 1; j < out->n; j++) {
			if (out->v[i].id == out->v[j].id) {
				snprintf(errbuf, errlen, "duplicate id %d in [%s.%s] and [%s.%s]", out->v[i].id,
				    table, out->v[i].name, table, out->v[j].name);
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

static const char *const root_keys[] = {
	"port", "listen", "users", "groups", "basic_auth", "token_auth", NULL
};
static const char *const basic_keys[] = { "user", "password", NULL };
static const char *const token_keys[] = { "tokens", NULL };

/*
 * Read the whole file.  On failure errbuf says what was wrong and nothing is
 * left allocated, so the caller must not call stnsd_config_free().
 *
 * Everything is checked here, at start up, rather than when a request arrives:
 * this is the moment an administrator is watching, and "stnsd -t" exists so
 * that the moment can be arranged before a reload.
 */
int
stnsd_config_load(const char *path, stnsd_conf_t *c, char *errbuf, size_t errlen)
{
	char parse_error[200];
	toml_table_t *root, *tab;
	FILE *fp;
	int rc = STNSD_NG;

	memset(c, 0, sizeof(*c));
	if ((c->path = dup_str(path)) == NULL) {
		snprintf(errbuf, errlen, "out of memory");
		return STNSD_NG;
	}

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
	if (conf_int(root, "port", &c->port, STNSD_DEFAULT_PORT, errbuf, errlen, "") != STNSD_OK)
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

	if (load_entries(root, "users", 1, &c->users, errbuf, errlen) != STNSD_OK)
		goto out_toml;
	if (load_entries(root, "groups", 0, &c->groups, errbuf, errlen) != STNSD_OK)
		goto out_toml;

	rc = STNSD_OK;

out_toml:
	toml_free(root);
out:
	if (rc != STNSD_OK)
		stnsd_config_free(c);
	return rc;
}

void
stnsd_config_free(stnsd_conf_t *c)
{
	free(c->path);
	free(c->listen);
	free(c->basic_user);
	free(c->basic_password);
	stnsd_strings_free(c->tokens, c->ntokens);
	free_entries(&c->users);
	free_entries(&c->groups);
	memset(c, 0, sizeof(*c));
}
