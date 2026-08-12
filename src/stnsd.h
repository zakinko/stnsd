/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * stnsd - a small STNS API server for NetBSD, FreeBSD and DragonFly BSD.
 *
 * It answers the same v1 API upstream STNS answers, from the same TOML
 * configuration, in C and with no dependency beyond libc.  The API itself is
 * STNS's, designed by pyama86 (https://github.com/STNS/STNS).
 */
#ifndef STNSD_H
#define STNSD_H

#include <sys/types.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "toml.h"

#define STNSD_VERSION "0.2.0"
#define STNSD_SERVER "stnsd/" STNSD_VERSION

#ifndef STNSD_CONFDIR
#ifdef __NetBSD__
#define STNSD_CONFDIR "/usr/pkg/etc"
#else
#define STNSD_CONFDIR "/usr/local/etc"
#endif
#endif

/*
 * The server's configuration sits under stns/server, beside the client's
 * stns/client, exactly as it does upstream -- so that a host can be both, and
 * so that a configuration can be moved between a Linux STNS server and this
 * one without being rewritten.
 */
#define STNSD_CONFIG_FILE STNSD_CONFDIR "/stns/server/stns.conf"
#define STNSD_DEFAULT_PORT 1104

/* Bounds, so that a hostile or broken client cannot make us allocate freely. */
#define STNSD_MAX_REQUEST (16 * 1024)	/* request line and headers together */
#define STNSD_MAX_HEADERS 64
#define STNSD_MAX_CHILDREN 64
#define STNSD_IO_TIMEOUT 30		/* seconds a client may hold a slot */

#define STNSD_OK 0
#define STNSD_NG (-1)

/*
 * One client connection: a socket, and the TLS session on it if there is one.
 *
 * Everything above the transport reads and writes through this, so the HTTP
 * side never learns whether it is talking over TLS -- which is the only reason
 * adding TLS did not touch the parser.
 */
typedef struct {
	int fd;
	void *ssl;		/* SSL *, or NULL on a plain connection */
} stnsd_conn_t;

/*
 * A growable byte buffer.  Every response body is built in one of these, and
 * the JSON writers below are the only things that append to it.
 */
typedef struct {
	char *data;
	size_t len;
	size_t cap;
	int error;	/* sticky: set once an allocation has failed */
} stnsd_buf_t;

/*
 * A user or a group.
 *
 * "values" is the list that link resolution merges into: the SSH keys of a
 * user, the member names of a group.  Upstream models both with the same
 * interface and the same merge, and so do we, because the merge is the fiddly
 * part and having it twice would mean having two of its bugs.
 *
 * values_present distinguishes an absent key from an empty one.  Upstream is a
 * Go program encoding a nil slice as null and an empty slice as [], and the
 * distinction reaches the wire, so it has to survive here too.
 */
typedef struct {
	char *name;
	int id;
	char **values;
	size_t nvalues;
	int values_present;
	char **links;		/* link_users, or link_groups */
	size_t nlinks;

	/* Users only.  A group leaves these NULL and group_id 0. */
	char *password;
	char *directory;
	char *shell;
	char *gecos;
	int group_id;
} stnsd_entry_t;

typedef struct {
	stnsd_entry_t *v;
	size_t n;
	int highest_id;
	int lowest_id;
} stnsd_entries_t;

typedef struct {
	char *path;		/* the file this was read from */

	int port;
	char *listen;		/* "addr:port" from the config or -l */

	char *basic_user;
	char *basic_password;
	char **tokens;
	size_t ntokens;

	/*
	 * TLS, with upstream's key names and upstream's meaning: cert and key
	 * turn it on, and a ca additionally requires the client to present a
	 * certificate signed by it.
	 */
	char *tls_cert;
	char *tls_key;
	char *tls_ca;
	void *tls_ctx;		/* SSL_CTX *, built once before any fork */

	stnsd_entries_t users;
	stnsd_entries_t groups;
} stnsd_conf_t;

/* config.c */
int stnsd_config_load(const char *path, stnsd_conf_t *c, char *errbuf, size_t errlen);
void stnsd_config_free(stnsd_conf_t *c);

/* model.c */
void stnsd_link_merge(stnsd_entries_t *e);
void stnsd_compute_id_range(stnsd_entries_t *e);
const stnsd_entry_t *stnsd_find_by_name(const stnsd_entries_t *e, const char *name);
const stnsd_entry_t *stnsd_find_by_id(const stnsd_entries_t *e, int id);
int stnsd_strings_add(char ***vec, size_t *n, const char *s);
void stnsd_strings_free(char **vec, size_t n);
void stnsd_strings_uniq_sort(char **vec, size_t *n);

/* json.c */
void stnsd_buf_init(stnsd_buf_t *b);
void stnsd_buf_free(stnsd_buf_t *b);
void stnsd_buf_add(stnsd_buf_t *b, const char *s, size_t len);
void stnsd_buf_puts(stnsd_buf_t *b, const char *s);
void stnsd_buf_printf(stnsd_buf_t *b, const char *fmt, ...);
void stnsd_json_string(stnsd_buf_t *b, const char *s);
void stnsd_json_user(stnsd_buf_t *b, const stnsd_entry_t *u);
void stnsd_json_group(stnsd_buf_t *b, const stnsd_entry_t *g);

/* tls.c */
int stnsd_tls_setup(stnsd_conf_t *c, char *errbuf, size_t errlen);
void stnsd_tls_teardown(stnsd_conf_t *c);
int stnsd_tls_accept(const stnsd_conf_t *c, stnsd_conn_t *conn);
void stnsd_conn_close(stnsd_conn_t *conn);
ssize_t stnsd_conn_read(stnsd_conn_t *conn, void *buf, size_t len);
ssize_t stnsd_conn_write(stnsd_conn_t *conn, const void *buf, size_t len);
int stnsd_tls_available(void);

/* http.c */
int stnsd_serve_connection(stnsd_conn_t *conn, const stnsd_conf_t *c);
int stnsd_base64_decode(const char *in, char *out, size_t outlen);

/* main.c */
void stnsd_log(int priority, const char *fmt, ...);
extern int stnsd_verbose;

#endif /* STNSD_H */
