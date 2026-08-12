/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The HTTP side: read a request, decide what it asked for, answer it.
 *
 * Only what the API needs is implemented -- GET, a request line, headers, no
 * body -- and everything else is refused rather than guessed at.  This process
 * has the password hashes of every account in its address space, so the parser
 * is the part of the program most worth keeping boring.
 */
#include <sys/socket.h>
#include <sys/time.h>

#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

typedef struct {
	char *name;
	char *value;
} header_t;

typedef struct {
	char *method;
	char *path;
	char *query;
	int http_11;
	int keep_alive;
	header_t headers[STNSD_MAX_HEADERS];
	size_t nheaders;
} request_t;

static char *
header_get(const request_t *r, const char *name)
{
	size_t i;

	for (i = 0; i < r->nheaders; i++) {
		if (strcasecmp(r->headers[i].name, name) == 0)
			return r->headers[i].value;
	}
	return NULL;
}

static char *
trim(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	if (*s == '\0')
		return s;
	end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t'))
		*end-- = '\0';
	return s;
}

/*
 * Read until the blank line that ends the headers, or until the request grows
 * past what any real request needs.  Returns the number of bytes read, 0 if
 * the peer closed cleanly before saying anything, -1 on error or overrun.
 */
static ssize_t
read_request(stnsd_conn_t *conn, char *buf, size_t buflen)
{
	size_t len = 0;
	ssize_t n;

	while (len < buflen - 1) {
		n = stnsd_conn_read(conn, buf + len, buflen - 1 - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return len == 0 ? 0 : -1;
		len += (size_t)n;
		buf[len] = '\0';
		if (strstr(buf, "\r\n\r\n") != NULL || strstr(buf, "\n\n") != NULL)
			return (ssize_t)len;
	}
	return -1;
}

/*
 * Split the request into a method, a path, a query and headers, in place.
 *
 * Nothing is copied and nothing is allocated: the pointers all point into the
 * caller's buffer, which outlives the request.
 */
static int
parse_request(char *buf, request_t *r)
{
	char *line, *next, *sp, *colon;

	memset(r, 0, sizeof(*r));

	line = buf;
	if ((next = strstr(line, "\n")) == NULL)
		return STNSD_NG;
	*next++ = '\0';
	if (next[-2] == '\r')
		next[-2] = '\0';

	r->method = line;
	if ((sp = strchr(line, ' ')) == NULL)
		return STNSD_NG;
	*sp++ = '\0';
	r->path = sp;
	if ((sp = strchr(sp, ' ')) == NULL)
		return STNSD_NG;
	*sp++ = '\0';
	if (strncmp(sp, "HTTP/1.", 7) != 0)
		return STNSD_NG;
	r->http_11 = sp[7] == '1';
	/* HTTP/1.1 keeps the connection unless asked not to; 1.0 the reverse. */
	r->keep_alive = r->http_11;

	if ((sp = strchr(r->path, '?')) != NULL) {
		*sp++ = '\0';
		r->query = sp;
	}

	while (*next != '\0') {
		line = next;
		if ((next = strchr(line, '\n')) == NULL)
			break;
		*next++ = '\0';
		if (line[0] != '\0' && line[strlen(line) - 1] == '\r')
			line[strlen(line) - 1] = '\0';
		if (line[0] == '\0')
			break;		/* end of headers */
		if ((colon = strchr(line, ':')) == NULL)
			return STNSD_NG;
		*colon++ = '\0';
		if (r->nheaders < STNSD_MAX_HEADERS) {
			r->headers[r->nheaders].name = line;
			r->headers[r->nheaders].value = trim(colon);
			r->nheaders++;
		}
	}

	if ((line = header_get(r, "Connection")) != NULL) {
		if (strcasecmp(line, "close") == 0)
			r->keep_alive = 0;
		else if (strcasecmp(line, "keep-alive") == 0)
			r->keep_alive = 1;
	}
	return STNSD_OK;
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Percent-decode a query value in place, and drop CR and LF from the result.
 *
 * Dropping them rather than rejecting them is upstream's sanitizeQuery, kept
 * for the same reason it exists there: a newline in a value that later reaches
 * a log line is how one request becomes two in the log.
 */
static void
decode_value(char *s)
{
	char *out = s;
	int hi, lo;

	for (; *s != '\0'; s++) {
		int c = (unsigned char)*s;

		if (c == '+') {
			c = ' ';
		} else if (c == '%' && (hi = hexval((unsigned char)s[1])) >= 0 &&
		    (lo = hexval((unsigned char)s[2])) >= 0) {
			c = hi * 16 + lo;
			s += 2;
		}
		if (c == '\r' || c == '\n')
			continue;
		*out++ = (char)c;
	}
	*out = '\0';
}

/*
 * Split the query into the two parameters the API has, in one pass -- it is
 * taken apart in place, so there is no second chance to walk it.
 *
 * A parameter we do not know is an error rather than something to ignore,
 * which is upstream's answer too: ?nane=root silently returning every user
 * would be a worse surprise than a 400.
 */
static int
parse_query(char *query, char **name, char **id)
{
	char *p, *end, *eq;

	*name = NULL;
	*id = NULL;
	for (p = query; p != NULL && *p != '\0'; p = end) {
		if ((end = strchr(p, '&')) != NULL)
			*end++ = '\0';
		if ((eq = strchr(p, '=')) == NULL)
			return STNSD_NG;
		*eq++ = '\0';
		decode_value(eq);
		if (strcmp(p, "name") == 0)
			*name = eq;
		else if (strcmp(p, "id") == 0)
			*id = eq;
		else
			return STNSD_NG;
	}
	return STNSD_OK;
}

int
stnsd_base64_decode(const char *in, char *out, size_t outlen)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t o = 0;
	unsigned int acc = 0;
	int bits = 0;

	for (; *in != '\0'; in++) {
		const char *at;

		if (*in == '=' || *in == '\r' || *in == '\n')
			break;
		if ((at = strchr(alphabet, *in)) == NULL || *in == '\0')
			return STNSD_NG;
		acc = (acc << 6) | (unsigned int)(at - alphabet);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o + 1 >= outlen)
				return STNSD_NG;
			out[o++] = (char)((acc >> bits) & 0xff);
		}
	}
	out[o] = '\0';
	return STNSD_OK;
}

/*
 * Constant time comparison, so that a wrong token cannot be found one byte at
 * a time by timing the answer.  Both lengths leak, which is unavoidable and
 * uninteresting.
 */
static int
secure_equal(const char *a, const char *b)
{
	size_t i, la = strlen(a), lb = strlen(b);
	unsigned char diff = (unsigned char)(la ^ lb);

	for (i = 0; i < la && i < lb; i++)
		diff |= (unsigned char)(a[i] ^ b[i]);
	return diff == 0;
}

/*
 * Is this request allowed?
 *
 * /v1/status and / are exempt, because a health check that needs a credential
 * is a health check nobody runs.  Upstream exempts them too -- and also
 * exempts every request whenever the environment variable CI is set, which we
 * deliberately do not copy: a server that silently stops authenticating
 * because of an inherited variable is a trap, not a feature.
 */
static int
authorized(const request_t *r, const stnsd_conf_t *c, int exempt)
{
	char *auth;
	size_t i;

	if (exempt)
		return 1;
	if (c->basic_user == NULL && c->ntokens == 0)
		return 1;
	if ((auth = header_get(r, "Authorization")) == NULL)
		return 0;

	if (c->ntokens > 0 && strncasecmp(auth, "token", 5) == 0) {
		const char *token = trim(auth + 5);

		for (i = 0; i < c->ntokens; i++) {
			if (secure_equal(c->tokens[i], token))
				return 1;
		}
		return 0;
	}
	if (c->basic_user != NULL && strncasecmp(auth, "Basic ", 6) == 0) {
		char decoded[512];
		char *colon;

		if (stnsd_base64_decode(auth + 6, decoded, sizeof(decoded)) != STNSD_OK)
			return 0;
		if ((colon = strchr(decoded, ':')) == NULL)
			return 0;
		*colon++ = '\0';
		return secure_equal(c->basic_user, decoded) && secure_equal(c->basic_password, colon);
	}
	return 0;
}

/* One response, headers and all.  Returns STNSD_NG if the write failed. */
static int
respond(stnsd_conn_t *conn, const request_t *r, int status, const char *reason, const char *content_type,
    const char *body, size_t bodylen, const stnsd_entries_t *range, const char *range_what)
{
	stnsd_buf_t head;
	ssize_t n;
	size_t off;
	int rc = STNSD_OK;

	stnsd_buf_init(&head);
	stnsd_buf_printf(&head, "HTTP/1.%d %d %s\r\n", r->http_11 ? 1 : 0, status, reason);
	stnsd_buf_printf(&head, "Content-Type: %s\r\n", content_type);
	stnsd_buf_printf(&head, "Content-Length: %zu\r\n", bodylen);
	stnsd_buf_printf(&head, "Server: %s\r\n", STNSD_SERVER);
	/*
	 * The id range goes out even on a 404: a client uses it to decide
	 * which ids are worth asking about at all, and a miss is exactly when
	 * that is worth learning.
	 */
	if (range != NULL && range->highest_id != 0 && range->lowest_id != 0) {
		stnsd_buf_printf(&head, "%s-Highest-Id: %d\r\n", range_what, range->highest_id);
		stnsd_buf_printf(&head, "%s-Lowest-Id: %d\r\n", range_what, range->lowest_id);
	}
	if (!r->keep_alive)
		stnsd_buf_puts(&head, "Connection: close\r\n");
	stnsd_buf_puts(&head, "\r\n");

	if (head.error) {
		stnsd_buf_free(&head);
		return STNSD_NG;
	}

	for (off = 0; off < head.len; off += (size_t)n) {
		if ((n = stnsd_conn_write(conn, head.data + off, head.len - off)) <= 0) {
			if (n < 0 && errno == EINTR) {
				n = 0;
				continue;
			}
			rc = STNSD_NG;
			goto out;
		}
	}
	for (off = 0; off < bodylen; off += (size_t)n) {
		if ((n = stnsd_conn_write(conn, body + off, bodylen - off)) <= 0) {
			if (n < 0 && errno == EINTR) {
				n = 0;
				continue;
			}
			rc = STNSD_NG;
			goto out;
		}
	}
out:
	stnsd_buf_free(&head);
	return rc;
}

/*
 * The error bodies upstream sends.
 *
 * A lookup that found nothing is an empty object, because upstream marshals an
 * error struct whose fields are all unexported; the router's own refusals
 * carry a message, because those come from echo rather than from STNS.  Both
 * are copied so that a client cannot tell the two servers apart -- with one
 * exception, noted where it happens: upstream's 400 for a malformed id quotes
 * the id back, and we do not repeat input into an error body.
 */
#define JSON_EMPTY "{}\n"
#define JSON_NOT_FOUND "{\"message\":\"Not Found\"}\n"
#define JSON_NOT_ALLOWED "{\"message\":\"Method Not Allowed\"}\n"
#define JSON_UNAUTHORIZED "{\"message\":\"Unauthorized\"}\n"

static int
respond_json(stnsd_conn_t *conn, const request_t *r, int status, const char *reason, stnsd_buf_t *body,
    const stnsd_entries_t *range, const char *range_what)
{
	if (body->error)
		return respond(conn, r, 500, "Internal Server Error", "application/json", JSON_EMPTY,
		    strlen(JSON_EMPTY), range, range_what);
	return respond(conn, r, status, reason, "application/json", body->data ? body->data : "", body->len, range,
	    range_what);
}

/*
 * GET /v1/users and GET /v1/groups.
 *
 * With no query the whole table is returned; with ?name= or ?id= just the one
 * match, and a miss is a 404 rather than an empty array -- which is what makes
 * a client's negative cache possible.
 */
static int
serve_entries(stnsd_conn_t *conn, const request_t *r, const stnsd_conf_t *c, const stnsd_entries_t *e, int is_user)
{
	const char *range_what = is_user ? "User" : "Group";
	const stnsd_entry_t *one = NULL;
	stnsd_buf_t body;
	char *name, *id;
	size_t i;
	int rc;

	stnsd_buf_init(&body);

	if (r->query != NULL && *r->query != '\0') {
		if (parse_query(r->query, &name, &id) != STNSD_OK || (name == NULL && id == NULL)) {
			stnsd_buf_puts(&body, JSON_EMPTY);
			rc = respond_json(conn, r, 400, "Bad Request", &body, e, range_what);
			goto out;
		}
		if (name != NULL) {
			one = stnsd_find_by_name(e, name);
		} else {
			char *end;
			long n;

			errno = 0;
			n = strtol(id, &end, 10);
			if (*id == '\0' || *end != '\0' || errno != 0 || n < 0 || n > 0x7fffffff) {
				stnsd_buf_puts(&body, JSON_EMPTY);
				rc = respond_json(conn, r, 400, "Bad Request", &body, e, range_what);
				goto out;
			}
			one = stnsd_find_by_id(e, (int)n);
		}
		if (one == NULL) {
			stnsd_buf_puts(&body, JSON_EMPTY);
			rc = respond_json(conn, r, 404, "Not Found", &body, e, range_what);
			goto out;
		}
		stnsd_buf_add(&body, "[", 1);
		if (is_user)
			stnsd_json_user(&body, one);
		else
			stnsd_json_group(&body, one);
		stnsd_buf_puts(&body, "]\n");
		rc = respond_json(conn, r, 200, "OK", &body, e, range_what);
		goto out;
	}

	if (e->n == 0) {
		stnsd_buf_puts(&body, JSON_EMPTY);
		rc = respond_json(conn, r, 404, "Not Found", &body, e, range_what);
		goto out;
	}
	stnsd_buf_add(&body, "[", 1);
	for (i = 0; i < e->n; i++) {
		if (i > 0)
			stnsd_buf_add(&body, ",", 1);
		if (is_user)
			stnsd_json_user(&body, &e->v[i]);
		else
			stnsd_json_group(&body, &e->v[i]);
	}
	stnsd_buf_puts(&body, "]\n");
	rc = respond_json(conn, r, 200, "OK", &body, e, range_what);

out:
	(void)c;
	stnsd_buf_free(&body);
	return rc;
}

static int
handle(stnsd_conn_t *conn, const request_t *r, const stnsd_conf_t *c)
{
	int is_users = strcmp(r->path, "/v1/users") == 0;
	int is_groups = strcmp(r->path, "/v1/groups") == 0;
	int is_status = strcmp(r->path, "/v1/status") == 0 || strcmp(r->path, "/status") == 0;
	int is_root = strcmp(r->path, "/") == 0;
	const stnsd_entries_t *range = is_users ? &c->users : (is_groups ? &c->groups : NULL);
	const char *range_what = is_users ? "User" : "Group";

	if (!is_users && !is_groups && !is_status && !is_root)
		return respond(conn, r, 404, "Not Found", "application/json", JSON_NOT_FOUND, strlen(JSON_NOT_FOUND),
		    NULL, NULL);

	if (strcmp(r->method, "GET") != 0)
		return respond(conn, r, 405, "Method Not Allowed", "application/json", JSON_NOT_ALLOWED,
		    strlen(JSON_NOT_ALLOWED), range, range_what);

	if (!authorized(r, c, is_status || is_root)) {
		if (stnsd_verbose)
			stnsd_log(LOG_INFO, "401 %s", r->path);
		return respond(conn, r, 401, "Unauthorized", "application/json", JSON_UNAUTHORIZED,
		    strlen(JSON_UNAUTHORIZED), range, range_what);
	}

	if (stnsd_verbose)
		stnsd_log(LOG_INFO, "%s %s%s%s", r->method, r->path, r->query ? "?" : "", r->query ? r->query : "");

	if (is_status) {
		static const char body[] = "OK";

		return respond(conn, r, 200, "OK", "text/plain; charset=UTF-8", body, strlen(body), NULL, NULL);
	}
	if (is_root) {
		static const char body[] = "Hello! STNS!!1";

		return respond(conn, r, 200, "OK", "text/plain; charset=UTF-8", body, strlen(body), NULL, NULL);
	}
	return serve_entries(conn, r, c, is_users ? &c->users : &c->groups, is_users);
}

/*
 * Serve one connection to its end.
 *
 * The timeouts that keep a silent client from holding a slot are set on the
 * socket before the handshake, by the accept loop -- a peer that opens a TLS
 * connection and then says nothing has to be bounded too.
 */
int
stnsd_serve_connection(stnsd_conn_t *conn, const stnsd_conf_t *c)
{
	char buf[STNSD_MAX_REQUEST];
	request_t r;
	ssize_t n;

	for (;;) {
		if ((n = read_request(conn, buf, sizeof(buf))) <= 0)
			return n == 0 ? STNSD_OK : STNSD_NG;
		if (parse_request(buf, &r) != STNSD_OK) {
			static const char body[] = "{}\n";
			request_t bad;

			memset(&bad, 0, sizeof(bad));
			bad.http_11 = 1;
			(void)respond(conn, &bad, 400, "Bad Request", "application/json", body, strlen(body), NULL,
			    NULL);
			return STNSD_NG;
		}
		if (handle(conn, &r, c) != STNSD_OK)
			return STNSD_NG;
		if (!r.keep_alive)
			return STNSD_OK;
	}
}
