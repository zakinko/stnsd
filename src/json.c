/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Writing the JSON the API answers with.
 *
 * There is no parser here, only a writer, and it is written to agree with Go's
 * encoding/json byte for byte -- field order, the escaping of <, > and &, null
 * for an absent list against [] for an empty one.  That is not fussiness for
 * its own sake: tests/compat.sh puts the same configuration in front of this
 * server and upstream's and compares what comes out, and the comparison is
 * only worth making if a difference means a real difference.
 */
#include "stnsd.h"

void
stnsd_buf_init(stnsd_buf_t *b)
{
	memset(b, 0, sizeof(*b));
}

void
stnsd_buf_free(stnsd_buf_t *b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

/*
 * Append, growing by doubling.  An allocation failure is remembered in
 * b->error and every later append is dropped, so the callers can build a whole
 * response without checking each step and test the flag once at the end.
 */
void
stnsd_buf_add(stnsd_buf_t *b, const char *s, size_t len)
{
	size_t want;
	char *grown;

	if (b->error)
		return;
	want = b->len + len + 1;
	if (want > b->cap) {
		size_t cap = b->cap ? b->cap : 256;

		while (cap < want)
			cap *= 2;
		if ((grown = realloc(b->data, cap)) == NULL) {
			b->error = 1;
			return;
		}
		b->data = grown;
		b->cap = cap;
	}
	memcpy(b->data + b->len, s, len);
	b->len += len;
	b->data[b->len] = '\0';
}

void
stnsd_buf_puts(stnsd_buf_t *b, const char *s)
{
	stnsd_buf_add(b, s, strlen(s));
}

void
stnsd_buf_printf(stnsd_buf_t *b, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->error = 1;
		return;
	}
	if ((size_t)n >= sizeof(tmp)) {
		b->error = 1;	/* nothing we emit is anywhere near this long */
		return;
	}
	stnsd_buf_add(b, tmp, (size_t)n);
}

/*
 * A JSON string literal, escaped the way Go's encoder escapes.
 *
 * The HTML escaping of <, > and & is Go's default rather than JSON's
 * requirement, and U+2028 and U+2029 go the same way: encoding/json escapes
 * them because they end a line in JavaScript but not in JSON.  We copy all of
 * it, because "same bytes" is a much easier property to test than "same
 * meaning".
 */
void
stnsd_json_string(stnsd_buf_t *b, const char *s)
{
	const unsigned char *p;

	stnsd_buf_add(b, "\"", 1);
	if (s == NULL) {
		stnsd_buf_add(b, "\"", 1);
		return;
	}
	for (p = (const unsigned char *)s; *p != '\0'; p++) {
		switch (*p) {
		case '"':
			stnsd_buf_puts(b, "\\\"");
			continue;
		case '\\':
			stnsd_buf_puts(b, "\\\\");
			continue;
		case '\n':
			stnsd_buf_puts(b, "\\n");
			continue;
		case '\r':
			stnsd_buf_puts(b, "\\r");
			continue;
		case '\t':
			stnsd_buf_puts(b, "\\t");
			continue;
		case '<':
			stnsd_buf_puts(b, "\\u003c");
			continue;
		case '>':
			stnsd_buf_puts(b, "\\u003e");
			continue;
		case '&':
			stnsd_buf_puts(b, "\\u0026");
			continue;
		default:
			break;
		}
		if (*p < 0x20) {
			stnsd_buf_printf(b, "\\u%04x", *p);
			continue;
		}
		/* U+2028 and U+2029, in UTF-8. */
		if (p[0] == 0xe2 && p[1] == 0x80 && (p[2] == 0xa8 || p[2] == 0xa9)) {
			stnsd_buf_printf(b, "\\u202%c", p[2] == 0xa8 ? '8' : '9');
			p += 2;
			continue;
		}
		stnsd_buf_add(b, (const char *)p, 1);
	}
	stnsd_buf_add(b, "\"", 1);
}

/*
 * An absent list is null and an empty one is [], because that is the
 * difference between a Go nil slice and an empty slice and it reaches the
 * wire.  A client has to cope with both whichever server it talks to.
 */
static void
json_strings(stnsd_buf_t *b, char **vec, size_t n, int present)
{
	size_t i;

	if (!present && n == 0) {
		stnsd_buf_puts(b, "null");
		return;
	}
	stnsd_buf_add(b, "[", 1);
	for (i = 0; i < n; i++) {
		if (i > 0)
			stnsd_buf_add(b, ",", 1);
		stnsd_json_string(b, vec[i]);
	}
	stnsd_buf_add(b, "]", 1);
}

/* The field order is Go's struct order, and json.Marshal keeps it. */
void
stnsd_json_user(stnsd_buf_t *b, const stnsd_entry_t *u)
{
	stnsd_buf_printf(b, "{\"id\":%d,\"name\":", u->id);
	stnsd_json_string(b, u->name);
	stnsd_buf_puts(b, ",\"password\":");
	stnsd_json_string(b, u->password);
	stnsd_buf_printf(b, ",\"group_id\":%d,\"directory\":", u->group_id);
	stnsd_json_string(b, u->directory);
	stnsd_buf_puts(b, ",\"shell\":");
	stnsd_json_string(b, u->shell);
	stnsd_buf_puts(b, ",\"gecos\":");
	stnsd_json_string(b, u->gecos);
	stnsd_buf_puts(b, ",\"keys\":");
	json_strings(b, u->values, u->nvalues, u->values_present);
	stnsd_buf_add(b, "}", 1);
}

void
stnsd_json_group(stnsd_buf_t *b, const stnsd_entry_t *g)
{
	stnsd_buf_printf(b, "{\"id\":%d,\"name\":", g->id);
	stnsd_json_string(b, g->name);
	stnsd_buf_puts(b, ",\"users\":");
	json_strings(b, g->values, g->nvalues, g->values_present);
	stnsd_buf_add(b, "}", 1);
}
