/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * allow_ips: which addresses may connect at all.
 *
 * Upstream applies this list per request, to the address echo calls RealIP --
 * which is the X-Forwarded-For header when there is one, so a client can
 * choose what it appears to be.  Behind a proxy that is what you want; in
 * front of one it is a filter that asks the caller whether to let them in.
 *
 * Here it is applied to the peer address of the connection instead, before the
 * TLS handshake and before the fork.  A stranger is refused without being
 * given a session to hold open, and no header can talk its way past.  The cost
 * is that a health check does not get the exemption upstream gives /v1/status:
 * whoever monitors the server has to be in the list, which seems a fair thing
 * to have to say out loud.
 */
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#include "stnsd.h"

/* The prefix an IPv4 address wears when it arrives on an IPv6 socket. */
static const unsigned char v4mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

/*
 * A rule written as ::ffff:10.0.0.1 is the v4 address 10.0.0.1 wearing a v6
 * hat, and is stored as the v4 one so that it matches the same clients as
 * 10.0.0.1 does -- whichever way the rule and the arriving address were
 * written.  Only when the prefix stays inside the mapped range: a shorter one
 * is asking about v6 space and is left alone.
 */
static void
normalise_v4mapped(stnsd_cidr_t *c)
{
	if (c->family != AF_INET6 || c->prefix < 96)
		return;
	if (memcmp(c->addr, v4mapped, sizeof(v4mapped)) != 0)
		return;
	memmove(c->addr, c->addr + 12, 4);
	memset(c->addr + 4, 0, sizeof(c->addr) - 4);
	c->family = AF_INET;
	c->prefix -= 96;
}

/*
 * "10.0.0.0/24", "192.168.1.5", "2001:db8::/32", "::1".  A bare address is a
 * full-length prefix, so both forms go through the same match.
 */
int
stnsd_cidr_parse(const char *text, stnsd_cidr_t *out)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash, *end;
	long prefix;
	int maxbits;

	if (strlcpy(buf, text, sizeof(buf)) >= sizeof(buf))
		return STNSD_NG;

	memset(out, 0, sizeof(*out));
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';

	if (strchr(buf, ':') != NULL) {
		out->family = AF_INET6;
		maxbits = 128;
	} else {
		out->family = AF_INET;
		maxbits = 32;
	}
	if (inet_pton(out->family, buf, out->addr) != 1)
		return STNSD_NG;

	if (slash == NULL) {
		out->prefix = maxbits;
		normalise_v4mapped(out);
		return STNSD_OK;
	}
	if (*slash == '\0')
		return STNSD_NG;
	prefix = strtol(slash, &end, 10);
	if (*end != '\0' || prefix < 0 || prefix > maxbits)
		return STNSD_NG;
	out->prefix = (int)prefix;
	normalise_v4mapped(out);
	return STNSD_OK;
}

/*
 * Compare the leading bits.  A v4 address arriving as ::ffff:10.0.0.1 is
 * unwrapped first, so a rule written for the v4 network still recognises it --
 * we ask for IPV6_V6ONLY and so should never see one, but a rule that only
 * works when the kernel behaves as expected is not much of a rule.
 */
int
stnsd_cidr_match(const stnsd_cidr_t *c, const struct sockaddr *sa)
{
	const unsigned char *addr;
	unsigned char unwrapped[4];
	int family, bytes, bits;

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)sa;

		family = AF_INET;
		addr = (const unsigned char *)&sin->sin_addr;
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)(const void *)sa;
		const unsigned char *raw = (const unsigned char *)&sin6->sin6_addr;

		if (memcmp(raw, v4mapped, sizeof(v4mapped)) == 0) {
			memcpy(unwrapped, raw + 12, sizeof(unwrapped));
			family = AF_INET;
			addr = unwrapped;
		} else {
			family = AF_INET6;
			addr = raw;
		}
	} else {
		return 0;
	}

	if (c->family != family)
		return 0;

	bytes = c->prefix / 8;
	bits = c->prefix % 8;
	if (bytes > 0 && memcmp(c->addr, addr, (size_t)bytes) != 0)
		return 0;
	if (bits != 0) {
		unsigned char mask = (unsigned char)(0xff << (8 - bits));

		if ((c->addr[bytes] & mask) != (addr[bytes] & mask))
			return 0;
	}
	return 1;
}

/* An empty list allows everyone: the key is absent, not set to nothing. */
int
stnsd_allowed(const stnsd_conf_t *c, const struct sockaddr *sa)
{
	size_t i;

	if (c->nallow == 0)
		return 1;
	/*
	 * A unix socket has no address to filter on, and the file system has
	 * already said who may open it.  That is the server-starter case.
	 */
	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return 1;
	for (i = 0; i < c->nallow; i++) {
		if (stnsd_cidr_match(&c->allow[i], sa))
			return 1;
	}
	return 0;
}

const char *
stnsd_addr_text(const struct sockaddr *sa, char *buf, size_t buflen)
{
	const void *addr;

	switch (sa->sa_family) {
	case AF_INET:
		addr = &((const struct sockaddr_in *)(const void *)sa)->sin_addr;
		break;
	case AF_INET6:
		addr = &((const struct sockaddr_in6 *)(const void *)sa)->sin6_addr;
		break;
	default:
		(void)strlcpy(buf, "(unknown)", buflen);
		return buf;
	}
	if (inet_ntop(sa->sa_family, addr, buf, (socklen_t)buflen) == NULL)
		(void)strlcpy(buf, "(unprintable)", buflen);
	return buf;
}
