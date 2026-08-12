/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * TLS, and the transport the rest of the program reads and writes through.
 *
 * The keys are upstream STNS's and so is their meaning: tls.cert and tls.key
 * turn TLS on, and adding tls.ca additionally requires the client to present a
 * certificate signed by it.  That last part is the one worth having here -- a
 * directory that hands out password hashes is better off knowing which
 * machines may ask than trusting a bearer token that travels with every
 * request.
 *
 * OpenSSL comes from the base system on all three platforms, so this costs no
 * package dependency.  Building with -DSTNSD_NO_TLS drops it entirely and
 * leaves a server that refuses to start if a configuration asks for TLS,
 * rather than one that quietly serves it in the clear.
 */
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

#ifndef STNSD_NO_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>

int
stnsd_tls_available(void)
{
	return 1;
}

/* The last thing OpenSSL complained about, as one line. */
static const char *
tls_error(void)
{
	static char buf[256];
	unsigned long e = ERR_get_error();

	if (e == 0)
		return "no further detail";
	ERR_error_string_n(e, buf, sizeof(buf));
	ERR_clear_error();
	return buf;
}

/*
 * Build the context, once, before any connection is accepted -- so that a
 * broken certificate is a refusal to start rather than a run of failed
 * handshakes nobody is watching.
 */
int
stnsd_tls_setup(stnsd_conf_t *c, char *errbuf, size_t errlen)
{
	SSL_CTX *ctx;

	c->tls_ctx = NULL;
	if (c->tls_cert == NULL && c->tls_key == NULL && c->tls_ca == NULL)
		return STNSD_OK;
	if (c->tls_cert == NULL || c->tls_key == NULL) {
		snprintf(errbuf, errlen, "[tls] needs both cert and key");
		return STNSD_NG;
	}

	if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
		snprintf(errbuf, errlen, "cannot create a TLS context: %s", tls_error());
		return STNSD_NG;
	}
	/*
	 * TLS 1.2 is the floor.  Everything that speaks to this is libcurl or
	 * a browser, and nothing that old needs to reach a directory.
	 */
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		snprintf(errbuf, errlen, "cannot require TLS 1.2: %s", tls_error());
		goto fail;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (SSL_CTX_use_certificate_chain_file(ctx, c->tls_cert) != 1) {
		snprintf(errbuf, errlen, "cannot read the certificate %s: %s", c->tls_cert, tls_error());
		goto fail;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, c->tls_key, SSL_FILETYPE_PEM) != 1) {
		snprintf(errbuf, errlen, "cannot read the private key %s: %s", c->tls_key, tls_error());
		goto fail;
	}
	if (SSL_CTX_check_private_key(ctx) != 1) {
		snprintf(errbuf, errlen, "%s is not the key for %s", c->tls_key, c->tls_cert);
		goto fail;
	}

	if (c->tls_ca != NULL) {
		STACK_OF(X509_NAME) *names;

		if (SSL_CTX_load_verify_locations(ctx, c->tls_ca, NULL) != 1) {
			snprintf(errbuf, errlen, "cannot read the CA %s: %s", c->tls_ca, tls_error());
			goto fail;
		}
		/*
		 * Naming the CAs we accept lets a client with several
		 * certificates pick the right one instead of guessing.
		 */
		if ((names = SSL_load_client_CA_file(c->tls_ca)) != NULL)
			SSL_CTX_set_client_CA_list(ctx, names);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	c->tls_ctx = ctx;
	return STNSD_OK;

fail:
	SSL_CTX_free(ctx);
	return STNSD_NG;
}

void
stnsd_tls_teardown(stnsd_conf_t *c)
{
	if (c->tls_ctx != NULL) {
		SSL_CTX_free((SSL_CTX *)c->tls_ctx);
		c->tls_ctx = NULL;
	}
}

/*
 * Complete the handshake, in the child that will serve the connection.  The
 * context is shared by copy on write; the session is the child's own.
 */
int
stnsd_tls_accept(const stnsd_conf_t *c, stnsd_conn_t *conn)
{
	SSL *ssl;

	if (c->tls_ctx == NULL)
		return STNSD_OK;	/* plain, by configuration */

	if ((ssl = SSL_new((SSL_CTX *)c->tls_ctx)) == NULL) {
		stnsd_log(LOG_ERR, "stnsd: SSL_new: %s", tls_error());
		return STNSD_NG;
	}
	if (SSL_set_fd(ssl, conn->fd) != 1) {
		stnsd_log(LOG_ERR, "stnsd: SSL_set_fd: %s", tls_error());
		SSL_free(ssl);
		return STNSD_NG;
	}
	if (SSL_accept(ssl) != 1) {
		/*
		 * A failed handshake is ordinary: a health check that speaks
		 * plain HTTP, a client whose certificate the CA did not sign,
		 * a port scan.  Say so only when asked to be verbose.
		 */
		if (stnsd_verbose)
			stnsd_log(LOG_INFO, "stnsd: handshake failed: %s", tls_error());
		SSL_free(ssl);
		return STNSD_NG;
	}
	conn->ssl = ssl;
	return STNSD_OK;
}

ssize_t
stnsd_conn_read(stnsd_conn_t *conn, void *buf, size_t len)
{
	int n;

	if (conn->ssl == NULL)
		return read(conn->fd, buf, len);

	n = SSL_read((SSL *)conn->ssl, buf, (int)(len > INT_MAX ? INT_MAX : len));
	if (n > 0)
		return n;
	switch (SSL_get_error((SSL *)conn->ssl, n)) {
	case SSL_ERROR_ZERO_RETURN:
		return 0;		/* the peer closed the session cleanly */
	case SSL_ERROR_SYSCALL:
		return -1;
	default:
		errno = EIO;
		return -1;
	}
}

ssize_t
stnsd_conn_write(stnsd_conn_t *conn, const void *buf, size_t len)
{
	int n;

	if (conn->ssl == NULL)
		return write(conn->fd, buf, len);

	n = SSL_write((SSL *)conn->ssl, buf, (int)(len > INT_MAX ? INT_MAX : len));
	if (n > 0)
		return n;
	errno = EIO;
	return -1;
}

void
stnsd_conn_close(stnsd_conn_t *conn)
{
	if (conn->ssl != NULL) {
		(void)SSL_shutdown((SSL *)conn->ssl);
		SSL_free((SSL *)conn->ssl);
		conn->ssl = NULL;
	}
	if (conn->fd >= 0) {
		(void)close(conn->fd);
		conn->fd = -1;
	}
}

#else /* STNSD_NO_TLS */

int
stnsd_tls_available(void)
{
	return 0;
}

/*
 * Built without TLS.  A configuration that asks for it is refused rather than
 * served in the clear: the administrator asked for a private channel, and
 * quietly not providing one is the worst of the available answers.
 */
int
stnsd_tls_setup(stnsd_conf_t *c, char *errbuf, size_t errlen)
{
	c->tls_ctx = NULL;
	if (c->tls_cert != NULL || c->tls_key != NULL || c->tls_ca != NULL) {
		snprintf(errbuf, errlen, "[tls] is configured but this stnsd was built without TLS");
		return STNSD_NG;
	}
	return STNSD_OK;
}

void
stnsd_tls_teardown(stnsd_conf_t *c)
{
	c->tls_ctx = NULL;
}

int
stnsd_tls_accept(const stnsd_conf_t *c, stnsd_conn_t *conn)
{
	return STNSD_OK;
}

ssize_t
stnsd_conn_read(stnsd_conn_t *conn, void *buf, size_t len)
{
	return read(conn->fd, buf, len);
}

ssize_t
stnsd_conn_write(stnsd_conn_t *conn, const void *buf, size_t len)
{
	return write(conn->fd, buf, len);
}

void
stnsd_conn_close(stnsd_conn_t *conn)
{
	if (conn->fd >= 0) {
		(void)close(conn->fd);
		conn->fd = -1;
	}
}

#endif /* STNSD_NO_TLS */
