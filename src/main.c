/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The daemon: parse the arguments, read the configuration, listen, and hand
 * each connection to a child.
 *
 * One fork per connection, capped.  A name service back end answers a handful
 * of small requests from an in-memory table, so the fork costs more than the
 * work does -- and buys the thing worth buying: a request that goes wrong
 * takes one child with it and nothing else, and the tables are read only after
 * the fork, shared by copy on write, so no lock is needed anywhere.
 */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

#define MAX_LISTEN 8

extern int stnsd_use_syslog;

static volatile sig_atomic_t want_reload;
static volatile sig_atomic_t want_stop;
static volatile sig_atomic_t child_died;
static int nchildren;
static char *pidfile_path;

static void
on_signal(int sig)
{
	switch (sig) {
	case SIGHUP:
		want_reload = 1;
		break;
	case SIGCHLD:
		child_died = 1;
		break;
	default:
		want_stop = 1;
		break;
	}
}

static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: stnsd [-fvV] [-c config] [-l [address:]port] [-p pidfile]\n"
	    "       stnsd -t [-c config]\n");
	exit(1);
}

/*
 * Split "address:port", "[v6:address]:port" or a bare "port".
 *
 * A bare port is accepted because that is what one usually means, and because
 * the configuration file's own "port" key is exactly that.
 */
static void
split_listen(const char *spec, char *host, size_t hostlen, char *port, size_t portlen)
{
	const char *colon;

	host[0] = '\0';
	if (spec[0] == '[') {
		const char *close = strchr(spec, ']');

		if (close != NULL && close[1] == ':') {
			size_t n = (size_t)(close - spec - 1);

			if (n >= hostlen)
				n = hostlen - 1;
			memcpy(host, spec + 1, n);
			host[n] = '\0';
			(void)strlcpy(port, close + 2, portlen);
			return;
		}
	}
	if ((colon = strrchr(spec, ':')) != NULL) {
		size_t n = (size_t)(colon - spec);

		if (n >= hostlen)
			n = hostlen - 1;
		memcpy(host, spec, n);
		host[n] = '\0';
		(void)strlcpy(port, colon + 1, portlen);
		return;
	}
	(void)strlcpy(port, spec, portlen);
}

/*
 * Bind every address the spec resolves to -- which on a dual stack machine is
 * one socket for IPv6 and one for IPv4, since NetBSD will not let a v6 socket
 * accept v4 connections and is right not to.
 */
static int
open_listeners(const char *spec, int *fds, int maxfds)
{
	struct addrinfo hints, *res, *ai;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int n = 0, error, on = 1;

	split_listen(spec, host, sizeof(host), port, sizeof(port));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((error = getaddrinfo(host[0] != '\0' ? host : NULL, port, &hints, &res)) != 0) {
		stnsd_log(LOG_ERR, "stnsd: %s: %s", spec, gai_strerror(error));
		return 0;
	}

	for (ai = res; ai != NULL && n < maxfds; ai = ai->ai_next) {
		int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (fd < 0)
			continue;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
		if (ai->ai_family == AF_INET6)
			(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0 || listen(fd, 64) < 0) {
			stnsd_log(LOG_ERR, "stnsd: cannot listen on %s: %s", spec, strerror(errno));
			(void)close(fd);
			continue;
		}
		fds[n++] = fd;
	}
	freeaddrinfo(res);
	return n;
}

/*
 * Sockets inherited from a supervisor, as Server::Starter passes them:
 * SERVER_STARTER_PORT holds "host:port=fd" or "/path=fd" entries, separated by
 * semicolons.  We are handed something already listening, so the point of the
 * exercise is to bind nothing and check that what arrived is what was claimed.
 */
static int
open_starter_listeners(int *fds, int maxfds, char *errbuf, size_t errlen)
{
	char spec[1024];
	const char *env;
	char *token, *next;
	int n = 0;

	if ((env = getenv("SERVER_STARTER_PORT")) == NULL || *env == '\0') {
		snprintf(errbuf, errlen,
		    "use_server_starter is set but SERVER_STARTER_PORT is not in the environment");
		return -1;
	}
	if (strlcpy(spec, env, sizeof(spec)) >= sizeof(spec)) {
		snprintf(errbuf, errlen, "SERVER_STARTER_PORT is longer than we can read");
		return -1;
	}

	for (token = spec; token != NULL && *token != '\0'; token = next) {
		struct sockaddr_storage ss;
		socklen_t sslen = sizeof(ss);
		char *eq;
		long fd;
		int accepting = 0;
		socklen_t len = sizeof(accepting);

		if ((next = strchr(token, ';')) != NULL)
			*next++ = '\0';
		if ((eq = strrchr(token, '=')) == NULL) {
			snprintf(errbuf, errlen, "SERVER_STARTER_PORT: '%s' has no file descriptor", token);
			return -1;
		}
		*eq++ = '\0';
		fd = strtol(eq, NULL, 10);
		if (fd < 0 || fd > 1024) {
			snprintf(errbuf, errlen, "SERVER_STARTER_PORT: '%s' is not a file descriptor", eq);
			return -1;
		}
		/*
		 * It has to be a socket, and where the system will say so, one
		 * that is listening.  Not every system answers SO_ACCEPTCONN --
		 * macOS returns ENOPROTOOPT -- and refusing to start because we
		 * could not ask would be the wrong way round: the supervisor
		 * handed this over, and getsockname has already agreed it is a
		 * socket.
		 */
		if (getsockname((int)fd, (struct sockaddr *)&ss, &sslen) < 0) {
			snprintf(errbuf, errlen, "SERVER_STARTER_PORT: fd %ld for %s is not a socket: %s", fd,
			    token, strerror(errno));
			return -1;
		}
		if (getsockopt((int)fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &len) == 0 && !accepting) {
			snprintf(errbuf, errlen, "SERVER_STARTER_PORT: fd %ld for %s is not listening", fd, token);
			return -1;
		}
		if (n >= maxfds) {
			snprintf(errbuf, errlen, "SERVER_STARTER_PORT hands over more sockets than we can use");
			return -1;
		}
		fds[n++] = (int)fd;
	}
	if (n == 0) {
		snprintf(errbuf, errlen, "SERVER_STARTER_PORT is empty");
		return -1;
	}
	return n;
}

static void
reap_children(void)
{
	while (waitpid(-1, NULL, WNOHANG) > 0) {
		if (nchildren > 0)
			nchildren--;
	}
}

static void
write_pidfile(const char *path)
{
	FILE *fp;

	if (path == NULL)
		return;
	if ((fp = fopen(path, "w")) == NULL) {
		stnsd_log(LOG_ERR, "stnsd: cannot write %s: %s", path, strerror(errno));
		return;
	}
	(void)fprintf(fp, "%ld\n", (long)getpid());
	(void)fclose(fp);
	pidfile_path = strdup(path);
}

int
main(int argc, char *argv[])
{
	char errbuf[512];
	char listen_spec[NI_MAXHOST + NI_MAXSERV + 4];
	struct pollfd pfd[MAX_LISTEN];
	stnsd_conf_t conf;
	const char *config = STNSD_CONFIG_FILE;
	const char *listen_arg = NULL;
	const char *pidfile = NULL;
	int fds[MAX_LISTEN];
	int nfds, i, ch;
	int foreground = 0, testonly = 0;

	while ((ch = getopt(argc, argv, "c:fhl:p:tvV")) != -1) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'l':
			listen_arg = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 't':
			testonly = 1;
			break;
		case 'v':
			stnsd_verbose = 1;
			break;
		case 'V':
			(void)printf("stnsd %s\n", STNSD_VERSION);
			return 0;
		case 'h':
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	if (stnsd_config_load(config, &conf, errbuf, sizeof(errbuf)) != STNSD_OK) {
		(void)fprintf(stderr, "stnsd: %s\n", errbuf);
		return 1;
	}
	/*
	 * The TLS context is built here, before anything is served, so that an
	 * unreadable certificate is a refusal to start rather than a run of
	 * failed handshakes.  -t therefore checks it too.
	 */
	if (stnsd_tls_setup(&conf, errbuf, sizeof(errbuf)) != STNSD_OK) {
		(void)fprintf(stderr, "stnsd: %s\n", errbuf);
		stnsd_config_free(&conf);
		return 1;
	}
	if (testonly) {
		(void)printf("%s: %zu users, %zu groups, port %d, %s", config, conf.users.n, conf.groups.n,
		    conf.port, conf.tls_ctx != NULL ? (conf.tls_ca != NULL ? "TLS with client certificates" : "TLS")
		    : "no TLS");
		if (conf.nallow > 0)
			(void)printf(", %zu allow_ips %s", conf.nallow, conf.nallow == 1 ? "entry" : "entries");
		if (conf.use_server_starter)
			(void)printf(", sockets from the supervisor");
		(void)printf("\n");
		stnsd_tls_teardown(&conf);
		stnsd_config_free(&conf);
		return 0;
	}

	if (listen_arg != NULL)
		(void)strlcpy(listen_spec, listen_arg, sizeof(listen_spec));
	else if (conf.listen != NULL)
		(void)strlcpy(listen_spec, conf.listen, sizeof(listen_spec));
	else
		(void)snprintf(listen_spec, sizeof(listen_spec), "%d", conf.port);

	if (conf.use_server_starter) {
		if ((nfds = open_starter_listeners(fds, MAX_LISTEN, errbuf, sizeof(errbuf))) < 0) {
			(void)fprintf(stderr, "stnsd: %s\n", errbuf);
			stnsd_tls_teardown(&conf);
			stnsd_config_free(&conf);
			return 1;
		}
		(void)strlcpy(listen_spec, "sockets from the supervisor", sizeof(listen_spec));
	} else if ((nfds = open_listeners(listen_spec, fds, MAX_LISTEN)) == 0) {
		(void)fprintf(stderr, "stnsd: nothing to listen on\n");
		stnsd_tls_teardown(&conf);
		stnsd_config_free(&conf);
		return 1;
	}

	if (!foreground) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog("stnsd", LOG_PID, LOG_DAEMON);
		stnsd_use_syslog = 1;
	}
	write_pidfile(pidfile);

	/*
	 * SIGPIPE is ignored rather than handled: a client that hangs up mid
	 * response is ordinary, and the write returning EPIPE says so already.
	 */
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGHUP, on_signal);
	(void)signal(SIGTERM, on_signal);
	(void)signal(SIGINT, on_signal);
	(void)signal(SIGCHLD, on_signal);

	stnsd_log(LOG_INFO, "stnsd %s listening on %s%s%s, %zu users, %zu groups", STNSD_VERSION, listen_spec,
	    conf.nallow > 0 ? " (allow_ips in force)" : "",
	    conf.tls_ctx != NULL ? (conf.tls_ca != NULL ? " (TLS, client certificate required)" : " (TLS)") : "",
	    conf.users.n, conf.groups.n);

	while (!want_stop) {
		int ready;

		if (child_died) {
			child_died = 0;
			reap_children();
		}
		if (want_reload) {
			stnsd_conf_t fresh;

			want_reload = 0;
			if (stnsd_config_load(conf.path, &fresh, errbuf, sizeof(errbuf)) != STNSD_OK ||
			    stnsd_tls_setup(&fresh, errbuf, sizeof(errbuf)) != STNSD_OK) {
				/*
				 * Keep serving the configuration we have.  A
				 * typo in an editor must not empty the
				 * directory of every machine that asks.
				 */
				stnsd_log(LOG_ERR, "stnsd: reload failed, keeping the running configuration: %s",
				    errbuf);
			} else {
				stnsd_tls_teardown(&conf);
				stnsd_config_free(&conf);
				conf = fresh;
				stnsd_log(LOG_INFO, "stnsd: reloaded %s, %zu users, %zu groups", conf.path,
				    conf.users.n, conf.groups.n);
			}
		}

		for (i = 0; i < nfds; i++) {
			pfd[i].fd = fds[i];
			pfd[i].events = POLLIN;
			pfd[i].revents = 0;
		}
		if ((ready = poll(pfd, (nfds_t)nfds, 1000)) < 0) {
			if (errno == EINTR)
				continue;
			stnsd_log(LOG_ERR, "stnsd: poll: %s", strerror(errno));
			break;
		}
		if (ready == 0)
			continue;

		for (i = 0; i < nfds; i++) {
			struct sockaddr_storage peer;
			socklen_t peerlen = sizeof(peer);
			struct timeval tv;
			stnsd_conn_t conn;
			int fd;
			pid_t pid;

			if ((pfd[i].revents & POLLIN) == 0)
				continue;
			if ((fd = accept(fds[i], (struct sockaddr *)&peer, &peerlen)) < 0) {
				if (errno != EINTR && errno != ECONNABORTED)
					stnsd_log(LOG_ERR, "stnsd: accept: %s", strerror(errno));
				continue;
			}
			/*
			 * allow_ips is applied here, to the address the
			 * connection actually came from, before a handshake is
			 * begun or a child is spawned for it.
			 */
			if (!stnsd_allowed(&conf, (struct sockaddr *)&peer)) {
				char who[64];

				if (stnsd_verbose)
					stnsd_log(LOG_INFO, "stnsd: refused %s: not in allow_ips",
					    stnsd_addr_text((struct sockaddr *)&peer, who, sizeof(who)));
				(void)close(fd);
				continue;
			}
			/*
			 * At the cap, answer nothing and close: a queue that
			 * grows without bound is how a slow client turns into
			 * an outage for everybody else.
			 */
			if (nchildren >= STNSD_MAX_CHILDREN) {
				reap_children();
				if (nchildren >= STNSD_MAX_CHILDREN) {
					stnsd_log(LOG_WARNING, "stnsd: %d children already, dropping a connection",
					    nchildren);
					(void)close(fd);
					continue;
				}
			}

			/*
			 * Bound the connection before the handshake, not after:
			 * a peer that opens a TLS session and then says nothing
			 * is as good a way to hold a slot as a silent HTTP one.
			 */
			tv.tv_sec = STNSD_IO_TIMEOUT;
			tv.tv_usec = 0;
			(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

			if ((pid = fork()) < 0) {
				stnsd_log(LOG_ERR, "stnsd: fork: %s", strerror(errno));
				(void)close(fd);
				continue;
			}
			if (pid == 0) {
				int j;

				for (j = 0; j < nfds; j++)
					(void)close(fds[j]);
				(void)signal(SIGHUP, SIG_DFL);
				(void)signal(SIGCHLD, SIG_DFL);
				conn.fd = fd;
				conn.ssl = NULL;
				/*
				 * The handshake happens in the child, so a
				 * client that fails it costs one child and
				 * nothing else.
				 */
				if (stnsd_tls_accept(&conf, &conn) == STNSD_OK)
					(void)stnsd_serve_connection(&conn, &conf);
				stnsd_conn_close(&conn);
				_exit(0);
			}
			nchildren++;
			(void)close(fd);
		}
	}

	stnsd_log(LOG_INFO, "stnsd: exiting");
	for (i = 0; i < nfds; i++)
		(void)close(fds[i]);
	if (pidfile_path != NULL) {
		(void)unlink(pidfile_path);
		free(pidfile_path);
	}
	stnsd_tls_teardown(&conf);
	stnsd_config_free(&conf);
	return 0;
}
