/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * A stand-in for Server::Starter, so that use_server_starter can be tested
 * without one: bind a listening socket, name it in SERVER_STARTER_PORT the way
 * start_server does, and exec the server on top.
 *
 * usage: starter address:port command [args...]
 */
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	struct addrinfo hints, *res;
	char env[256];
	char *colon, *host, *port;
	int fd, on = 1, error;

	if (argc < 3) {
		(void)fprintf(stderr, "usage: starter address:port command [args...]\n");
		return 2;
	}
	host = argv[1];
	if ((colon = strrchr(host, ':')) == NULL) {
		(void)fprintf(stderr, "starter: %s is not address:port\n", host);
		return 2;
	}
	*colon = '\0';
	port = colon + 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((error = getaddrinfo(host, port, &hints, &res)) != 0) {
		(void)fprintf(stderr, "starter: %s\n", gai_strerror(error));
		return 1;
	}
	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		perror("starter: socket");
		return 1;
	}
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, 16) < 0) {
		perror("starter: bind");
		return 1;
	}
	freeaddrinfo(res);

	/* The server is handed the socket, not the address. */
	(void)snprintf(env, sizeof(env), "%s:%s=%d", host, port, fd);
	if (setenv("SERVER_STARTER_PORT", env, 1) < 0) {
		perror("starter: setenv");
		return 1;
	}
	(void)execvp(argv[2], &argv[2]);
	perror("starter: exec");
	return 1;
}
