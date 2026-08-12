/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Logging, to syslog once daemonised and to stderr before that.
 */
#include <syslog.h>
#include <unistd.h>

#include "stnsd.h"

int stnsd_verbose = 0;
int stnsd_use_syslog = 0;

void
stnsd_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (stnsd_use_syslog) {
		vsyslog(priority, fmt, ap);
	} else {
		(void)vfprintf(stderr, fmt, ap);
		(void)fputc('\n', stderr);
	}
	va_end(ap);
}
