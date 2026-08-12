/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Unit tests for the parts that do not need a socket: reading the
 * configuration, resolving links, and writing JSON.
 *
 * tests/compat.sh checks that we agree with upstream about the answers.  These
 * check the things upstream would never be asked -- a configuration with a
 * duplicate id, an id of zero, a key of the wrong type -- where the right
 * behaviour is to refuse to start rather than to serve something surprising.
 */
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "stnsd.h"

static int failures;
static int checks;

static void
ok(int cond, const char *what)
{
	checks++;
	if (cond) {
		(void)printf("ok   - %s\n", what);
	} else {
		failures++;
		(void)printf("FAIL - %s\n", what);
	}
}

static void
eq_str(const char *got, const char *want, const char *what)
{
	checks++;
	if (got != NULL && strcmp(got, want) == 0) {
		(void)printf("ok   - %s\n", what);
	} else {
		failures++;
		(void)printf("FAIL - %s\n       expected: %s\n       actual:   %s\n", what, want,
		    got == NULL ? "(null)" : got);
	}
}

/* contains_str <haystack> <needle> <what> */
static void
contains_str(const char *haystack, const char *needle, const char *what)
{
	checks++;
	if (haystack != NULL && strstr(haystack, needle) != NULL) {
		(void)printf("ok   - %s\n", what);
	} else {
		failures++;
		(void)printf("FAIL - %s\n       expected to contain: %s\n       actual: %s\n", what, needle,
		    haystack == NULL ? "(null)" : haystack);
	}
}

static const char *
write_conf(const char *body)
{
	static char path[] = "/tmp/stnsd_unit.XXXXXX";
	static char kept[sizeof(path)];
	FILE *fp;
	int fd;

	(void)strlcpy(path, "/tmp/stnsd_unit.XXXXXX", sizeof(path));
	if ((fd = mkstemp(path)) < 0)
		return NULL;
	if ((fp = fdopen(fd, "w")) == NULL)
		return NULL;
	(void)fputs(body, fp);
	(void)fclose(fp);
	(void)strlcpy(kept, path, sizeof(kept));
	return kept;
}

/* load <toml> - returns 1 and fills c on success, 0 on failure with why in err. */
static int
load(const char *body, stnsd_conf_t *c, char *err, size_t errlen)
{
	const char *path = write_conf(body);
	int rc;

	if (path == NULL) {
		(void)strlcpy(err, "cannot write a temporary file", errlen);
		return 0;
	}
	rc = stnsd_config_load(path, c, err, errlen);
	(void)unlink(path);
	return rc == STNSD_OK;
}

static void
test_config(void)
{
	char err[512];
	stnsd_conf_t c;

	(void)printf("\n== the configuration file ==\n");

	ok(load("[users.alice]\nid = 1001\n", &c, err, sizeof(err)), "a minimal file loads");
	if (c.users.n == 1) {
		eq_str(c.users.v[0].name, "alice", "the table name becomes the entry name");
		ok(c.users.v[0].id == 1001, "the id is read");
		ok(c.users.v[0].password == NULL, "an absent password stays absent");
		ok(c.users.v[0].values_present == 0, "absent keys are not an empty list");
		ok(c.port == STNSD_DEFAULT_PORT, "the port defaults to 1104");
	} else {
		ok(0, "one user was read");
	}
	stnsd_config_free(&c);

	ok(load("[users.alice]\nid = 1001\nkeys = []\n", &c, err, sizeof(err)) && c.users.v[0].values_present,
	    "an empty list is distinguishable from an absent one");
	stnsd_config_free(&c);

	/*
	 * Upstream validates the id as "required,gte=0", and Go's required
	 * rejects the zero value, so an id of 0 never starts there either.
	 */
	ok(!load("[users.alice]\nid = 0\n", &c, err, sizeof(err)), "an id of zero is refused");
	ok(!load("[users.alice]\nshell = \"/bin/sh\"\n", &c, err, sizeof(err)), "a missing id is refused");
	ok(!load("[users.a]\nid = 1\n[users.b]\nid = 1\n", &c, err, sizeof(err)), "a duplicate id is refused");
	ok(!load("[users.alice]\nid = \"1001\"\n", &c, err, sizeof(err)), "an id of the wrong type is refused");
	ok(!load("[users.alice]\nid = 1\nshel = \"/bin/sh\"\n", &c, err, sizeof(err)),
	    "a misspelled key is refused rather than ignored");
	ok(!load("port = 70000\n", &c, err, sizeof(err)), "a port out of range is refused");
	ok(!load("this is not toml = = =\n", &c, err, sizeof(err)), "a file that is not TOML is refused");
	ok(!load("[token_auth]\ntokens = []\n", &c, err, sizeof(err)),
	    "an empty token list is refused, since it would deny everything");
	ok(!load("[basic_auth]\nuser = \"stns\"\n", &c, err, sizeof(err)),
	    "basic auth without a password is refused");

	/* A group's own keys are a different set from a user's. */
	ok(!load("[groups.staff]\nid = 1\nshell = \"/bin/sh\"\n", &c, err, sizeof(err)),
	    "a user's key in a group table is refused");

	ok(load("port = 2000\n[users.alice]\nid = 1\n[groups.staff]\nid = 2\nusers = [\"alice\"]\n", &c, err,
	    sizeof(err)), "users and groups load together");
	ok(c.port == 2000, "the port is read");
	ok(c.users.highest_id == 1 && c.users.lowest_id == 1, "the id range of one user");
	stnsd_config_free(&c);

	ok(load("[tls]\ncert = \"/x.pem\"\nkey = \"/x-key.pem\"\n", &c, err, sizeof(err)),
	    "a [tls] table with a cert and a key loads");
	eq_str(c.tls_cert, "/x.pem", "the certificate path is read");
	ok(c.tls_ca == NULL, "and no ca means no client certificates are demanded");
	stnsd_config_free(&c);

	ok(!load("[tls]\ncert = \"/x.pem\"\n", &c, err, sizeof(err)),
	    "a certificate without a key is refused");
	ok(!load("[tls]\nkey = \"/x-key.pem\"\n", &c, err, sizeof(err)),
	    "and a key without a certificate");
	ok(!load("[tls]\nca = \"/ca.pem\"\n", &c, err, sizeof(err)),
	    "a ca on its own is refused, since it would silently require nothing");
	ok(!load("[tls]\ncert = \"/x.pem\"\nkey = \"/k\"\nverify = true\n", &c, err, sizeof(err)),
	    "an unknown key in [tls] is refused");

	ok(load("[users.a]\nid = 5\n[users.b]\nid = 9\n[users.c]\nid = 3\n", &c, err, sizeof(err)),
	    "three users load");
	ok(c.users.highest_id == 9, "the highest id is found");
	ok(c.users.lowest_id == 3, "the lowest id is found");
	stnsd_config_free(&c);
}

static void
test_links(void)
{
	char err[512];
	stnsd_conf_t c;
	const stnsd_entry_t *e;

	(void)printf("\n== link_users and link_groups ==\n");

	ok(load("[users.alice]\nid = 1\nkeys = [\"kA\"]\n"
	    "[users.bob]\nid = 2\nkeys = [\"kB\"]\nlink_users = [\"alice\"]\n", &c, err, sizeof(err)),
	    "a link loads");
	e = stnsd_find_by_name(&c.users, "bob");
	ok(e != NULL && e->nvalues == 2, "bob gains alice's key");
	ok(e != NULL && e->nvalues == 2 && strcmp(e->values[0], "kA") == 0 && strcmp(e->values[1], "kB") == 0,
	    "and the merged list is sorted, as upstream's uniqStrings leaves it");
	e = stnsd_find_by_name(&c.users, "alice");
	ok(e != NULL && e->nvalues == 1, "alice is unchanged");
	stnsd_config_free(&c);

	/* a -> b -> c, so a ends up with c's. */
	ok(load("[users.a]\nid = 1\nkeys = [\"kA\"]\nlink_users = [\"b\"]\n"
	    "[users.b]\nid = 2\nkeys = [\"kB\"]\nlink_users = [\"c\"]\n"
	    "[users.c]\nid = 3\nkeys = [\"kC\"]\n", &c, err, sizeof(err)), "a chain of links loads");
	e = stnsd_find_by_name(&c.users, "a");
	ok(e != NULL && e->nvalues == 3, "links are followed transitively");
	stnsd_config_free(&c);

	/* A cycle must terminate, and must not duplicate. */
	ok(load("[users.a]\nid = 1\nkeys = [\"kA\"]\nlink_users = [\"b\"]\n"
	    "[users.b]\nid = 2\nkeys = [\"kB\"]\nlink_users = [\"a\"]\n", &c, err, sizeof(err)),
	    "a cycle of links loads");
	e = stnsd_find_by_name(&c.users, "a");
	ok(e != NULL && e->nvalues == 2, "a cycle terminates without duplicating");
	stnsd_config_free(&c);

	ok(load("[users.a]\nid = 1\nlink_users = [\"nosuchuser\"]\n", &c, err, sizeof(err)),
	    "a link to nothing loads");
	e = stnsd_find_by_name(&c.users, "a");
	ok(e != NULL && e->nvalues == 0 && e->values_present == 0,
	    "and leaves the list absent rather than empty, as upstream does");
	stnsd_config_free(&c);

	ok(load("[groups.staff]\nid = 1\nusers = [\"alice\"]\n"
	    "[groups.ops]\nid = 2\nusers = [\"bob\"]\nlink_groups = [\"staff\"]\n", &c, err, sizeof(err)),
	    "linked groups load");
	e = stnsd_find_by_name(&c.groups, "ops");
	ok(e != NULL && e->nvalues == 2, "a group gains the linked group's members");
	stnsd_config_free(&c);

	ok(load("[users.a]\nid = 1\nkeys = [\"k\", \"k\"]\nlink_users = [\"b\"]\n"
	    "[users.b]\nid = 2\nkeys = [\"k\"]\n", &c, err, sizeof(err)), "duplicate keys load");
	e = stnsd_find_by_name(&c.users, "a");
	ok(e != NULL && e->nvalues == 1, "duplicates are collapsed by the merge");
	stnsd_config_free(&c);
}

static void
test_json(void)
{
	stnsd_buf_t b;
	stnsd_entry_t u;

	(void)printf("\n== the JSON writer ==\n");

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "plain");
	eq_str(b.data, "\"plain\"", "a plain string");
	stnsd_buf_free(&b);

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "a\"b\\c");
	eq_str(b.data, "\"a\\\"b\\\\c\"", "quotes and backslashes");
	stnsd_buf_free(&b);

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "line\nnext\ttab\r");
	eq_str(b.data, "\"line\\nnext\\ttab\\r\"", "the control characters Go names");
	stnsd_buf_free(&b);

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "\001");
	eq_str(b.data, "\"\\u0001\"", "and the ones it numbers");
	stnsd_buf_free(&b);

	/* Go's encoder escapes these three by default; a client sees \u003c. */
	stnsd_buf_init(&b);
	stnsd_json_string(&b, "<a> & <b>");
	eq_str(b.data, "\"\\u003ca\\u003e \\u0026 \\u003cb\\u003e\"", "the HTML escaping Go does by default");
	stnsd_buf_free(&b);

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "\xe2\x80\xa8");
	eq_str(b.data, "\"\\u2028\"", "U+2028, which Go escapes and JSON does not require");
	stnsd_buf_free(&b);

	stnsd_buf_init(&b);
	stnsd_json_string(&b, "\xe3\x81\x82");
	eq_str(b.data, "\"\xe3\x81\x82\"", "other UTF-8 is passed through");
	stnsd_buf_free(&b);

	memset(&u, 0, sizeof(u));
	u.id = 1001;
	u.name = (char *)(void *)"alice";
	u.group_id = 1001;
	stnsd_buf_init(&b);
	stnsd_json_user(&b, &u);
	eq_str(b.data,
	    "{\"id\":1001,\"name\":\"alice\",\"password\":\"\",\"group_id\":1001,"
	    "\"directory\":\"\",\"shell\":\"\",\"gecos\":\"\",\"keys\":null}",
	    "a user with nothing set: empty strings and a null key list");
	stnsd_buf_free(&b);

	memset(&u, 0, sizeof(u));
	u.id = 7;
	u.name = (char *)(void *)"staff";
	u.values_present = 1;
	stnsd_buf_init(&b);
	stnsd_json_group(&b, &u);
	eq_str(b.data, "{\"id\":7,\"name\":\"staff\",\"users\":[]}", "an empty member list is [] and not null");
	stnsd_buf_free(&b);
}

static void
test_base64(void)
{
	char out[64];

	(void)printf("\n== base64, for basic auth ==\n");

	ok(stnsd_base64_decode("c3RuczpodW50ZXIy", out, sizeof(out)) == STNSD_OK && strcmp(out, "stns:hunter2") == 0,
	    "a credential decodes");
	ok(stnsd_base64_decode("YQ==", out, sizeof(out)) == STNSD_OK && strcmp(out, "a") == 0, "padding is handled");
	ok(stnsd_base64_decode("YWI=", out, sizeof(out)) == STNSD_OK && strcmp(out, "ab") == 0, "two bytes");
	ok(stnsd_base64_decode("!!!!", out, sizeof(out)) == STNSD_NG, "an invalid character is refused");
	ok(stnsd_base64_decode("aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=", out, 4) == STNSD_NG,
	    "a result too long for the buffer is refused");
}

static void
test_strings(void)
{
	char **vec = NULL;
	size_t n = 0;

	(void)printf("\n== string vectors ==\n");

	(void)stnsd_strings_add(&vec, &n, "b");
	(void)stnsd_strings_add(&vec, &n, "a");
	(void)stnsd_strings_add(&vec, &n, "b");
	(void)stnsd_strings_add(&vec, &n, "c");
	stnsd_strings_uniq_sort(vec, &n);
	ok(n == 3, "duplicates are removed");
	ok(n == 3 && strcmp(vec[0], "a") == 0 && strcmp(vec[1], "b") == 0 && strcmp(vec[2], "c") == 0,
	    "and the rest is sorted");
	stnsd_strings_free(vec, n);
}

/* A sockaddr for a printed address, so the matcher can be asked about it. */
static struct sockaddr_storage
peer(const char *text)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (strchr(text, ':') != NULL) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)&ss;

		sin6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, text, &sin6->sin6_addr) != 1)
			(void)printf("FAIL - the test itself cannot parse %s\n", text);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)(void *)&ss;

		sin->sin_family = AF_INET;
		if (inet_pton(AF_INET, text, &sin->sin_addr) != 1)
			(void)printf("FAIL - the test itself cannot parse %s\n", text);
	}
	return ss;
}

/* matches <rule> <address> - 1 if the rule covers the address. */
static int
matches(const char *rule, const char *address)
{
	struct sockaddr_storage ss = peer(address);
	stnsd_cidr_t c;

	if (stnsd_cidr_parse(rule, &c) != STNSD_OK) {
		(void)printf("FAIL - %s did not parse\n", rule);
		return -1;
	}
	return stnsd_cidr_match(&c, (const struct sockaddr *)(const void *)&ss);
}

static void
test_allow_ips(void)
{
	stnsd_cidr_t c;

	(void)printf("\n== allow_ips: addresses and networks ==\n");

	ok(matches("10.0.0.0/8", "10.1.2.3") == 1, "a v4 network covers an address inside it");
	ok(matches("10.0.0.0/8", "11.0.0.1") == 0, "and not one outside it");
	ok(matches("192.168.1.5", "192.168.1.5") == 1, "a bare v4 address matches itself");
	ok(matches("192.168.1.5", "192.168.1.6") == 0, "and nothing else");
	ok(matches("0.0.0.0/0", "203.0.113.9") == 1, "/0 covers everything");
	/* A prefix that stops mid-byte is where an off-by-one would show. */
	ok(matches("192.168.0.0/23", "192.168.1.255") == 1, "a /23 covers the second half of its range");
	ok(matches("192.168.0.0/23", "192.168.2.1") == 0, "and stops where it should");
	ok(matches("10.0.0.0/31", "10.0.0.1") == 1, "a /31 covers both of its addresses");
	ok(matches("10.0.0.0/31", "10.0.0.2") == 0, "and no more");

	(void)printf("\n== allow_ips: the several ways to write IPv6 ==\n");

	ok(matches("::1", "::1") == 1, "the loopback matches itself");
	ok(matches("::1", "::2") == 0, "and not its neighbour");
	/* The same address, written four ways, against one rule. */
	ok(matches("2001:db8::1", "2001:db8::1") == 1, "compressed against compressed");
	ok(matches("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001") == 1,
	    "compressed against the fully written form");
	ok(matches("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1") == 1,
	    "upper case hex against lower");
	ok(matches("2001:db8:0:0:0:0:0:1", "2001:db8::1") == 1, "zeroes written out against zeroes elided");

	ok(matches("2001:db8::/32", "2001:db8:1234:5678::9") == 1, "a v6 network covers an address inside it");
	ok(matches("2001:db8::/32", "2001:db9::1") == 0, "and not one outside it");
	ok(matches("fe80::/10", "fe80::1") == 1, "link local covers a link local address");
	ok(matches("fe80::/10", "fec0::1") == 0, "and not one just past the prefix");
	ok(matches("::/0", "2001:db8::1") == 1, "::/0 covers every v6 address");
	ok(matches("2001:db8::1/128", "2001:db8::1") == 1, "a /128 is one address");
	ok(matches("2001:db8::1/128", "2001:db8::2") == 0, "and only that one");

	/*
	 * A v4 client arriving on a v6 socket is written ::ffff:10.0.0.1, and a
	 * rule about the v4 network has to recognise it.  IPV6_V6ONLY means we
	 * should not see one, which is exactly why it is worth a test.
	 */
	ok(matches("10.0.0.0/8", "::ffff:10.0.0.1") == 1, "a v4-mapped address is matched by the v4 rule");
	ok(matches("::ffff:10.0.0.1", "::ffff:10.0.0.1") == 1, "or by a v4-mapped rule");
	ok(matches("::ffff:10.0.0.1", "10.0.0.1") == 1, "which is the same rule as the v4 one");
	ok(matches("::ffff:10.0.0.0/104", "10.1.2.3") == 1, "a mapped network is the v4 network it describes");
	ok(matches("10.0.0.0/8", "::1") == 0, "a v4 rule does not cover a v6 address");
	ok(matches("::/0", "10.0.0.1") == 0, "and a v6 rule does not cover a v4 one");

	(void)printf("\n== allow_ips: what is not an address ==\n");

	ok(stnsd_cidr_parse("10.0.0.0/33", &c) != STNSD_OK, "a v4 prefix over 32 is refused");
	ok(stnsd_cidr_parse("2001:db8::/129", &c) != STNSD_OK, "a v6 prefix over 128 is refused");
	ok(stnsd_cidr_parse("10.0.0.0/-1", &c) != STNSD_OK, "a negative prefix is refused");
	ok(stnsd_cidr_parse("10.0.0.0/", &c) != STNSD_OK, "an empty prefix is refused");
	ok(stnsd_cidr_parse("10.0.0.256", &c) != STNSD_OK, "a byte over 255 is refused");
	ok(stnsd_cidr_parse("2001:db8:::1", &c) != STNSD_OK, "a doubled elision is refused");
	ok(stnsd_cidr_parse("not an address", &c) != STNSD_OK, "and so is prose");
	ok(stnsd_cidr_parse("10.0.0.0/8/8", &c) != STNSD_OK, "as is a second prefix");
}

/* write <dir> <name> <body> - a file inside a directory the test owns. */
static void
write_file(const char *dir, const char *name, const char *body)
{
	char path[512];
	FILE *fp;

	(void)snprintf(path, sizeof(path), "%s/%s", dir, name);
	if ((fp = fopen(path, "w")) == NULL) {
		(void)printf("FAIL - cannot write %s\n", path);
		return;
	}
	(void)fputs(body, fp);
	(void)fclose(fp);
}

static void
test_include(void)
{
	char dir[] = "/tmp/stnsd_include.XXXXXX";
	char main_conf[512], sub[512];
	char err[512];
	stnsd_conf_t c;

	(void)printf("\n== include ==\n");

	if (mkdtemp(dir) == NULL) {
		ok(0, "a temporary directory for the include tests");
		return;
	}
	(void)snprintf(sub, sizeof(sub), "%s/conf.d", dir);
	(void)mkdir(sub, 0755);
	(void)snprintf(main_conf, sizeof(main_conf), "%s/stns.conf", dir);

	/* A relative include is taken from the directory of the file naming it. */
	write_file(dir, "stns.conf", "port = 2000\ninclude = \"conf.d/*.conf\"\n[users.alice]\nid = 1\n");
	write_file(sub, "bob.conf", "[users.bob]\nid = 2\n");
	write_file(sub, "ops.conf", "[groups.ops]\nid = 10\nusers = [\"alice\", \"bob\"]\n");
	write_file(sub, "ignored.txt", "this is not TOML at all\n");

	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) == STNSD_OK, "a glob include loads");
	ok(c.users.n == 2, "users from both files are there");
	ok(stnsd_find_by_name(&c.users, "alice") != NULL && stnsd_find_by_name(&c.users, "bob") != NULL,
	    "and they are the right two");
	ok(c.groups.n == 1, "so is the group from the third file");
	ok(c.port == 2000, "a setting in the including file survives");
	/* The pattern is *.conf, so the .txt is not read -- and it is not TOML. */
	ok(c.users.highest_id == 2 && c.users.lowest_id == 1, "the id range spans every file");
	stnsd_config_free(&c);

	/* Links across files are why the merge waits for the last one. */
	write_file(dir, "stns.conf", "include = \"conf.d/*.conf\"\n[users.alice]\nid = 1\nkeys = [\"kA\"]\n");
	write_file(sub, "bob.conf", "[users.bob]\nid = 2\nlink_users = [\"alice\"]\n");
	write_file(sub, "ops.conf", "[groups.ops]\nid = 10\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) == STNSD_OK, "an entry may link across files");
	{
		const stnsd_entry_t *e = stnsd_find_by_name(&c.users, "bob");

		ok(e != NULL && e->nvalues == 1 && strcmp(e->values[0], "kA") == 0,
		    "and the merge finds it, because it waits for every file");
	}
	stnsd_config_free(&c);

	/* Two files defining the same account is a mistake, not a merge. */
	write_file(sub, "bob.conf", "[users.alice]\nid = 9\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) != STNSD_OK,
	    "the same name in two files is refused");
	write_file(sub, "bob.conf", "[users.bob]\nid = 1\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) != STNSD_OK,
	    "and so is the same id in two files");

	/* An empty conf.d is ordinary; a named file that is missing is not. */
	write_file(dir, "stns.conf", "include = \"conf.d/nothing-*.conf\"\n[users.alice]\nid = 1\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) == STNSD_OK,
	    "a pattern matching nothing is not an error");
	stnsd_config_free(&c);
	write_file(dir, "stns.conf", "include = \"conf.d/absent.conf\"\n[users.alice]\nid = 1\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) != STNSD_OK,
	    "but a named file that is not there is");

	/* A file that includes itself must stop rather than spin. */
	write_file(dir, "stns.conf", "include = \"stns.conf\"\n[users.alice]\nid = 1\n");
	ok(stnsd_config_load(main_conf, &c, err, sizeof(err)) != STNSD_OK, "a self include is caught");
	contains_str(err, "loop", "and the message says what it looks like");

	(void)unlink(main_conf);
	(void)snprintf(main_conf, sizeof(main_conf), "%s/conf.d/bob.conf", dir);
	(void)unlink(main_conf);
	(void)snprintf(main_conf, sizeof(main_conf), "%s/conf.d/ops.conf", dir);
	(void)unlink(main_conf);
	(void)snprintf(main_conf, sizeof(main_conf), "%s/conf.d/ignored.txt", dir);
	(void)unlink(main_conf);
	(void)rmdir(sub);
	(void)rmdir(dir);
}

static void
test_unsupported(void)
{
	char err[512];
	stnsd_conf_t c;

	(void)printf("\n== the keys upstream has and this does not ==\n");

	/*
	 * These have to be refused by name.  "unknown key" would be untrue and
	 * would send somebody hunting for a typo that is not there.
	 */
	ok(!load("load_module = \"mod_stns_etcd.so\"\n", &c, err, sizeof(err)), "load_module is refused");
	contains_str(err, "plugin", "and the message says it is a plugin");
	ok(!load("[redis]\nhost = \"localhost\"\n", &c, err, sizeof(err)), "[redis] is refused");
	contains_str(err, "Redis", "by name");
	ok(!load("[modules.etcd]\nendpoints = []\n", &c, err, sizeof(err)), "[modules] is refused");
	contains_str(err, "plugin", "as a plugin backend");
	ok(!load("[ldap]\nbase_dn = \"dc=example\"\n", &c, err, sizeof(err)), "[ldap] is refused");
	contains_str(err, "LDAP", "by name");
	ok(!load("module_path = \"/usr/local/stns\"\n", &c, err, sizeof(err)), "module_path is refused");

	/* And the keys we do now support must load. */
	ok(load("use_server_starter = true\n[users.a]\nid = 1\n", &c, err, sizeof(err)) && c.use_server_starter,
	    "use_server_starter loads");
	stnsd_config_free(&c);
	ok(!load("use_server_starter = \"yes\"\n", &c, err, sizeof(err)),
	    "and is a boolean, not a string that looks like one");

	ok(load("allow_ips = [\"10.0.0.0/8\", \"::1\"]\n[users.a]\nid = 1\n", &c, err, sizeof(err)) &&
	    c.nallow == 2, "allow_ips loads");
	stnsd_config_free(&c);
	ok(!load("allow_ips = [\"10.0.0.0/8\", \"garbage\"]\n", &c, err, sizeof(err)),
	    "and one bad entry stops the server rather than every client");
	contains_str(err, "garbage", "naming the entry it could not read");
}

int
main(void)
{
	test_config();
	test_links();
	test_json();
	test_base64();
	test_strings();
	test_allow_ips();
	test_include();
	test_unsupported();

	(void)printf("\n%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
