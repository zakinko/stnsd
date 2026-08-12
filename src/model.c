/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The user and group tables: string vectors, link resolution, lookups and the
 * id range the API advertises in its headers.
 */
#include "stnsd.h"

int
stnsd_strings_add(char ***vec, size_t *n, const char *s)
{
	char **grown;
	char *copy;
	size_t len;

	len = strlen(s) + 1;
	if ((copy = malloc(len)) == NULL)
		return STNSD_NG;
	memcpy(copy, s, len);

	if ((grown = realloc(*vec, (*n + 1) * sizeof(*grown))) == NULL) {
		free(copy);
		return STNSD_NG;
	}
	*vec = grown;
	(*vec)[*n] = copy;
	(*n)++;
	return STNSD_OK;
}

void
stnsd_strings_free(char **vec, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(vec[i]);
	free(vec);
}

static int
cmp_string(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/*
 * Deduplicate and sort in place, freeing what falls out.
 *
 * Upstream's uniqStrings does exactly this -- keep the first of each, then
 * sort -- and the sort is observable, because it decides the order of the keys
 * and members it returns.  A merged list therefore comes back sorted and an
 * untouched one comes back in the order the file wrote it, on both servers.
 */
void
stnsd_strings_uniq_sort(char **vec, size_t *n)
{
	size_t i, kept;

	if (*n == 0)
		return;
	qsort(vec, *n, sizeof(*vec), cmp_string);
	for (i = 1, kept = 1; i < *n; i++) {
		if (strcmp(vec[kept - 1], vec[i]) == 0) {
			free(vec[i]);
			continue;
		}
		vec[kept++] = vec[i];
	}
	*n = kept;
}

static ssize_t
index_of(const stnsd_entries_t *e, const char *name)
{
	size_t i;

	for (i = 0; i < e->n; i++) {
		if (strcmp(e->v[i].name, name) == 0)
			return (ssize_t)i;
	}
	return -1;
}

/*
 * Resolve link_users and link_groups.
 *
 * A user's link_users names other users whose SSH keys become theirs as well;
 * a group's link_groups names other groups whose members become its members.
 * Links are followed transitively -- if a links b and b links c, a ends up
 * with c's -- and a cycle terminates because each entry is visited once.
 *
 * The merge reads every source's values as the file gave them, not as another
 * merge has left them, so the answer does not depend on the order the entries
 * happen to be visited in.  Upstream holds these in a Go map and iterates it,
 * so its own order is whatever the runtime feels like that second; taking the
 * closure of the originals lands on the same set either way.
 */
void
stnsd_link_merge(stnsd_entries_t *e)
{
	char **merged;
	size_t nmerged;
	char *visited;
	size_t i, j, k;

	if (e->n == 0)
		return;
	if ((visited = calloc(e->n, 1)) == NULL)
		return;

	for (i = 0; i < e->n; i++) {
		stnsd_entry_t *v = &e->v[i];
		int found = 0;

		if (v->nlinks == 0)
			continue;

		merged = NULL;
		nmerged = 0;
		memset(visited, 0, e->n);

		/*
		 * Breadth first over the names in link_*, pushing what each
		 * one names onto the same list.  The list is the queue: k
		 * walks it while the loop below appends to it.
		 */
		{
			ssize_t *queue;
			size_t nqueue = 0;

			if ((queue = calloc(e->n, sizeof(*queue))) == NULL)
				break;
			for (j = 0; j < v->nlinks; j++) {
				ssize_t at = index_of(e, v->links[j]);

				if (at < 0 || visited[at])
					continue;
				visited[at] = 1;
				queue[nqueue++] = at;
			}
			for (k = 0; k < nqueue; k++) {
				const stnsd_entry_t *src = &e->v[queue[k]];

				found = 1;
				for (j = 0; j < src->nvalues; j++) {
					if (stnsd_strings_add(&merged, &nmerged, src->values[j]) != STNSD_OK)
						break;
				}
				for (j = 0; j < src->nlinks; j++) {
					ssize_t at = index_of(e, src->links[j]);

					if (at < 0 || visited[at])
						continue;
					visited[at] = 1;
					queue[nqueue++] = at;
				}
			}
			free(queue);
		}

		/*
		 * A link naming something that does not exist contributes
		 * nothing, and an entry that gained nothing is left exactly as
		 * the file wrote it -- unsorted, and null rather than [] if it
		 * had no list at all.  Upstream skips the merge in that case
		 * too, and the difference shows on the wire.
		 */
		if (!found) {
			stnsd_strings_free(merged, nmerged);
			continue;
		}

		for (j = 0; j < v->nvalues; j++)
			(void)stnsd_strings_add(&merged, &nmerged, v->values[j]);
		stnsd_strings_uniq_sort(merged, &nmerged);

		stnsd_strings_free(v->values, v->nvalues);
		v->values = merged;
		v->nvalues = nmerged;
		v->values_present = 1;
	}
	free(visited);
}

/*
 * The highest and lowest id in the table.
 *
 * These reach the client as User-Highest-Id and friends, and a client uses
 * them to skip asking about a uid the server could not possibly own -- which
 * is why they are computed once here rather than per request.  Zero means "no
 * entries", and the headers are then left off, matching upstream.
 */
void
stnsd_compute_id_range(stnsd_entries_t *e)
{
	size_t i;

	e->highest_id = 0;
	e->lowest_id = 0;
	for (i = 0; i < e->n; i++) {
		if (i == 0 || e->v[i].id > e->highest_id)
			e->highest_id = e->v[i].id;
		if (i == 0 || e->v[i].id < e->lowest_id)
			e->lowest_id = e->v[i].id;
	}
}

const stnsd_entry_t *
stnsd_find_by_name(const stnsd_entries_t *e, const char *name)
{
	size_t i;

	for (i = 0; i < e->n; i++) {
		if (strcmp(e->v[i].name, name) == 0)
			return &e->v[i];
	}
	return NULL;
}

const stnsd_entry_t *
stnsd_find_by_id(const stnsd_entries_t *e, int id)
{
	size_t i;

	for (i = 0; i < e->n; i++) {
		if (e->v[i].id == id)
			return &e->v[i];
	}
	return NULL;
}
