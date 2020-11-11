/*
    This file is part of HPerf.
    Copyright (C) 2020  Laurent Poirrier

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef PROG_H
#define PROG_H
#include <stddef.h>
#include "dso.h"


struct pmmap {
	uint64_t pid;
	uint64_t start;
	uint64_t length;
	char *path;
	uint64_t offset;
};

struct prog {
	struct dso *dso;
	size_t ndso;
	
	struct pmmap *pmap;
	size_t npmap;
	
	struct obstack strings;

	size_t insn;
	
	uint64_t samples, unspec, orphans;
	uint64_t branch_samples, branch_unspec, branch_orphans;
};

void prog_init(struct prog *p);
void prog_clear(struct prog *p);


int prog_lookup(struct prog *p, char *dso_path);
int prog_load(struct prog *p, char *dso_path);

int prog_mmap(struct prog *p, uint64_t pid, uint64_t start, uint64_t length,
	char *dso_path, uint64_t offset);
int prog_translate(struct prog *p, uint64_t pid, uint64_t ip,
	char **dso_r, uint64_t *foffs_r);

int prog_sample(struct prog *p, uint64_t pid, uint64_t ip,
	char *dso_path, char *sym, uint64_t offs);

int prog_branch(struct prog *p, uint64_t pid,
	uint64_t pre_ip, char *pre_dso,
	uint64_t src_ip, char *src_dso,
	uint64_t dst_ip, char *dst_dso,
	int miss, uint64_t cycles);


#endif

