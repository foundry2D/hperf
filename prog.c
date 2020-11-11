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
#include <string.h>
#include "message.h"
#include "mem.h"
#include "dso.h"
#include "prog.h"


// ************************************************************************
// 
// ************************************************************************
void prog_init(struct prog *p)
{
	MEM_INIT(p->dso, p->ndso);
	MEM_INIT(p->pmap, p->npmap);
	
	obstack_init(&p->strings);
	
	p->insn = 0;
	p->samples = 0;
	p->unspec = 0;
	p->orphans = 0;
	p->branch_samples = 0;
	p->branch_unspec = 0;
	p->branch_orphans = 0;
}

void prog_clear(struct prog *p)
{
	for (size_t d = 0; d < p->ndso; d++)
		dso_clear(&p->dso[d]);
	
	MEM_CLEAR(p->dso, p->ndso);
	MEM_CLEAR(p->pmap, p->npmap);
	
	obstack_clear(&p->strings);
}

// ************************************************************************
// 
// ************************************************************************
int prog_lookup(struct prog *p, char *dso_path)
{
	for (size_t i = 0; i < p->ndso; i++) {
		if (strncmp(p->dso[i].path, dso_path,
				sizeof(p->dso[i].path) - 1) == 0)
			return i;
	}
	
	return -1;
}

// ************************************************************************
// 
// ************************************************************************
int prog_load(struct prog *p, char *dso_path)
{
	int id = p->ndso;
	
	if (MEM_RESIZE(p->dso, p->ndso, id + 1))
		return -1;

	dso_init(&p->dso[id], dso_path);
	
	if (dso_load(&p->dso[id])) {
		ERROR("Warning: could not disassemble '%s'\n", dso_path);
	}
	
	p->insn += p->dso[id].ninsn;
	
	p->samples += p->dso[id].samples;
	p->unspec += p->dso[id].unspec;
	p->orphans += p->dso[id].orphans;
	return id;
}

// ************************************************************************
// 
// ************************************************************************
int prog_mmap(struct prog *p, uint64_t pid, uint64_t start, uint64_t length,
	char *dso_path, uint64_t offset)
{
	char *path = obstack_dup(&p->strings, dso_path);
	
	if (path == NULL)
		return -1;
	
	int t = p->npmap;
	
	if (MEM_RESIZE(p->pmap, p->npmap, t + 1))
		return -1;
	
	struct pmmap *m = &p->pmap[t];
	
	m->pid = pid;
	m->start = start;
	m->length = length;
	m->path = path;
	m->offset = offset;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
int prog_translate(struct prog *p, uint64_t pid, uint64_t ip,
	char **dso_r, uint64_t *foffs_r)
{
	struct pmmap *m = p->pmap;
	size_t n = p->npmap;
	
	for (size_t t = 0; t < n; t++) {
		if (pid != m[t].pid) {
			//DEBUG("\t\t\t%s: pid mismatch\n", m[t].path);
			continue;
		}
		
		if ((ip < m[t].start) || (ip >= m[t].start + m[t].length)) {
			//DEBUG("\t\t\t%s: range mismatch\n", m[t].path);
			continue;
		}
		
		if (dso_r)
			*dso_r = m[t].path;
		
		if (foffs_r)
			*foffs_r = ip - m[t].start + m[t].offset;
		
		return 0;
	}
	
	return -1;
}

// ************************************************************************
// 
// ************************************************************************
static int prog_require(struct prog *p, char *dso_path)
{
	int id = prog_lookup(p, dso_path);
	
	if (id < 0) {
		id = prog_load(p, dso_path);
		
		if (id < 0)
			return -1;
	}
	
	return id;
}

// ************************************************************************
// 
// ************************************************************************
int prog_sample(struct prog *p, uint64_t pid, uint64_t ip,
	char *dso_path, char *sym, uint64_t offs)
{
	// lookup dso
	int id = prog_require(p, dso_path);
	
	if (id < 0)
		return -1;
	
	// count hit
	p->samples++;

	if (p->dso[id].insn == 0) {
		dso_hit_dso(&p->dso[id]);
		
		p->unspec++;
		return 0;
	}
	
	// translate
	char *dso_check;
	uint64_t foffs;
	
	if (prog_translate(p, pid, ip, &dso_check, &foffs)) {
		DEBUG("\t=== no mmap for pid=%ld ip=0x%lx (%s: %s+0x%lx)\n",
			pid, ip, dso_path, (sym) ? sym : "[unknown]", offs);
		
		if (dso_hit_sym(&p->dso[id], sym, offs))
			p->orphans++;
		
		return 0;
	}
	
	if (strcmp(dso_path, dso_check) != 0) {
		DEBUG("\t==== sample at 0x%lx reports dso %s, "
			"but falls in %s range\n",
			ip, dso_path, dso_check);

		if (dso_hit_sym(&p->dso[id], sym, offs))
			p->orphans++;
		
		return 0;
	}
	
	// register sample
	if (dso_hit_foffs(&p->dso[id], foffs, sym, offs))
		p->orphans++;
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
int prog_branch(struct prog *p, uint64_t pid,
	uint64_t pre_ip, char *pre_dso,
	uint64_t src_ip, char *src_dso,
	uint64_t dst_ip, char *dst_dso,
	int miss, uint64_t cycles)
{
	// lookup dso
	int pre_id = prog_require(p, pre_dso);
	int src_id = prog_require(p, src_dso);
	int dst_id = prog_require(p, dst_dso);
	
	if ((pre_id < 0) || (src_id < 0) || (dst_id < 0))
		return -1;
	
	p->branch_samples++;
	
	// translate src
	char *src_dso_check;
	uint64_t src_foffs;
	
	if (p->dso[src_id].insn == 0) {
		src_foffs = (uint64_t)-1;
	} else if (prog_translate(p, pid, src_ip, &src_dso_check, &src_foffs)) {
		DEBUG("\t=== no mmap for pid=%ld ip=0x%lx (%s)\n",
			pid, src_ip, src_dso);
		
		src_foffs = (uint64_t)-1;
	} else if (strcmp(src_dso, src_dso_check) != 0) {
		DEBUG("\t==== branch from 0x%lx reports dso %s, "
			"but falls in %s range\n",
			src_ip, src_dso, src_dso_check);
	}
	
	// early exit if no src
	if (src_foffs == (uint64_t)-1) {
		p->branch_unspec++;
		return 0;
	}
	
	// translate dst
	char *dst_dso_check;
	uint64_t dst_foffs;
	
	if (p->dso[dst_id].insn == 0) {
		dst_foffs = (uint64_t)-1;
	} else if (prog_translate(p, pid, dst_ip, &dst_dso_check, &dst_foffs)) {
		DEBUG("\t=== no mmap for pid=%ld ip=0x%lx (%s)\n",
			pid, dst_ip, dst_dso);
		
		dst_foffs = (uint64_t)-1;
	} else if (strcmp(dst_dso, dst_dso_check) != 0) {
		DEBUG("\t==== branch  to  0x%lx reports dso %s, "
			"but falls in %s range\n",
			dst_ip, dst_dso, dst_dso_check);
	}
	
	// ignoring no-dst branches hides interrupts
	// (Is this desirable? If so, is it a good approach?)
	if (dst_foffs == (uint64_t)-1) {
		p->branch_unspec++;
		return 0;
	}

	// translate pre
	char *pre_dso_check;
	uint64_t pre_foffs;
	
	if (p->dso[pre_id].insn == 0) {
		pre_foffs = (uint64_t)-1;
	} else if (prog_translate(p, pid, pre_ip, &pre_dso_check, &pre_foffs)) {
		DEBUG("\t=== no mmap for pid=%ld ip=0x%lx (%s)\n",
			pid, pre_ip, pre_dso);
		
		pre_foffs = (uint64_t)-1;
	} else if (strcmp(pre_dso, pre_dso_check) != 0) {
		DEBUG("\t==== branch prev 0x%lx reports dso %s, "
			"but falls in %s range\n",
			pre_ip, pre_dso, pre_dso_check);
	}
	
	// register branch
	if (dso_branch(
			&p->dso[pre_id], pre_foffs,
			&p->dso[src_id], src_foffs,
			&p->dso[dst_id], dst_foffs,
			miss, cycles))
		p->branch_orphans++;
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
