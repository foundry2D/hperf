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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "message.h"
#include "prog.h"
#include "meta.h"

// ************************************************************************
// 
// ************************************************************************
void meta_init(struct meta *m)
{
	MEM_INIT(m->hot, m->nhot);
	
	m->sym = NULL;
	m->func = NULL;
	
	m->sample_threshold_hits = 1;
	m->hotspot_threshold_hits = 2;
	m->hotspot_context_insn = 5;
	m->dump_context_insn = 50;
}

void meta_clear(struct meta *m)
{
	MEM_CLEAR(m->hot, m->nhot);
	free(m->sym);
	free(m->func);
}

// ************************************************************************
// 
// ************************************************************************
static int meta_hotspot(struct meta *m, struct prog *p, uint64_t t,
	uint64_t i0, uint64_t i1, uint64_t hits, uint64_t center)
{
	(void)p;
	
	if (hits < m->hotspot_threshold_hits)
		return 0;
	
	size_t hid = m->nhot;
	
	if (MEM_RESIZE(m->hot, m->nhot, hid + 1))
		return -1;
	
	m->hot[hid].dso = t;
	m->hot[hid].i0 = i0;
	m->hot[hid].i1 = i1;
	m->hot[hid].ic = i0 + (center / hits);
	m->hot[hid].hits = hits;
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
static int meta_file(struct meta *m, struct prog *p, uint64_t t,
	uint64_t file_id)
{
	(void)m;
	
	if (file_id == (uint64_t)-1)
		return 0;
	
	p->dso[t].file[file_id].flags |= SOURCE_FILE_DUMP;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static int meta_run_dso(struct meta *m, struct prog *p, uint64_t t)
{
	struct insn *insn = p->dso[t].insn;
	uint64_t ninsn = p->dso[t].ninsn;
	
	if (ninsn < 1)
		return 0;
	
	// gather hotspots
	size_t hid0 = m->nhot;
	
	int h_on = 0;
	uint64_t h_i0, h_i1, h_hits, h_center, h_sym;
	
	for (uint64_t i = 0; i < ninsn; i++) {
		if (insn[i].hits >= m->sample_threshold_hits) {
			if (!h_on) {
				h_sym = insn[i].sym_id;
				h_i0 = i;
				h_hits = 0;
				h_center = 0;
				h_on = 1;
			}
			
			h_hits += insn[i].hits;
			h_center += insn[i].hits * (i - h_i0);
			h_i1 = i;
		}
		
		if (!h_on)
			continue;
		
		if ((i > h_i1 + m->hotspot_context_insn)
		||  (insn[i].sym_id != h_sym)) {
			if (meta_hotspot(m, p, t, h_i0, h_i1, h_hits, h_center))
				return -1;
			h_on = 0;
		}
	}
	
	if (h_on) {
		if (meta_hotspot(m, p, t, h_i0, h_i1, h_hits, h_center))
			return -1;
		h_on = 0;
	}
	
	// compute dump areas & source files
	uint64_t htop = 0;
	
	for (size_t hid = hid0; hid < m->nhot; hid++) {
		uint64_t i0 = m->hot[hid].i0;
		uint64_t i1 = m->hot[hid].i1;
		
		for (uint64_t i = i0; i <= i1; i++)
			insn[i].flags |= INSN_HOTSPOT;
		insn[m->hot[hid].ic].flags |= INSN_CENTER;
		
		if (i0 < m->dump_context_insn)
			i0 = 0;
		else
			i0 -= m->dump_context_insn;
		
		if (i1 + m->dump_context_insn >= ninsn)
			i1 = ninsn - 1;
		else
			i1 += m->dump_context_insn;
		
		if (i0 < htop)
			i0 = htop;
		
		for (uint64_t i = i0; i <= i1; i++) {
			insn[i].flags |= INSN_DUMP;
			meta_file(m, p, t, insn[i].file_id);
		}
		
		if (htop < i1 + 1)
			htop = i1 + 1;
	}
	
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static int dso_cmp_topref(const void *va, const void *vb)
{
	uint64_t ha = ((struct topref *)va)->hits;
	uint64_t hb = ((struct topref *)vb)->hits;
	
	if (ha > hb)
		return -1;
	if (ha < hb)
		return 1;
	return 0;
}


static int dso_cmp_hot(const void *va, const void *vb)
{
	uint64_t ha = ((struct hotspot *)va)->hits;
	uint64_t hb = ((struct hotspot *)vb)->hits;
	
	if (ha > hb)
		return -1;
	if (ha < hb)
		return 1;
	return 0;
}

// ************************************************************************
static int meta_sort(struct meta *m, struct prog *p)
{
	size_t nsym = 0;
	size_t nfunc = 0;
	
	for (uint64_t t = 0; t < p->ndso; t++) {
		nsym += p->dso[t].nsym;
		nfunc += p->dso[t].nfunc;
	}
	
	struct topref *sym = m->sym =
		(struct topref *)malloc(nsym * sizeof(struct topref));
	struct topref *func = m->func =
		(struct topref *)malloc(nfunc * sizeof(struct topref));
	
	if ((sym == NULL) || (func == NULL))
		return -1;
	
	m->nsym = nsym;
	m->nfunc = nfunc;

	size_t s = 0;
	
	for (uint64_t t = 0; t < p->ndso; t++) {
		for (size_t i = 0; i < p->dso[t].nsym; i++) {
			sym[s].dso = t;
			sym[s].idx = i;
			sym[s].hits = p->dso[t].sym[i].hits;
			s++;
		}
	}
		
	size_t f = 0;

	for (uint64_t t = 0; t < p->ndso; t++) {
		for (size_t i = 0; i < p->dso[t].nfunc; i++) {
			func[f].dso = t;
			func[f].idx = i;
			func[f].hits = p->dso[t].func[i].hits;
			f++;
		}
	}
	
	qsort(sym, nsym, sizeof(struct topref), dso_cmp_topref);
	qsort(func, nfunc, sizeof(struct topref), dso_cmp_topref);
	qsort(m->hot, m->nhot, sizeof(struct hotspot), dso_cmp_hot);
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
int meta_run(struct meta *m, struct prog *p)
{
	for (uint64_t t = 0; t < p->ndso; t++) {
		if (meta_run_dso(m, p, t))
			return -1;
	}
	
	if (meta_sort(m, p))
		return -1;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
