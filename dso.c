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
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "message.h"
#include "mem.h"
#include "pipe.h"
#include "token.h"
#include "dso.h"


// ************************************************************************
// 
// ************************************************************************
int dso_init(struct dso *dso, char *path)
{
	strncpy(dso->path, path, sizeof(dso->path) - 1);
	dso->path[sizeof(dso->path) - 1] = 0;
	
	MEM_INIT(dso->insn, dso->ninsn);
	MEM_INIT(dso->sym, dso->nsym);
	MEM_INIT(dso->func, dso->nfunc);
	MEM_INIT(dso->file, dso->nfile);
	
	obstack_init(&dso->disasm);
	
	int r = 0;
	r |= map_init(&dso->sym_id);
	r |= map_init(&dso->func_id);
	r |= map_init(&dso->file_id);
	
	dso->samples = 0;
	dso->unspec = 0;
	dso->orphans = 0;
	
	if (r)
		dso_clear(dso);
	
	return r;
}

// ************************************************************************
void dso_clear(struct dso *dso)
{
	dso->path[0] = 0;
	
	MEM_CLEAR(dso->insn, dso->ninsn);
	MEM_CLEAR(dso->sym, dso->nsym);
	MEM_CLEAR(dso->func, dso->nfunc);
	MEM_CLEAR(dso->file, dso->nfile);
	
	obstack_clear(&dso->disasm);
	
	map_clear(&dso->sym_id);
	map_clear(&dso->func_id);
	map_clear(&dso->file_id);
}


// ************************************************************************
// 
// ************************************************************************
struct state {
	uint64_t sym_id;
	uint64_t func_id;
	uint64_t file_id;
	uint32_t line;
	uint32_t disc;
	int ready;
};

// ************************************************************************
// 
// ************************************************************************
static int dso_set_sym(struct dso *dso, struct state *s,
	uint64_t foffs, uint64_t addr, char *sym)
{
	size_t k = dso->nsym;
	
	if (MEM_RESIZE(dso->sym, dso->nsym, k + 1))
		return -1;

	size_t k0;
	int found;
	
	if (map_tool(&dso->sym_id, sym, k,
			&dso->sym[k].name, &k0, &found,
			MAP_INSERT | MAP_STORE))
		return -1;
	
	dso->sym[k].foffs = foffs;
	dso->sym[k].addr = addr;
	dso->sym[k].insn = dso->ninsn;
	dso->sym[k].hits = 0;
	dso->sym[k].multiple = 0;

	if (found) {
		//DEBUG("\t=== %s: duplicate symbol: %s (%ld and %ld)\n",
		//	dso->path, sym, k0, k);
		dso->sym[k0].multiple = 1;
		dso->sym[k].multiple = 1;
	}
	
	
	s->sym_id = k;
	
	return 0;
}


static int dso_set_func(struct dso *dso, struct state *s, char *func)
{
	size_t k = dso->nfunc;
	
	char *store;
	uint64_t k0;
	int found;
	
	if (map_tool(&dso->func_id, func, k, &store, &k0, &found,
			MAP_LOOKUP | MAP_INSERT | MAP_STORE)) {
		ERROR("%s: failed to store func '%s'\n", dso->path, func);
		return -1;
	}
	
	if (found) {
		s->func_id = k0;
		return 0;
	}
	
	if (MEM_RESIZE(dso->func, dso->nfunc, k + 1))
		return -1;
	
	dso->func[k].name = store;
	dso->func[k].hits = 0;
	s->func_id = k;
	
	return 0;
}

static int dso_set_file(struct dso *dso, struct state *s,
	char *file, uint64_t line, uint64_t disc)
{
	s->line = line;
	s->disc = disc;

	if ((s->file_id != (uint64_t)-1)
	&&  (strcmp(dso->file[s->file_id].name, file) == 0))
		return 0;
	
	size_t k = dso->nfile;
	char *store;
	uint64_t k0;
	int found;
	
	
	if (map_tool(&dso->file_id, file, k, &store, &k0, &found,
			MAP_LOOKUP | MAP_INSERT | MAP_STORE)) {
		ERROR("%s: failed to store file '%s'\n", dso->path, file);
		return -1;
	}
	
	if (found) {
		s->file_id = k0;
		return 0;
	}
	
	if (MEM_RESIZE(dso->file, dso->nfile, k + 1))
		return -1;
	
	dso->file[k].name = store;
	dso->file[k].hits = 0;
	dso->file[k].flags = 0;
	s->file_id = k;
	
	return 0;
}

static int dso_set_insn(struct dso *dso, struct state *s,
	uint64_t addr, uint8_t count, uint8_t *bin, char *disasm,
	uint64_t target_insn)
{
	size_t i = dso->ninsn;
	
	if (MEM_RESIZE(dso->insn, dso->ninsn, i + 1))
		return -1;
	
	char *store = obstack_dup(&dso->disasm, disasm);
	
	if (store == NULL) {
		dso->ninsn = i;
		return -1;
	}
	
	struct insn *x = &dso->insn[i];
	
	if (s->sym_id != (uint64_t)-1) {
		struct symbol *sym = &dso->sym[s->sym_id];
		x->foffs = (addr - sym->addr) + sym->foffs;
	} else {
		x->foffs = addr;
	}
	
	x->addr = addr;
	x->count = count;
	memcpy(x->bin, bin, 15);
	x->sym_id = s->sym_id;
	x->func_id = s->func_id;
	x->file_id = s->file_id;
	x->line = s->line;
	x->disc = s->disc;
	x->disasm = store;
	
	x->target_insn = target_insn;
	
	x->hits = 0;
	x->flags = 0;
	
	x->branches = 0;
	x->misses = 0;
	x->throughs = 0;
	
	memset(x->span, 0, INSN_SPANS * sizeof(struct span));
	
	x->source = DSO_INSN_NONE;
	x->landings = 0;
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
static int dso_parse_sym(struct dso *dso, struct state *s, char *b, size_t l)
{
	if (l < 6)
		return 0;
	
	char *e;
	uint64_t addr = hexparse(b, &e);
	
	if (e == b)
		return 0;
	
	if ((e[0] != ' ') || (e[1] != '<'))
		return 0;
	
	char *sym = e + 2;
	
	e = strchr(sym, '>');
	
	if (e == NULL)
		return 0;
	
	if (strncmp(e, "> (File Offset: 0x", 18) != 0)
		return 0;
	
	char *g;
	
	uint64_t foffs = hexparse(e + 18, &g);
	
	if ((g[0] != ')') || (g[1] != ':') || (g[2] != 0))
		return 0;
	
	*e = 0;

	// strip @@LIBVERSION
	//e = strchr(sym, '@');
	
	//if (e != NULL)
	//	*e = 0;
	
	if (dso_set_sym(dso, s, foffs, addr, sym))
		return -1;
	
	s->ready = 1;
	return 0;
}

// ***********************************************************
static int dso_parse_func(struct dso *dso, struct state *s, char *b, size_t l)
{
	if ((b[0] == ' ') || (b[0] == '/'))
		return 0;
	
	if (l < 4)
		return 0;
	
	if ((b[l - 3] != '(') || (b[l - 2] != ')') || (b[l - 1] != ':'))
		return 0;
	
	b[l - 3] = 0;
	
	if (dso_set_func(dso, s, b))
		return -1;
	
	s->ready = 1;
	return 0;
}

// ************************************************************************
static int dso_parse_file(struct dso *dso, struct state *s, char *b, size_t l)
{
	if (b[0] != '/')
		return 0;
	
	size_t offs = l - 1;
	
	uint64_t disc = 0;
	
	if (b[offs] == ')') {
		offs--;
		
		while ((offs > 0) && (b[offs] >= '0') && (b[offs] <= '9'))
			offs--;
		
		if (offs < 16)
			return -1;
		
		if (memcmp(b + offs - 15, " (discriminator ", 16) != 0)
			return -1;
		
		disc = decparse(b + offs + 1, NULL);
		
		offs -= 16;
	}
	
	while ((offs > 0) && (b[offs] >= '0') && (b[offs] <= '9'))
		offs--;
	
	if ((offs == 0) || (b[offs] != ':'))
		return 0;
	
	uint64_t line = decparse(b + offs + 1, NULL);
	
	b[offs] = 0;
	
	if (dso_set_file(dso, s, b, line, disc))
		return -1;
	
	s->ready = 1;
	return 0;
}


// ************************************************************************
static int dso_parse_byte(char *e, uint8_t *byte)
{
	uint8_t v = 0;
	
	if ((e[0] >= '0') && (e[0] <= '9'))
		v |= (e[0] - '0') << 4;
	else if ((e[0] >= 'A') && (e[0] <= 'F'))
		v |= (e[0] - 'A' + 10) << 4;
	else if ((e[0] >= 'a') && (e[0] <= 'f'))
		v |= (e[0] - 'a' + 10) << 4;
	else
		return -1;

	if ((e[1] >= '0') && (e[1] <= '9'))
		v |= (e[1] - '0');
	else if ((e[1] >= 'A') && (e[1] <= 'F'))
		v |= (e[1] - 'A' + 10);
	else if ((e[1] >= 'a') && (e[1] <= 'f'))
		v |= (e[1] - 'a' + 10);
	else
		return -1;
	
	if (e[2] != ' ')
		return -1;
	
	*byte = v;
	return 0;
}

// ************************************************************************
static uint64_t dso_parse_target(char *b, size_t l)
{
	if (b[l - 1] != ')')
		return DSO_INSN_NONE;
	
	char *ot = strstr(b, " (File Offset: 0x");
	
	if (ot == NULL)
		return DSO_INSN_NONE;
	
	char *oh = ot + 17;
	
	char *e;
	uint64_t foffs = hexparse(oh, &e);
	
	if ((e[0] != ')') || (e[1] != 0))
		return DSO_INSN_NONE;
	
	ot[0] = 0;
	return foffs;
}

// ************************************************************************
static int dso_parse_insn(struct dso *dso, struct state *s, char *b, size_t l)
{
	(void)l;
	
	char *a = b;
	
	while ((*a == ' ') || (*a == '\t'))
		a++;
	
	char *e;
	uint64_t addr = hexparse(a, &e);
	
	if ((e == a) || (*e != ':'))
		return 0;
	
	e++;
	
	while ((*e == ' ') || (*e == '\t'))
		e++;
	
	int count;
	uint8_t bin[15];
	
	for (count = 0; count < 15; count++) {
		if (dso_parse_byte(e, &bin[count]))
			break;
		
		e += 3;
	}
	
	if (count < 1)
		return 0;
	
	while ((*e == ' ') || (*e == '\t'))
		e++;
	
	uint64_t target_insn = dso_parse_target(e, l - (e - b));

	if (dso_set_insn(dso, s, addr, count, bin, e, target_insn))
		return -1;
	
	s->ready = 1;
	return 0;
}

// ************************************************************************
static int dso_parse_misc(struct dso *dso, struct state *s, char *b, size_t l)
{
	(void)dso;
	
	// empty line
	if (l == 0) {
		s->ready = 1;
		return 0;
	}
	
	// skip
	if (strcmp(b, "\t...") == 0) {
		s->ready = 1;
		return 0;
	}
	
	// section header
	if (strncmp(b, "Disassembly of section ", 23) == 0) {
		s->func_id = (uint64_t)-1;
		s->file_id = (uint64_t)-1;
		s->line = 0;
		s->ready = 1;
		return 0;
	}
	
	// file format
	if ((b[0] == '/') && (strstr(b, "file format") != NULL)) {
		s->ready = 1;
		return 0;
	}
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static size_t dso_locate_foffs(struct dso *dso, uint64_t foffs,
	size_t i0, size_t i1)
{
	uint64_t f0 = dso->insn[i0].foffs;
	uint64_t f1 = dso->insn[i1].foffs;
	
	//DEBUG("\t*** %s: hit %lx in [%lx %lx]\n", dso->path, addr, a0, a1);
	
	if ((foffs < f0) || (foffs > f1))
		return DSO_INSN_NONE;
	
	while (1) {
		//DEBUG("\t[%zd:%lx %zd:%lx]\n", k0, a0, k1, a1);
		if (foffs == f0)
			return i0;
		
		if (foffs == f1)
			return i1;
		
		if (i1 <= i0 + 1)
			return DSO_INSN_NONE;
		
		if (f1 <= f0)
			return DSO_INSN_NONE;
		
		size_t im = (i0 + i1) / 2;
		uint64_t fm = dso->insn[im].foffs;
		
		if (foffs < fm) {
			i1 = im;
			f1 = fm;
		} else {
			i0 = im;
			f0 = fm;
		}
	}
}

// ************************************************************************
static size_t dso_locate_sym(struct dso *dso, char *sym, uint64_t offs)
{
	uint64_t k;
	int found;
	
	if (sym == NULL)
		return DSO_INSN_NONE;
	
	map_tool(&dso->sym_id, sym, 0, NULL, &k, &found, MAP_LOOKUP);
	
	if (!found) {
		//DEBUG("\t=== %s: sym lookup %s+0x%lx: not found\n",
		//	dso->path, sym, offs);
		return DSO_INSN_NONE;
	}
	
	if (dso->sym[k].multiple) {
		//DEBUG("\t=== %s: sym lookup %s+0x%lx: multiple\n",
		//	dso->path, sym, offs);
		return DSO_INSN_NONE;
	}
	
	uint64_t foffs = dso->sym[k].foffs + offs;
	
	size_t i0 = dso->sym[k].insn;
	
	if (i0 >= dso->ninsn - 1)
		i0 = dso->ninsn - 1;
	
	size_t i1;
	size_t delta = 1;
	
	while (1) {
		i1 = i0 + delta;
		
		if (i1 >= dso->ninsn - 1) {
			i1 = dso->ninsn - 1;
			break;
		}
		
		uint64_t f1 = dso->insn[i1].foffs;
		
		if (f1 >= foffs)
			break;
		
		delta *= 2;
	}
	
	size_t i = dso_locate_foffs(dso, foffs, i0, i1);
	
	DEBUG("\t=== %s: fallback sym lookup %s+0x%lx: insn %zd %s.\n",
		dso->path, sym, offs,
		(i != DSO_INSN_NONE) ? i : 0,
		(i != DSO_INSN_NONE) ? "succeeded" : "failed");
	return i;
}

// ************************************************************************
// 
// ************************************************************************
static void dso_resolve_targets(struct dso *dso)
{
	struct insn *insn = dso->insn;
	size_t ninsn = dso->ninsn;
	
	size_t targets = 0;
	size_t resolved = 0;
	
	for (size_t i = 0; i < ninsn; i++) {
		uint64_t foffs = insn[i].target_insn;
		
		if (foffs == DSO_INSN_NONE)
			continue;
		
		targets++;
		
		size_t j = dso_locate_foffs(dso, foffs, 0, ninsn - 1);
		
		insn[i].target_insn = j;
		
		if (j != DSO_INSN_NONE) {
			insn[j].flags |= INSN_TARGET;
			resolved++;
		}
	}
	
	MESSAGE("      targ: %9zd / %9zd\n", resolved, targets);
}

// ************************************************************************
// 
// ************************************************************************
int dso_load(struct dso *dso)
{
	if (dso->path[0] == '[')
		return 0;
	
	size_t len = strlen(dso->path);
	
	if ((len > 3) && (memcmp(dso->path + len - 3, ".xz", 3) == 0))
		return 0;
	
	char *argv[5];
	int k = 0;
	
	argv[k++] = "objdump";
	argv[k++] = "-dlwF";
	argv[k++] = "-Mintel";
	argv[k++] = dso->path;
	argv[k++] = NULL;
	
	int fd = pipe_in(argv);
	
	if (fd < 0)
		return -1;
	
	FILE *f = fdopen(fd, "r");
	
	if (!f) {
		ERROR("fdopen(pipefd): %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	
	MESSAGE("    %s:\n", dso->path);
	
	char buff[4096];
	int r = -1;
	
	struct state s;
	
	s.sym_id = (uint64_t)-1;
	s.func_id = (uint64_t)-1;
	s.file_id = (uint64_t)-1;
	s.line = 0;
	s.disc = 0;
	
	while (1) {
		if ((dso->ninsn > 0) && ((dso->ninsn & 0x7ffff) == 0))
			MESSAGE("      [insn: %6zd k]\n", dso->ninsn >> 10);
		
		if (fgets(buff, sizeof(buff), f) != buff) {
			if (ferror(f)) {
				ERROR("fgets(): %s\n", strerror(errno));
				break;
			}
			
			r = 0;
			break;
		}
		
		size_t len = strlen(buff);
		
		if ((len > 0) && (buff[len - 1] == '\n')) {
			len--;
			buff[len] = 0;
		}
		
		s.ready = 0;
		
		if (dso_parse_file(dso, &s, buff, len))
			break;

		if (s.ready)
			continue;
		
		if (dso_parse_insn(dso, &s, buff, len))
			break;
		
		if (s.ready)
			continue;
		
		if (dso_parse_func(dso, &s, buff, len))
			break;
		
		if (s.ready)
			continue;
		
		if (dso_parse_sym(dso, &s, buff, len))
			break;
		
		if (s.ready)
			continue;
		
		if (dso_parse_misc(dso, &s, buff, len))
			break;
		
		if (s.ready)
			continue;
		
		ERROR("Unknown objdump entry: %s\n", buff);
	}
	
	fclose(f);
	
	MESSAGE("      insn: %9zd\n", dso->ninsn);
	
	if (r == 0)
		dso_resolve_targets(dso);
	
	return r;
}

// ************************************************************************
// 
// ************************************************************************
static void dso_hit_insn(struct dso *dso, uint64_t i)
{
	dso->samples++;
	dso->insn[i].hits++;
	
	uint64_t sym_id = dso->insn[i].sym_id;
	uint64_t func_id = dso->insn[i].func_id;
	uint64_t file_id = dso->insn[i].file_id;
	
	if (sym_id != (uint64_t)-1)
		dso->sym[sym_id].hits++;
	if (func_id != (uint64_t)-1)
		dso->func[func_id].hits++;
	if (file_id != (uint64_t)-1)
		dso->file[file_id].hits++;
}

// ************************************************************************
int dso_hit_foffs(struct dso *dso, uint64_t foffs, char *sym, uint64_t offs)
{
	if (dso->ninsn < 1) {
		dso->samples++;
		dso->orphans++;
		return -1;
	}
	
	size_t i = dso_locate_foffs(dso, foffs, 0, dso->ninsn - 1);

	if (i == DSO_INSN_NONE) {
		DEBUG("\t=== %s: %s+0x%lx: miss foffs 0x%lx, "
			"not in [0x%lx 0x%lx]\n",
			dso->path, (sym) ? sym : "[unknown]", offs,
			foffs,
			dso->insn[0].foffs,
			dso->insn[dso->ninsn - 1].foffs);
		dso->samples++;
		dso->orphans++;
		return -1;
	}

	dso_hit_insn(dso, i);
	
	//DEBUG("\t%zd:%lx: %ld hits\n", k0, a0, dso->insn[k0].hits);
	return 0;
}

// ************************************************************************
int dso_hit_sym(struct dso *dso, char *sym, uint64_t offs)
{
	if (dso->ninsn < 1) {
		dso->samples++;
		dso->orphans++;
		return -1;
	}

	size_t i = dso_locate_sym(dso, sym, offs);
	
	if (i == DSO_INSN_NONE) {
		dso->samples++;
		dso->orphans++;
		return -1;
	}
	
	dso_hit_insn(dso, i);
	
	return 0;
}

// ************************************************************************
void dso_hit_dso(struct dso *dso)
{
	dso->samples++;
	dso->unspec++;
}

// ************************************************************************
// 
// ************************************************************************
int  dso_branch(
	struct dso *pre_dso, uint64_t pre_foffs,
	struct dso *src_dso, uint64_t src_foffs,
	struct dso *dst_dso, uint64_t dst_foffs,
	int miss, uint64_t cycles)
{
	if ((src_foffs == (uint64_t)-1)
	||  (src_dso == NULL)
	||  (src_dso->ninsn < 1))
		return 0;
	
	// source
	size_t src_i = dso_locate_foffs(src_dso, src_foffs,
			0, src_dso->ninsn - 1);
	
	if (src_i == DSO_INSN_NONE)
		return -1;
	
	struct insn *src = &src_dso->insn[src_i];

	src->branches++;
	src->misses += (miss != 0);
	
	// destination
	if ((dst_foffs != (uint64_t)-1) && (dst_dso == src_dso)) {
		size_t dst_i = dso_locate_foffs(dst_dso, dst_foffs,
			0, dst_dso->ninsn - 1);
		
		if (dst_i == DSO_INSN_NONE)
			return -1;
		
		struct insn *dst = &dst_dso->insn[dst_i];

		if (dst->source == DSO_INSN_NONE) {
			dst->source = src_i;
		} else if (dst->source != src_i) {
			dst->source = src_i;
			dst->flags |= INSN_SOURCES_MORE;
		}
		
		dst->landings++;
	}
	
	// previous
	if ((pre_foffs != (uint64_t)-1) && (pre_dso == src_dso)) {
		size_t pre_i = dso_locate_foffs(pre_dso, pre_foffs,
			0, pre_dso->ninsn - 1);

		if (pre_i == DSO_INSN_NONE)
			return -1;
		
		// save span
		for (uint64_t j = 0; j < INSN_SPANS; j++) {
			if (src->span[j].count == 0) {
				src->span[j].start_i = pre_i;
				src->span[j].count = 1;
				src->span[j].cycles = cycles;
				break;
			}
			
			if (src->span[j].start_i == pre_i) {
				src->span[j].count++;
				src->span[j].cycles += cycles;
				break;
			}
		}
		
		// count throughs
		if ((pre_i < src_i) && (pre_i + INSN_THROUGH_MAX >= src_i)) {
			for (size_t i = pre_i; i <= src_i; i++) {
				src_dso->insn[i].throughs++;
			}
		}
	}

	return 0;
	
}



// ************************************************************************
// 
// ************************************************************************
