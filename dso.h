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
#ifndef DSO_H
#define DSO_H
#include <stddef.h>
#include <stdint.h>
#include "mem.h"
#include "map.h"

// special values
#define DSO_INSN_NONE		((size_t)-1)
#define DSO_SYM_NONE		((uint64_t)-1)

#define INSN_THROUGH_MAX	256

#define INSN_SPANS		2
struct span {
	size_t start_i;
	uint64_t cycles;
	uint64_t count;
};

// insn flags
#define INSN_DUMP		1
#define INSN_HOTSPOT		2
#define INSN_CENTER		4
#define INSN_TARGET		8
#define INSN_SPANS_MORE		16
#define INSN_SOURCES_MORE	32
struct insn {
	uint64_t foffs, addr;
	uint8_t count;
	uint8_t bin[15];
	
	uint64_t sym_id;
	uint64_t func_id;
	uint64_t file_id;
	uint32_t line;
	uint32_t disc;
	
	char *disasm;
	
	uint64_t target_insn;
	
	uint64_t hits;
	uint64_t flags;
	
	uint64_t branches, misses;
	uint64_t throughs;
	
	struct span span[INSN_SPANS];
	
	size_t source;
	uint64_t landings;
	
	uint64_t _padding;
};

struct symbol {
	char *name;
	uint64_t foffs, addr;
	size_t insn;
	uint64_t hits;
	int multiple;
};

struct source_func {
	char *name;
	uint64_t hits;
};

// file flags
#define SOURCE_FILE_DUMP	1

struct source_file {
	char *name;
	uint64_t hits;
	uint64_t flags;
};

struct dso {
	char path[1024];
	
	struct insn *insn;
	size_t ninsn;
	
	struct symbol *sym;
	size_t nsym;
	
	struct source_func *func;
	size_t nfunc;

	struct source_file *file;
	size_t nfile;
	
	struct obstack disasm;
	
	struct map sym_id;
	struct map func_id;
	struct map file_id;
	
	size_t samples, unspec, orphans;
};

int  dso_init(struct dso *dso, char *path);
void dso_clear(struct dso *dso);

int  dso_load(struct dso *dso);
int  dso_hit_foffs(struct dso *dso, uint64_t foffs, char *sym, uint64_t offs);
int  dso_hit_sym(struct dso *dso, char *sym, uint64_t offs);
void dso_hit_dso(struct dso *dso);

int  dso_branch(
	struct dso *pre_dso, uint64_t pre_foffs,
	struct dso *src_dso, uint64_t src_foffs,
	struct dso *dst_dso, uint64_t dst_foffs,
	int miss, uint64_t cycles);

#endif
