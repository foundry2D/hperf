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
#ifndef META_H
#define META_H
#include <stddef.h>
#include <stdint.h>
#include "prog.h"


struct hotspot {
	uint64_t dso;
	uint64_t i0, i1, ic;
	uint64_t hits;
};

struct topref {
	uint64_t dso;
	size_t idx;
	uint64_t hits;
};

struct meta {
	struct hotspot *hot;
	size_t nhot;
	
	struct topref *sym;
	size_t nsym;
	
	struct topref *func;
	size_t nfunc;
	
	// options
	uint64_t sample_threshold_hits;
	uint64_t hotspot_threshold_hits;
	uint64_t hotspot_context_insn;
	uint64_t dump_context_insn;
};

void meta_init(struct meta *m);
void meta_clear(struct meta *m);

int meta_run(struct meta *m, struct prog *p);

#endif
