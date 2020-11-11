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
#include "message.h"
#include "serialize.h"
#include "dump.h"


// ************************************************************************
// 
// ************************************************************************
int dump(struct meta *m, struct prog *p)
{
	DEBUG("DSOs:\n");

	for (size_t t = 0; t < p->ndso; t++) {
		DEBUG("  %6ld %s\n", p->dso[t].samples, p->dso[t].path);
	}
	
	DEBUG("Symbols:\n");
	for (size_t i = 0; i < m->nsym; i++) {
		if (m->sym[i].hits == 0)
			break;
		
		size_t t = m->sym[i].dso;
		size_t s = m->sym[i].idx;
		
		DEBUG("  %6ld %s %s\n",
			p->dso[t].sym[s].hits,
			p->dso[t].path,
			p->dso[t].sym[s].name);
	}
	
	DEBUG("Functions:\n");
	for (size_t i = 0; i < m->nfunc; i++) {
		if (m->func[i].hits == 0)
			break;
		
		size_t t = m->func[i].dso;
		size_t f = m->func[i].idx;
		
		DEBUG("  %6ld %s %s()\n",
			p->dso[t].func[f].hits,
			p->dso[t].path,
			p->dso[t].func[f].name);
	}

	DEBUG("Source files:\n");
	for (size_t t = 0; t < p->ndso; t++) {
		for (size_t f = 0; f < p->dso[t].nfile; f++) {
			if (p->dso[t].file[f].hits == 0)
				DEBUG("  %6s", "");
			else
				DEBUG("  %6ld", p->dso[t].file[f].hits);
			
			DEBUG(" %6s %s\n",
				(p->dso[t].file[f].flags & SOURCE_FILE_DUMP)
					? "[DUMP]" : "",
				p->dso[t].file[f].name);
		}
	}
	
	DEBUG("Hotspots:\n");
	for (size_t hid = 0; hid < m->nhot; hid++) {
		struct hotspot *h = &m->hot[hid];
		struct dso *dso = &p->dso[h->dso];
		
		uint64_t sym_id = -1;
		
		if (dso->ninsn > 0)
			sym_id = dso->insn[h->ic].sym_id;
		
		char *sym = (sym_id == (uint64_t)-1) ? "[unknown]"
			: dso->sym[sym_id].name;
		
		DEBUG("  %6ld %s: %ld - %ld (center %ld %s)\n",
			h->hits, dso->path, h->i0, h->i1, h->ic, sym);
	}
	
	DEBUG("Insn:\n");
	for (size_t t = 0; t < p->ndso; t++) {
		DEBUG("%s:\n", p->dso[t].path);
		uint64_t cur_sym_id = (uint64_t)-1;
		int cur_dump = 0;
		for (size_t i = 0; i < p->dso[t].ninsn; i++) {
			if (!(p->dso[t].insn[i].flags & INSN_DUMP)) {
				cur_dump = 0;
				continue;
			}
			
			if (!cur_dump) {
				DEBUG("  ...\n");
				cur_dump = 1;
			}
			
			if (p->dso[t].insn[i].sym_id != cur_sym_id) {
				cur_sym_id = p->dso[t].insn[i].sym_id;
				
				if (cur_sym_id != (uint64_t)-1) {
					DEBUG("%s:\n",
						p->dso[t].sym[cur_sym_id].name);
					if (p->dso[t].sym[cur_sym_id].insn
					!= i)
						DEBUG("  ...\n");
				}
			}
			
			DEBUG("  %s",
				(p->dso[t].insn[i].flags & INSN_CENTER)
				? "H"
				: (p->dso[t].insn[i].flags & INSN_HOTSPOT)
				? "h" : " ");
				
			if (p->dso[t].insn[i].hits == 0)
				DEBUG(" %6s", "");
			else
				DEBUG(" %6ld",
					p->dso[t].insn[i].hits);

			DEBUG(" %6ld %s",
				i,
				p->dso[t].insn[i].disasm);
			
			if (p->dso[t].insn[i].target_insn != DSO_INSN_NONE) {
				DEBUG(" (insn %ld)",
					p->dso[t].insn[i].target_insn);
			}
			
			DEBUG("\n");
		}
	}
	
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
