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
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "message.h"
#include "pipe.h"
#include "prog.h"
#include "meta.h"
#include "serialize.h"

// ************************************************************************
// 
// ************************************************************************
int sout_open(struct sout *f, char *path)
{
	f->file = fopen(path, "w");

	if (!f->file) {
		ERROR("%s: %s\n", path, strerror(errno));
		return -1;
	}
	
	f->written = 0;
	f->flags = SOUT_CLOSE;
	
	return 0;
}

void sout_stdout(struct sout *f)
{
	f->file = stdout;
	f->written = 0;
	f->flags = 0;
}

int sout_close(struct sout *f)
{
	if (!(f->flags & SOUT_CLOSE))
		return 0;
	
	if (fclose(f->file)) {
		ERROR("fclose(): %s\n", strerror(errno));
		return -1;
	}
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
int sout_eof(struct sout *f)
{
	return feof(f->file);
}

int sout_error(struct sout *f)
{
	return ferror(f->file);
}

// ************************************************************************
// 
// ************************************************************************
#define SOUT_PROGRESS_SHIFT	23
static void sout_progress(struct sout *f, size_t n)
{
	size_t w0 = f->written;
	size_t w1 = w0 + n;
	
	f->written = w1;
	
	if ((w0 == 0) ||
	    ((w0 >> SOUT_PROGRESS_SHIFT) == (w1 >> SOUT_PROGRESS_SHIFT)))
		return;
	
	MESSAGE("    [%3zd MB]\n", w1 >> 20);
}

int sout_write(struct sout *f, char *buff, size_t size)
{
	if (fwrite(buff, size, 1, f->file) != 1) {
		ERROR("fwrite(): %s\n", strerror(errno));
		return -1;
	}
	
	sout_progress(f, size);
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
int vser(struct sout *f, const char *format, va_list ap)
{
	int r = vfprintf(f->file, format, ap);
	
	if (r < 0)
		return -1;
	
	sout_progress(f, r);
	
	return 0;
}

int ser(struct sout *f, const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	
	int r = vser(f, format, ap);
	
	va_end(ap);
	
	return r;
}

// ************************************************************************
// 
// ************************************************************************
static char ebuff[2048];

static char *escape(const char *s)
{
	size_t o = 0;
	
	while (o + 1 < sizeof(ebuff) && (*s != 0)) {
		if ((*s == '"') || (*s == '\\'))
			ebuff[o++] = '\\';
		
		ebuff[o++] = *s;
		s++;
	}
	
	if (o >= sizeof(ebuff))
		o = sizeof(ebuff) - 1;
	ebuff[o] = 0;
	
	return ebuff;
}


// ************************************************************************
// 
// ************************************************************************
int serialize_const(struct sout *f)
{
	ser(f, "const INSN_DUMP = %d\n", INSN_DUMP);
	ser(f, "const INSN_HOTSPOT = %d\n", INSN_HOTSPOT);
	ser(f, "const INSN_CENTER = %d\n", INSN_CENTER);
	ser(f, "const INSN_TARGET = %d\n", INSN_TARGET);
	ser(f, "const INSN_SPANS_MORE = %d\n", INSN_SPANS_MORE);
	ser(f, "const INSN_SOURCES_MORE = %d\n", INSN_SOURCES_MORE);
	
	return sout_error(f);
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_insn(struct sout *f, struct dso *dso)
{
	ser(f, "   ninsn: %zd,\n", dso->ninsn);
	ser(f, "   block: [\n");

	int cur_dump = 0;
	for (size_t i = 0; i < dso->ninsn; i++) {
		if (!(dso->insn[i].flags & INSN_DUMP)) {
			if (cur_dump) {
				ser(f, "     ],\n");
				ser(f, "    },\n");
				cur_dump = 0;
			}
			continue;
		}
		
		if (!cur_dump) {
			ser(f, "    {\n");
			ser(f, "     base: %ld,\n", i);
			ser(f, "     insn: [\n");
			cur_dump = 1;
		}
		
		struct insn *in = &dso->insn[i];
		
		ser(f, "      {\n");
		ser(f, "       foffs: 0x%lx,", in->foffs);
		ser(f, "  addr: 0x%lx,\n", in->addr);
		ser(f, "       bin: [");
		for (uint8_t b = 0; b < in->count; b++)
			ser(f, " 0x%02x,", in->bin[b]);
		ser(f, " ],\n");
		ser(f, "       sym_id: %ld,", in->sym_id);
		ser(f, " func_id: %ld,", in->func_id);
		ser(f, " file_id: %ld,", in->file_id);
		ser(f, " line: %d,", in->line);
		ser(f, " disc: %d,\n", in->disc);
		ser(f, "       disasm: \"%s\",\n", escape(in->disasm));
		ser(f, "       target_insn: %ld,", in->target_insn);
		ser(f, " hits: %ld,", in->hits);
		ser(f, " flags: 0x%lx,\n", in->flags);
		ser(f, "       branches: %ld,", in->branches);
		ser(f, " misses: %ld,", in->misses);
		ser(f, " throughs: %ld,\n", in->throughs);
		ser(f, "       span: [\n");
		for (int j = 0; j < INSN_SPANS; j++) {
			if (in->span[j].cycles == 0)
				break;
			ser(f, "        "
				"{ start_i: %zd, cycles: %ld, count: %ld },\n",
				in->span[j].start_i,
				in->span[j].cycles,
				in->span[j].count);
		}
		ser(f, "       ],\n");
		ser(f, "       source: %zd, landings: %ld\n",
			in->source, in->landings);
		ser(f, "      },\n");
	}

	if (cur_dump) {
		ser(f, "     ],\n");
		ser(f, "    },\n");
		cur_dump = 0;
	}
	
	ser(f, "   ],\n");
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_sym(struct sout *f, struct symbol *sym)
{
	ser(f, "    {");
	ser(f, " name: \"%s\",", escape(sym->name));
	ser(f, " foffs: 0x%lx,", sym->foffs);
	ser(f, " addr: 0x%lx,", sym->addr);
	ser(f, " insn: %ld,", sym->insn);
	ser(f, " hits: %ld,", sym->hits);
	ser(f, " multiple: %d,", sym->multiple);
	ser(f, " },\n");
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_func(struct sout *f, struct source_func *func)
{
	ser(f, "    { hits: %ld, name: \"%s\" },\n",
		func->hits, escape(func->name));
}

// ************************************************************************
// 
// ************************************************************************
static int serialize_file_contents(struct sout *outf, char *path)
{
	int k = 0;
	char *argv[6];
	argv[k++] = "highlight";
	argv[k++] = "-f";
	argv[k++] = "-O";
	argv[k++] = "html";
	argv[k++] = path;
	argv[k++] = NULL;
	
	int fd = pipe_in(argv);
	
	if (fd < 0)
		return -1;
	
	FILE *inf = fdopen(fd, "r");
	
	if (!inf) {
		ERROR("fdopen(pipefd): %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	
	char buff[4096];
	size_t tl = 0;
	int r = -1;
	
	while (1) {
		if (fgets(buff, sizeof(buff), inf) != buff) {
			if (ferror(inf)) {
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
		
		ser(outf, "\"%s\",\n", escape(buff));
		
		tl++;
	}
		
	fclose(inf);
	return r;
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_file(struct sout *f, struct source_file *file)
{
	ser(f, "    {\n");
	ser(f, "     name: \"%s\",\n", escape(file->name));
	ser(f, "     hits: %ld,\n", file->hits);
	ser(f, "     flags: 0x%lx,\n", file->flags);
	ser(f, "     line: [\n");
	ser(f, "      null,\n");
	
	serialize_file_contents(f, file->name);
	
	ser(f, "     ],\n");
	ser(f, "    },\n");
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_dso(struct sout *f, struct dso *dso)
{
	ser(f, "  {\n");
	ser(f, "   path: \"%s\",\n", escape(dso->path));
	serialize_insn(f, dso);
	ser(f, "   sym: [\n");
	for (size_t i = 0; i < dso->nsym; i++)
		serialize_sym(f, &dso->sym[i]);
	ser(f, "   ],\n");
	ser(f, "   func: [\n");
	for (size_t i = 0; i < dso->nfunc; i++)
		serialize_func(f, &dso->func[i]);
	ser(f, "   ],\n");
	ser(f, "   file: [\n");
	for (size_t i = 0; i < dso->nfile; i++)
		serialize_file(f, &dso->file[i]);
	ser(f, "   ],\n");
	ser(f, "   samples: %ld,\n", dso->samples);
	ser(f, "   unspec: %ld,\n", dso->unspec);
	ser(f, "   orphans: %ld,\n", dso->orphans);
	ser(f, "  },\n");
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_pmap(struct sout *f, struct pmmap *m)
{
	ser(f, "  {\n");
	ser(f, "   pid: %ld,\n", m->pid);
	ser(f, "   start: 0x%lx,\n", m->start);
	ser(f, "   length: 0x%lx,\n", m->length);
	ser(f, "   path: \"%s\",\n", escape(m->path));
	ser(f, "   offset: 0x%lx,\n", m->offset);
	ser(f, "  },\n");
}

// ************************************************************************
// 
// ************************************************************************
int serialize_prog(struct sout *f, struct prog *p)
{
	ser(f, "var prog = {\n");
	
	ser(f, " dso: [\n");
	for (size_t t = 0; t < p->ndso; t++)
		serialize_dso(f, &p->dso[t]);
	ser(f, " ],\n");

	ser(f, " pmap: [\n");
	for (size_t t = 0; t < p->npmap; t++)
		serialize_pmap(f, &p->pmap[t]);
	ser(f, " ],\n");

	ser(f, " insn: %ld,\n", p->insn);
	ser(f, " samples: %ld,\n", p->samples);
	ser(f, " unspec: %ld,\n", p->unspec);
	ser(f, " orphans: %ld,\n", p->orphans);
	ser(f, " branch_samples: %ld,\n", p->branch_samples);
	ser(f, " branch_unspec: %ld,\n", p->branch_unspec);
	ser(f, " branch_orphans: %ld,\n", p->branch_orphans);
	ser(f, "};\n");
	
	return sout_error(f);
}

// ************************************************************************
// 
// ************************************************************************
static void serialize_hot(struct sout *f, struct hotspot *hot)
{
	ser(f, "  { dso: %ld, i0: %ld, i1: %ld, ic: %ld, hits: %ld },\n",
		hot->dso, hot->i0, hot->i1, hot->ic, hot->hits);
}

static void serialize_topref(struct sout *f, struct topref *tr)
{
	ser(f, "  { dso: %ld, idx: %ld, hits: %ld },\n",
		tr->dso, tr->idx, tr->hits);
}

// ************************************************************************
// 
// ************************************************************************
int serialize_meta(struct sout *f, struct meta *m)
{
	ser(f, "var meta = {\n");
	
	ser(f, " hot: [\n");
	for (size_t t = 0; t < m->nhot; t++)
		serialize_hot(f, &m->hot[t]);
	ser(f, " ],\n");
	
	ser(f, " sym: [\n");
	for (size_t t = 0; t < m->nsym; t++) {
		if (m->sym[t].hits == 0)
			break;
		serialize_topref(f, &m->sym[t]);
	}
	ser(f, " ],\n");
	
	ser(f, " func: [\n");
	for (size_t t = 0; t < m->nfunc; t++) {
		if (m->func[t].hits == 0)
			break;
		serialize_topref(f, &m->func[t]);
	}
	ser(f, " ],\n");

	ser(f, "};\n");

	return sout_error(f);
}

// ************************************************************************
// 
// ************************************************************************
