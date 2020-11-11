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
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "message.h"
#include "pipe.h"
#include "token.h"
#include "prog.h"
#include "trace.h"

// ************************************************************************
// 
// ************************************************************************
struct trace {
	size_t error, read, samples;
};

// ************************************************************************
// 
// ************************************************************************
static void trace_dump(int n, char **token)
{
	for (int i = 0; i < n; i++) {
		ERROR("\t%2d: {%s}\n", i, token[i]);
	}
}

// ************************************************************************
// 
// ************************************************************************
/*
 [0]  1   [2]         3           [4]              5
comm pid time: PERF_RECORD_MMAP pid/tid: [0xADDRESS(0xSIZE)
  @ 0/FILE-OFFSET?]: prot /path
  6      7           [8]    9

 [0]  1   [2]         3            [4]             5
comm pid time: PERF_RECORD_MMAP2 pid/tid: [0xADDRESS(0xSIZE)
  @ 0/FILE-OFFSET? maj:min inode inode_gen]: prot /path
  6      7           [8]    [9]     [10]     [11]   12

*/
static int trace_parse_mmap(struct prog *p, int n, char **token)
{
	if  (n < 10)
		return -1;
	
	if ((token[6][0] != '@') || (token[6][1] != 0))
		return -1;
	
	int v;
	
	if (strcmp(token[3], "PERF_RECORD_MMAP2") == 0) {
		if (n < 13)
			return -1;
		v = 2;
	} else if (strcmp(token[3], "PERF_RECORD_MMAP") == 0) {
		v = 1;
	} else {
		return -1;
	}
	
	char *e;
	
	uint64_t pid = decparse(token[1], &e);
	
	if (*e != 0)
		return -1;
	
	char *w = token[5];
	
	if ((w[0] != '[') || (w[1] != '0') || (w[2] != 'x'))
		return -1;
	
	uint64_t start = hexparse(w + 3, &e);
	
	w = e;
	
	if ((w[0] != '(') || (w[1] != '0') || (w[2] != 'x'))
		return -1;

	uint64_t length = hexparse(w + 3, &e);
	
	if (*e != ')')
		return -1;
	
	uint64_t offset;
	w = token[7];
	
	if ((w[0] == '0') && (w[1] == 'x')) {
		w += 2;
		offset = hexparse(w, &e);
	} else {
		offset = decparse(w, &e);
	}
	
	if (v == 1) {
		if (*e != ']')
			return -1;
		
		w = token[9];
	} else if (v == 2) {
		if (*e != 0)
			return -1;

		w = token[12];
	}
	
	char *path = w;
	
	if (pid == 0)
		return 0;
	
	//DEBUG("mmap%d: pid %ld, addr 0x%lx, size 0x%lx, "
	//	"file %s, offset 0x%lx\n",
	//	v, pid, start, length, path, offset);
	
	if (prog_mmap(p, pid, start, length, path, offset))
		return -1;
	
	return 0;
}

// ************************************************************************
/*
 [0]  1   [2]    3       4       5     6         7
comm pid time: cycles 'cycles:' ip sym+symoffs (dso)
ip(dso) / ip(dso) / Mis|Predicted / X|- / A|- / cycles
                       (8+k)
*/
static int trace_parse_sample(struct prog *p, int n, char **token)
{
	if (n < 8)
		return -1;
	
	if (strcmp(token[4], "cycles:") != 0)
		return -1;
	
	char *e;
	
	uint64_t pid = decparse(token[1], &e);
	
	if (*e != 0)
		return -1;
	
	uint64_t addr = hexparse(token[5], &e);
	
	if (*e != 0)
		return -1;
	
	char *sym, *hoffs;
	uint64_t offs = 0;
	
	if (match(token[6], '?', "?+0x?", &sym, &hoffs)) {
		sym = NULL;
	} else {
		offs = hexparse(hoffs, &e);
		
		if (*e != 0)
			return -1;
	}
	
	char *dso;
	
	if (match(token[7], '?', "(?)", &dso))
		return -1;
	
	//MESSAGE("%s: %s + %s = 0x%lx\n", dso, sym, hoffs, addr);
	
	if (prog_sample(p, pid, addr, dso, sym, offs))
		return -1;
	
	char *pre_dso = NULL;
	uint64_t pre_addr = (uint64_t)-1;
	
	for (int k = n - 1; k >= 8; k--) {
		char *src_as, *src_dso, *dst_as, *dst_dso;
		char *ps, *cs;
		
		if (match(token[k], '?', "0x?(?)/0x?(?)/?/?/?/?",
				&src_as, &src_dso, &dst_as, &dst_dso,
				&ps, NULL, NULL, &cs))
			return -1;
		
		uint64_t src_addr = hexparse(src_as, &e);
		
		if (*e != 0)
			return -1;
		
		uint64_t dst_addr = hexparse(dst_as, &e);
		
		if (*e != 0)
			return -1;
		
		int miss;
		
		if ((ps[0] == 'P') && (ps[1] == 0))
			miss = 0;
		else if ((ps[0] == 'M') && (ps[1] == 0))
			miss = 1;
		else
			return -1;
		
		uint64_t cycles = decparse(cs, &e);
		
		if (*e != 0)
			return -1;
		
		// so as to not introduce a bias, we discard the first
		// branch from the stack
		if (pre_dso) {
			if (prog_branch(p, pid,
					pre_addr, pre_dso,
					src_addr, src_dso,
					dst_addr, dst_dso,
					miss, cycles))
				return -1;
		}
		
		pre_dso = dst_dso;
		pre_addr = dst_addr;
	}
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static int trace_parse_line(struct prog *p, char *buff, size_t size)
{
	// tokenize
	char *token[64];
	int n;
	
	if (tokenize(buff, size, 64, &n, token)) {
		ERROR("Unable to tokenize:\n");
		trace_dump(n, token);
		return -1;
	}
	
	// parse sample
	if (trace_parse_sample(p, n, token) == 0)
		return 0;
	
	// parse mmap
	if (trace_parse_mmap(p, n, token) == 0)
		return 0;
	
	ERROR("Unable to parse:\n");
	trace_dump(n, token);
	return -1;
}


// ************************************************************************
// 
// ************************************************************************
int trace_load(struct prog *p, char *path)
{
	char *argv[8];
	int k = 0;
	
	argv[k++] = "perf";
	argv[k++] = "script";
	
	if (path) {
		argv[k++] = "-i";
		argv[k++] = path;
	}
	
	argv[k++] = "--show-mmap-events";
	argv[k++] = "-F";
	argv[k++] = "comm,pid,time,period,event,ip,sym,symoff,dso,brstack";
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
	
	MESSAGE("%s:\n", path);
	size_t lines = 0;
	size_t parsed = 0;
	
	char buff[16384];
	int r = 0;
	
	while (1) {
		if ((parsed > 0) && ((parsed & 0xffff) == 0))
			MESSAGE("  [samples: %6zd k]\n", parsed >> 10);
		
		if (fgets(buff, sizeof(buff), f) != buff) {
			if (ferror(f)) {
				ERROR("fgets(): %s\n", strerror(errno));
				r = -1;
			}
			
			break;
		}
		
		lines++;
		
		if (trace_parse_line(p, buff, sizeof(buff)) == 0)
			parsed++;
	}
	
	MESSAGE("  samples: parsed: %9zd, ignored: %9zd\n",
		parsed, lines - parsed);
	MESSAGE("             hits: %9ld,  unspec: %9ld, orphans: %9ld\n",
		p->samples - p->unspec - p->orphans,
		p->unspec, p->orphans);
	MESSAGE(" branches:   hits: %9zd,  unspec: %9zd, orphans: %9zd\n",
		p->branch_samples - p->branch_unspec - p->branch_orphans,
		p->branch_unspec, p->branch_orphans);
	MESSAGE("     insn:         %9zd\n", p->insn);
	
	fclose(f);
	
	
	return r;
}


// ************************************************************************
// 
// ************************************************************************
