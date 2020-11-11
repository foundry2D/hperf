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
#include "message.h"
#include "prog.h"
#include "trace.h"
#include "meta.h"
#include "dump.h"
#include "output.h"
#include "main.h"

// ************************************************************************
// 
// ************************************************************************
struct param_info {
	char *flag;
	char *arg_name;
	char *description;
	char *def_val;
};

enum param_id {
	PARAM_INPUT,
	PARAM_OUTPUT,
	PARAM_SAMPLE_THRESHOLD,
	PARAM_HOTSPOT_THRESHOLD,
	PARAM_HOTSPOT_CONTEXT,
	PARAM_DUMP_CONTEXT,
	PARAM_THEME,
	NPARAMS,
};

static struct param_info param[NPARAMS] = {
{ "-i", "file", "input file, produced by perf-record", "perf.data" },
{ "-o", "file", "output file", "report.html" },
{ "-s", "count[%%]", "minimum number of samples per insn", "1" },
{ "-t", "count[%%]", "minimum total number of samples per hotspot", "2" },
{ "-c", "n", "merge hotspots separated by up to n insn", "5" },
{ "-d", "n", "output n insn before and after hotspots", "100" },
{ "-T", "theme", "'dark', 'light' or css file path", "light" },
};

// ************************************************************************
// 
// ************************************************************************
static void help_message(void)
{
	MESSAGE("Usage: hperf [options]\n"
		"\n"
		"Options:\n"
		"\n");
	
	for (int p = 0; p < NPARAMS; p++) {
		MESSAGE("  %-4s %-10s   %s (default: %s)\n",
			param[p].flag, param[p].arg_name,
			param[p].description, param[p].def_val);
	}
	
	MESSAGE("\n");
}

// ************************************************************************
// 
// ************************************************************************
static int arg_parse(char **val, char *flag, char *arg)
{
	int p = 0;
	
	while (p < NPARAMS) {
		if (strcmp(flag, param[p].flag) == 0)
			break;
		p++;
	}
	
	if (p >= NPARAMS) {
		ERROR("Unknown flag '%s'.\n", flag);
		return -1;
	}
	
	if (arg == NULL) {
		ERROR("Value expected after '%s'.\n", flag);
		return -1;
	}
	
	if (val[p] != NULL) {
		ERROR("Flag '%s' specified multiple times.\n", flag);
		return -1;
	}
	
	val[p] = arg;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static int pci(char *str, uint64_t *dst)
{
	char *e;
	
	uint64_t r = strtol(str, &e, 0);
	
	if ((e == str) || (*e != 0)) {
		ERROR("%s: could not parse insn count\n", str);
		return -1;
	}
	
	if (dst)
		*dst = r;
	
	return 0;
}

static int pcs(char *str, uint64_t *dst, uint64_t total)
{
	char *e;
	
	uint64_t r = strtol(str, &e, 0);
	
	if ((e == str) || (*e != 0)) {
		double f = strtod(str, &e);
		
		if ((e == str) || (e[0] != '%') || (e[1] != 0)) {
			ERROR("%s: could not parse sample count\n", str);
			return -1;
		}
		
		r = f * 0.01 * total;
		
		MESSAGE("  note: %s == %ld samples\n", str, r);
	}
	
	if (dst)
		*dst = r;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
static int run(char **val)
{
	struct prog prog;
	struct meta meta;
	
	prog_init(&prog);
	meta_init(&meta);
	
	int r = trace_load(&prog, val[PARAM_INPUT]);
	
	if (r)
		goto clear;
	
	if (prog.samples == 0) {
		ERROR("No samples read.\n");
		r = -1;
		goto clear;
	}
	
	r |= pcs(val[PARAM_SAMPLE_THRESHOLD],
		&meta.sample_threshold_hits, prog.samples);
	r |= pcs(val[PARAM_HOTSPOT_THRESHOLD],
		&meta.hotspot_threshold_hits, prog.samples);
	r |= pci(val[PARAM_HOTSPOT_CONTEXT],
		&meta.hotspot_context_insn);
	r |= pci(val[PARAM_DUMP_CONTEXT],
		&meta.dump_context_insn);
	
	if (r)
		goto clear;
	
	r |= meta_run(&meta, &prog);
	
	if (r) goto clear;
	
	//dump(&meta, &prog);
	
	r = output(&meta, &prog, val[PARAM_OUTPUT], val[PARAM_THEME]);

clear:	
	prog_clear(&prog);
	meta_clear(&meta);

	return r;
}

// ************************************************************************
// 
// ************************************************************************
int main(int argc, char **argv)
{
	char *val[NPARAMS];
	
	for (int p = 0; p < NPARAMS; p++)
		val[p] = NULL;
	
	for (int t = 1; t < argc; t += 2) {
		if ((strcmp(argv[t], "-h") == 0)
		||  (strcmp(argv[t], "--help") == 0)) {
			help_message();
			return 0;
		}
		
		if (arg_parse(val, argv[t], argv[t + 1])) {
			help_message();
			return 1;
		}
	}
	
	for (int p = 0; p < NPARAMS; p++) {
		if (val[p] == NULL)
			val[p] = param[p].def_val;
	}
	
	return run(val);
}

