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
#ifndef SERIALIZE_H
#define SERIALIZE_H
#include <stdio.h>
#include <stdarg.h>
#include "prog.h"
#include "meta.h"

#define SOUT_CLOSE	1

struct sout {
	FILE *file;
	size_t written;
	int flags;
};

int sout_open(struct sout *f, char *path);
void sout_stdout(struct sout *f);
int sout_close(struct sout *f);

int sout_eof(struct sout *f);
int sout_error(struct sout *f);

int sout_write(struct sout *f, char *buff, size_t size);

int vser(struct sout *f, const char *format, va_list ap);
__attribute__ ((format (printf, 2, 3)))
int ser(struct sout *f, const char *format, ...);

int serialize_const(struct sout *f);
int serialize_prog(struct sout *f, struct prog *p);
int serialize_meta(struct sout *f, struct meta *m);

#endif
