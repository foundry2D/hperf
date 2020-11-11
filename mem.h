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
#ifndef MEM_H
#define MEM_H
#include <stddef.h>

// ************************************************************************
// 
// ************************************************************************
#define BUF_GRAN	21

void buf_init(void **ptr, size_t *size);
void buf_clear(void **ptr, size_t *size);

int buf_resize(void **ptr, size_t *size, size_t esz, size_t n);


// ************************************************************************
// 
// ************************************************************************
#define MEM_INIT(ptr, size)	buf_init((void **)&(ptr), &(size))
#define MEM_CLEAR(ptr, size)	buf_clear((void **)&(ptr), &(size))

#define MEM_RESIZE(ptr, size, n)	\
		buf_resize((void **)&(ptr), &(size), sizeof(*ptr), (n))


// ************************************************************************
// 
// ************************************************************************
#define OBSTACK_SIZE	((size_t)2 << 20)

struct obstack {
	char **bufs;
	size_t nbufs;
	size_t offset;
};

void obstack_init(struct obstack *ob);
void obstack_clear(struct obstack *ob);

void obstack_swap(struct obstack *ob0, struct obstack *ob1);

char *obstack_get(struct obstack *ob, size_t n);
char *obstack_dup(struct obstack *ob, const char *src);


#endif
