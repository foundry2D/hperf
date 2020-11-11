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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "message.h"
#include "mem.h"

// ************************************************************************
// 
// ************************************************************************
void buf_init(void **ptr, size_t *size)
{
	*ptr = NULL;
	*size = 0;
}

void buf_clear(void **ptr, size_t *size)
{
	free(*ptr);
	*ptr = NULL;
	*size = 0;
}


// ************************************************************************
// 
// ************************************************************************
static size_t buf_roundup(size_t bytes)
{
	size_t mask = ((size_t)1 << BUF_GRAN) - 1;
	return (bytes + mask) & (~mask);
}


// ************************************************************************
// 
// ************************************************************************
int buf_resize(void **ptr, size_t *size, size_t esz, size_t n)
{
	size_t b0 = buf_roundup(esz * (*size));
	size_t b1 = buf_roundup(esz * n);
	
	if (b1 <= b0) {
		*size = n;
		return 0;
	}
	
	void *r = realloc(*ptr, b1);
	
	if (!r) {
		ERROR("MEM_RESIZE(%zd -> %zd): buf_resize(%zd -> %zd): %s\n",
			*size, n, b0, b1, strerror(errno));
		return -1;
	}
	
	*ptr = r;
	*size = n;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
void obstack_init(struct obstack *ob)
{
	ob->bufs = NULL;
	ob->nbufs = 0;
	ob->offset = 0;
}

void obstack_clear(struct obstack *ob)
{
	for (size_t i = 0; i < ob->nbufs; i++)
		free(ob->bufs[i]);
	
	free(ob->bufs);
	
	ob->bufs = NULL;
	ob->nbufs = 0;
	ob->offset = 0;
}

void obstack_swap(struct obstack *ob0, struct obstack *ob1)
{
	struct obstack tmp;
	
	tmp = *ob1;
	*ob1 = *ob0;
	*ob0 = tmp;
}

// ************************************************************************
// 
// ************************************************************************
char *obstack_get(struct obstack *ob, size_t n)
{
	// fast path
	if ((ob->nbufs > 0) && (ob->offset + n < OBSTACK_SIZE)) {
		char *r = ob->bufs[ob->nbufs - 1] + ob->offset;
		ob->offset += n;
		return r;
	}
	
	// enlarge pointer vector
	char **bufs = realloc(ob->bufs, (ob->nbufs + 1) * sizeof(char **));
	
	if (bufs == NULL) {
		ERROR("obstack_get(%zd): realloc(%zd bufs): %s\n",
			n, ob->nbufs + 1, strerror(errno));
		return NULL;
	}
	
	ob->bufs = bufs;
	
	// allocate new block
	size_t a = (n < OBSTACK_SIZE) ? OBSTACK_SIZE : n;
	
	char *block = malloc(a);
	
	if (block == NULL) {
		ERROR("obstack_get(%zd): malloc(%zd): %s\n",
			n, a, strerror(errno));
		return NULL;
	}
	
	// register new block and allocation
	ob->bufs[ob->nbufs] = block;
	ob->nbufs++;
	ob->offset = n;
	
	return block;
}

// ************************************************************************
// 
// ************************************************************************
char *obstack_dup(struct obstack *ob, const char *src)
{
	size_t len = strlen(src);
	
	char *dst = obstack_get(ob, len + 1);
	
	if (dst == NULL)
		return NULL;
	
	memcpy(dst, src, len + 1);
	
	return dst;
}
