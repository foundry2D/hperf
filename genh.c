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
#define _POSIX_C_SOURCE 201605L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

void make_macro(char *s)
{
	while (*s) {
		if ((*s >= 'a') && (*s <= 'z')) {
			*s = (int)*s + 'A' - 'a';
		} else if ((*s >= 'A') && (*s <= 'Z')) {
		} else if ((*s >= '0') && (*s <= '9')) {
		} else {
			*s = '_';
		}
		
		s++;
	}
}

int main(int argc, char **argv)
{
	FILE *f;
	char *path;
	char *m;
	size_t offs;
	int c;
	
	if (argc != 2) {
		fprintf(stderr, "Usage: genh <file>\n");
		return(1);
	}
	
	path = argv[1];
	
	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return(1);
	}
	
	m = strdup(path);
	if (!m) {
		fprintf(stderr, "strdup(): %s\n", strerror(errno));
		return(1);
	}
	
	make_macro(m);
	
	printf("#ifndef %s\n#define %s { \\\n",
		m, m);
	
	offs = 0;
	
	while (1) {
		c = getc(f);
		
		if (c == EOF)
			break;
		
		printf(" 0x%02x,", c);
		
		if ((offs % 12) == 11)
			printf(" \\\n");

		offs++;
	}
	
	printf(" \\\n 0 }\n#endif\n\n");
	
	fclose(f);
	free(m);
	
	return(0);
}

