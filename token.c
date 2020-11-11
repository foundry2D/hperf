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
#include <stdarg.h>
#include "token.h"



// ************************************************************************
// 
// ************************************************************************
int tokenize(char *s, size_t sz, int max, int *n, char **tokens)
{
	size_t offs = 0;
	int k = 0;
	
	*n = 0;
	
	while (1) {
		int bc = 0;
		
		while ((s[offs] == ' ') || (s[offs] == '\t')
		|| (s[offs] == '\n')) {
			bc++;
			offs++;
		}
		
		if (s[offs] == 0)
			break;
		
		if (k >= max) {
			//ERROR("Too many tokens:\n%s", s);
			*n = k;
			return -1;
		}
		
		//blanks[k] = bc + (k != 0);
		tokens[k] = s + offs;

		while ((s[offs] != ' ') && (s[offs] != '\t')
		&& (s[offs] != '\n') && (s[offs] != 0))
			offs++;
		
		k++;
		
		s[offs] = 0;
		offs++;
	}
	
	if (offs == sz - 1) {
		//ERROR("Line too long:\n%s\n", s);
		*n = k;
		return -1;
	}
	
	*n = k;
	return 0;
}


// ************************************************************************
// 
// ************************************************************************
int match(char *s, char ind, char *p, ...)
{
	va_list va;

	va_start(va, p);
	
	size_t so = 0;
	size_t po = 0;
	int r = 0;

	while (1) {
		char pc = p[po]; 
		if (pc != ind) {
			if (s[so] != pc) {
				r = -1;
				break;
			}
			
			if (pc == 0)
				break;
			so++;
			po++;
			continue;
		}
		
		char **memb = va_arg(va, char **);
		
		if (memb)
			*memb = &s[so];
		
		char stop = p[po + 1];
		
		while ((s[so] != stop) && (s[so] != 0))
			so++;
		
		if (s[so] != stop) {
			r = -1;
			break;
		}
		
		s[so] = 0;
		so++;
		
		if (stop == 0)
			break;
		po += 2;
	}
	
	va_end(va);
	
	return r;
}


// ************************************************************************
// 
// ************************************************************************
uint64_t hexparse(char *s, char **stop)
{
	uint64_t r = 0;
	
	while (1) {
		char c = *s;
		
		if ((c >= '0') && (c <= '9')) {
			r = (r << 4) | (c - '0');
		} else if ((c >= 'A') && (c <= 'F')) {
			r = (r << 4) | (c - 'A' + 10);
		} else if ((c >= 'a') && (c <= 'f')) {
			r = (r << 4) | (c - 'a' + 10);
		} else {
			break;
		}
		
		s++;
	}

	if (stop)
		*stop = s;
	
	return r;
}

// ************************************************************************
// 
// ************************************************************************
uint64_t decparse(char *s, char **stop)
{
	uint64_t r = 0;
	
	while (1) {
		char c = *s;
		
		if ((c >= '0') && (c <= '9')) {
			r = (r * 10) + (c - '0');
		} else {
			break;
		}
		
		s++;
	}

	if (stop)
		*stop = s;
	
	return r;
}

