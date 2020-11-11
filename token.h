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
#ifndef TOKEN_H
#define TOKEN_H
#include <string.h>
#include <stdint.h>

int tokenize(char *s, size_t sz, int max, int *n, char **tokens);

int match(char *s, char indicator, char *pattern, ...);

uint64_t hexparse(char *s, char **stop);
uint64_t decparse(char *s, char **stop);

#endif
