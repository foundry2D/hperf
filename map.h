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
#ifndef MAP_H
#define MAP_H
#include <stdint.h>
#include "mem.h"

// *************************************************************************
// Structures
// *************************************************************************
#define MAP_EMPTY	((uint64_t)-1)

struct map_entry {
	uint64_t loc;
	uint64_t value;
	char *key;
};

struct map {
	struct map_entry *table;
	size_t size;
	
	// parameters
	uint64_t bits, bits_add, entries_max_per1024;

	// stats
	uint64_t entries, entries_max;
	uint64_t lookups, lookup_steps;
	
	struct obstack strings;
};

// *************************************************************************
// Functions
// *************************************************************************
int map_init(struct map *map);
void map_clear(struct map *map);

/*
 key     found -> (MAP_UPDATE) ?  update value : do nothing;
 key not found -> (MAP_INSERT) ? add key/value : do nothing;
 
 add key/value: (MAP_STORE) ? dup() key : use provided pointer;
*/

#define MAP_LOOKUP	0
#define MAP_UPDATE	1
#define MAP_INSERT	2
#define MAP_STORE	4
int map_tool(struct map *map, char *key, uint64_t value,
	char **key_r, uint64_t *value_r, int *found_r, int op);

void map_debug_stats(struct map *map);
void map_debug_full(struct map *map);

#endif

