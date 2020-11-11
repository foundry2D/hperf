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
#include <stdlib.h>
#include "message.h"
#include "mem.h"
#include "map.h"


// **************************************************************************
// 
// **************************************************************************
#define MAP_DEFAULT_BITS	16
#define MAP_DEFAULT_BITS_ADD	2
#define MAP_DEFAULT_EMAXPK	700

#define MAP_MASK(map)		((uint64_t)(map)->size - 1)

// **************************************************************************
// 
// **************************************************************************
static int map_init_internal(struct map *map,
	uint64_t bits, uint64_t bits_add, uint64_t entries_max_per1024)
{
	if (bits < 4)
		bits = 4;
	if (bits_add < 1)
		bits_add = 1;

	obstack_init(&map->strings);

	MEM_INIT(map->table, map->size);
	
	if (MEM_RESIZE(map->table, map->size, (size_t)1 << bits))
		return -1;
	
	map->bits = bits;
	map->bits_add = bits_add;
	map->entries_max_per1024 = entries_max_per1024;
	
	map->entries = 0;
	map->entries_max = (map->size * entries_max_per1024) >> 10;

	if (map->entries_max < 1)
		map->entries_max = 1;
	if (map->entries_max > map->size - 1)
		map->entries_max = map->size - 1;

	map->lookups = 0;
	map->lookup_steps = 0;
	
	
	struct map_entry *table = map->table;
	uint64_t size = map->size;
	
	for (uint64_t loc = 0; loc < size; loc++) {
		table[loc].loc = MAP_EMPTY;
		table[loc].value = 0;
		table[loc].key = NULL;
	}
	
	return 0;
}


int map_init(struct map *map)
{
	return map_init_internal(map,
		MAP_DEFAULT_BITS, MAP_DEFAULT_BITS_ADD, MAP_DEFAULT_EMAXPK);
}

void map_clear(struct map *map)
{
	obstack_clear(&map->strings);
	MEM_CLEAR(map->table, map->size);
}

// **************************************************************************
// 
// **************************************************************************
#define FNV_OFFSET_BASIS	0xcbf29ce484222325
#define FNV_PRIME		0x100000001b3

static inline uint64_t var_hash_u8(uint64_t h, uint8_t c)
{
	h ^= c;
	h *= FNV_PRIME;
	
	return h;
}

static uint64_t var_hash_str(char *str)
{
	uint64_t h = FNV_OFFSET_BASIS;
	
	while (1) {
		uint8_t c = *((unsigned char *)str);
		
		if (c == 0)
			break;
		
		h = var_hash_u8(h, c);
		str++;
	}
	
	return h;
}

// **************************************************************************
// 
// **************************************************************************
static int map_prepare(struct map *map)
{
	if (map->entries <= map->entries_max)
		return 0;
	
	//DEBUG("entries (%ld) > max (%ld / %zd)\n",
	//	map->entries, map->entries_max, map->size);
	map_debug_stats(map);
	map_debug_full(map);
	
	struct map tmp;
	if (map_init_internal(&tmp,
			map->bits, map->bits_add, map->entries_max_per1024))
		return -1;
	
	
	struct map_entry *table = map->table;
	uint64_t size = map->size;
	
	for (uint64_t i = 0; i < size; i++) {
		if (table[i].loc == MAP_EMPTY)
			continue;
		
		int found;
		int r = map_tool(&tmp, table[i].key, table[i].value,
				NULL, NULL, &found, MAP_INSERT);
		
		if (r || found) {
			DEBUG("rehash: Add '%s' -> %ld failed!\n",
				table[i].key, table[i].value);
			map_clear(&tmp);
			return -1;
		}
	}
	
	obstack_swap(&map->strings, &tmp.strings);
	
	map_clear(map);
	*map = tmp;
	
	return 0;
}

// **************************************************************************
// 
// **************************************************************************
int map_tool(struct map *map, char *key, uint64_t value,
	char **key_r, uint64_t *value_r, int *found_r, int op)
{
	if (op & MAP_INSERT) {
		if (map_prepare(map))
			return -1;
	}
	
	uint64_t mask = (uint64_t)map->size - 1;
	uint64_t loc = var_hash_str(key) & mask;

	//DEBUG(" %6s %55s => %10ld: %8ld\n",
	//	(op == MAP_ADD) ? "add" :
	//	(op == MAP_CLONE) ? "clone" : "lookup",
	//	key, value, loc);

	struct map_entry *table = map->table;
	uint64_t i = loc;
	uint64_t steps = 0;
	
	while (1) {
		struct map_entry p = table[i];
		
		// empty
		if (p.loc == MAP_EMPTY) {
			map->lookups++;
			map->lookup_steps += steps;
			
			if (found_r)
				*found_r = 0;

			// LOOKUP: not found
			if (!(op & MAP_INSERT))
				return 0;
			
			// ADD or CLONE: insert
			if (op & MAP_STORE) {
				key = obstack_dup(&map->strings, key);

				if (key == NULL)
					return -1;

				if (key_r)
					*key_r = key;
			}

			table[i].loc = loc;
			table[i].key = key;
			table[i].value = value;
			
			map->entries++;
			return 0;
		}
		
		// found match
		if (strcmp(p.key, key) == 0) {
			map->lookups++;
			map->lookup_steps += steps;

			if (key_r)
				*key_r = p.key;
			if (value_r)
				*value_r = p.value;
			if (found_r)
				*found_r = 1;
			
			if (op & MAP_UPDATE)
				table[i].value = value;

			return 0;
		}
		
		// robin hood
		uint64_t dp = i - p.loc;
		uint64_t dq = i - loc;
		
		if (dq > dp) {
			map->lookups++;
			map->lookup_steps += steps;

			// LOOKUP: not found
			if (!(op & MAP_INSERT)) {
				if (found_r)
					*found_r = 0;
				
				return 0;
			}
			
			// ADD or CLONE: insert and switch
			if (op & MAP_STORE) {
				key = obstack_dup(&map->strings, key);

				if (key == NULL)
					return -1;

				if (key_r)
					*key_r = key;

				op &= ~MAP_STORE;
			}
			
			table[i].loc = loc;
			table[i].key = key;
			table[i].value = value;
			
			// *found_r will be set to 0 later
			// map->entries will be incremented later
			loc = p.loc;
			key = p.key;
			value = p.value;
		}
		
		// check
		if (steps >= mask) {
			ERROR("map_tool(%s (loc %ld) => %ld, nf:%s f:%s %s): "
				"probe (%ld steps) longer than "
				"table (%ld / %zd)\n",
				key, loc, value,
				(op & MAP_UPDATE) ? "update" : "nil",
				(op & MAP_INSERT) ? "insert" : "nil",
				(op & MAP_STORE) ? "store" : "clone",
				steps, map->entries, map->size);
			map_debug_stats(map);
			//map_debug_full(map);
			exit(1);
		}
		
		// next
		i = (i + 1) & mask;
		steps++;
	}
}

// **************************************************************************
// 
// **************************************************************************
void map_debug_stats(struct map *map)
{
	DEBUG("map: load %8ld / %8zd = %5.2f (%2ld bits)\n"
		"  lookups %8ld / %8ld = %5.2f\n",
		map->entries, map->size,
		(double)map->entries / map->size,
		map->bits,
		map->lookup_steps, map->lookups,
		(map->lookups) ? (double)map->lookup_steps / map->lookups : 0.0
		);
}

static void map_debug_key(struct map *map, uint64_t i)
{
	if (map->table[i].loc == MAP_EMPTY) {
		DEBUG("[%8li] empty\n", i);
		return;
	}

	DEBUG("[%8li] %8ld (+%3li): %8ld <- ",
		i, map->table[i].loc,
		(i - map->table[i].loc) & MAP_MASK(map),
		map->table[i].value);
	
	DEBUG("'%s'\n", map->table[i].key);
}

void map_debug_full(struct map *map)
{
	DEBUG("--------------------------------\n");

	uint64_t skip = 0;
	
	for (uint64_t i = 0; i < map->size; i++) {
		if (map->table[i].loc == MAP_EMPTY) {
			skip++;
			continue;
		}
		
		if (skip) {
			DEBUG(" ... %li ...\n", skip);
			skip = 0;
		}
		
		map_debug_key(map, i);
	}

	DEBUG("--------------------------------\n");
}

