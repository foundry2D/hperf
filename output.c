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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "message.h"
#include "files.h"
#include "serialize.h"
#include "output.h"


// ************************************************************************
// 
// ************************************************************************
static int output_file(struct sout *f, int id)
{
	char *content;
	size_t size;
	
	if (file_get(id, &content, &size))
		return -1;
	
	if (sout_write(f, content, size - 1))
		return -1;
	
	return 0;
}

// ************************************************************************
// 
// ************************************************************************
int output(struct meta *m, struct prog *p, char *out_path, char *theme)
{
	struct sout stf;
	struct sout *f = &stf;
	
	if ((out_path == NULL) || (strcmp(out_path, "-") == 0)) {
		sout_stdout(f);
	} else {
		if (sout_open(f, out_path))
			return -1;
	}
	
	MESSAGE("Serializing...\n");
	
	ser(f,
		"<!doctype html>\n"
		"<html lang='en'>\n"
		"<head>\n"
		"<meta charset='UTF-8'>\n"
		"<meta name='viewport'"
			" content='width=device-width, initial-scale=1.0'>\n"
		"<title>HPerf</title>\n");
	
	int r = 0;
	
	if (strcmp(theme, "dark") == 0) {
		ser(f, "<style>\n");
		r |= output_file(f, FILE_DARK_CSS);
		ser(f, "</style>\n");
	} else if (strcmp(theme, "light") == 0) {
		ser(f, "<style>\n");
		r |= output_file(f, FILE_LIGHT_CSS);
		ser(f, "</style>\n");
	} else {
		ser(f, "<link rel='stylesheet' href='%s'>",
			theme);
	}
	
	ser(f,
		"</head>\n"
		"<script>\n");
	
	r |= output_file(f, FILE_APP_JS);

	r |= serialize_const(f);
	r |= serialize_prog(f, p);
	r |= serialize_meta(f, m);

	ser(f,
		"</script>\n"
		"</html>\n");

	MESSAGE("    Done. %9zd bytes.\n", f->written);

	r |= sout_error(f);
	
	sout_close(f);
	
	return r;
}


// ************************************************************************
// 
// ************************************************************************
