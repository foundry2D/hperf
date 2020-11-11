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
#include "files.h"

#include "gen_dark.css.h"
#include "gen_light.css.h"
#include "gen_app.js.h"

static char file_dark_css[] = GEN_DARK_CSS;
static char file_light_css[] = GEN_LIGHT_CSS;
static char file_app_js[] = GEN_APP_JS;

int file_get(int id, char **content, size_t *size)
{
	switch(id) {
	case FILE_DARK_CSS:
		if (content)
			*content = file_dark_css;
		if (size)
			*size = sizeof(file_dark_css);
		
		return 0;
	
	case FILE_LIGHT_CSS:
		if (content)
			*content = file_light_css;
		if (size)
			*size = sizeof(file_light_css);
		
		return 0;
	
	case FILE_APP_JS:
		if (content)
			*content = file_app_js;
		if (size)
			*size = sizeof(file_app_js);
		
		return 0;
	
	default:
		return -1;
	
	}
}
