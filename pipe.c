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
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "message.h"
#include "pipe.h"

int pipe_in(char **argv)
{
	// pipe
	int fd[2];
	
	if (pipe(fd)) {
		ERROR("pipe(): %s\n", strerror(errno));
		return -1;
	}
	
	// fork
	pid_t child = fork();
	
	if (child == (pid_t)-1) {
		ERROR("fork(): %s\n", strerror(errno));
		return -1;
	}
	
	// parent
	if (child != 0) {
		// close pipe's write end
		close(fd[1]);
		
		return fd[0];
	}
	
	// child
	close(fd[0]);
	
	if (dup2(fd[1], 1) != 1) {
		ERROR("dup2(): %s\n", strerror(errno));
		exit(1);
	}
	
	execvp(argv[0], argv);
	
	ERROR("execvp('%s'): %s\n", argv[0], strerror(errno));
	exit(1);
}

