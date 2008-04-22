/***************************************************************************
 *   Copyright (C) 2008 by vaicebine                                       *
 *   vaicebine@gmail.com                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "netcom.h"
#include "icmp_knockd.h"

/* TODO: change to pcap ? */
/*
 * Create RAW socket
 */
int ip_socket(void) 
{
	return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

/*
 * Create pipe
 */
int create_pipe(int *pipe_in_fd, int *pipe_out_fd)
{
	int pipe_fds[2];
	int rc = OK;

	rc = pipe(pipe_fds);
	if (rc < 0)
		return ERROR;

	*pipe_in_fd = pipe_fds[0];
	*pipe_out_fd = pipe_fds[1];

	return rc;
}


