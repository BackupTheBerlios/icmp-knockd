/***************************************************************************
 *   Copyright (C) 2008 by vaicebine                                       *
 *    - vaicebine@gmail.com                                                *   
 *    - research@labs.b33r.net                                             *
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "icmp_knockd.h"
#include "principal.h"
#include "agent.h"
#include "log.h"
#include "util.h"
#include "netcom.h"


/*
 * Global variables
 */
pid_t child_pid;
pid_t parent_pid;
int ip_socket_fd;
int ip_pipe_in_fd;
int ip_pipe_out_fd;
int cmd_pipe_in_fd;
int cmd_pipe_out_fd;

/*
 * Local variables
 */
static const char version[]="version-current";

/*
 * Show program version
 */
void show_version(void)
{
	printf("%s \n", version);
}

/*
 * Show Usage
 */
void usage(char *name)
{
	fprintf(stderr, "usage: %s [-c file] [-d] [-v] [-h]\n"
					"Options:\n"
					"\t-c file		:config file\n"
					"\t-d		:daemon mode\n"
					"\t-v		:show version\n"
					"\t-h		:show usage (this page)\n"
					"Copyright (C) 2008 research@labs.b33r.net\n\n", name);
}

int main(int argc, char *argv[])
{
	char  *file = NULL;
	char  c;
	int   daemon = 0;
	int   rc = OK;


	if (getuid() != 0) {
		fprintf(stderr, "Run me as root please\n");
		return 1;
	}

	while ((c = getopt(argc, argv, "c:dvh")) != EOF) {
		
		switch (c) {
			case 'c':
				file = strdup(optarg);
				if (file == NULL) {
					fprintf(stderr, "Failed to alloc memory\n");
					exit(1);					
				}
                break;
			case 'd':
				daemon++;
				break;
			case 'v':
				show_version();
				exit(0);
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			default:
				usage(argv[0]);
				exit(1);
        	}
	}

	init_filter();
	set_conf_file(file);
	parse_conf();

	rc = init_log();
	if (rc != OK) {
		fprintf(stderr, "Failed to open log file \n");
		return 1;
	}

	ip_socket_fd = ip_socket();
	if (ip_socket_fd < 0) {
		fprintf(stderr, "Failed to create raw socket \n");
		return 1;
	}

	rc = create_pipe(&ip_pipe_in_fd, &ip_pipe_out_fd);
	if (rc != OK) {
		fprintf(stderr, "Failed to create net pipe \n");
		return 1;
	}

	rc = create_pipe(&cmd_pipe_in_fd, &cmd_pipe_out_fd);
	if (rc != OK) {
		fprintf(stderr, "Failed to create cmd pipe \n");
		return 1;
	}

	log_msg(LOG_WARN,  "Icmp Knock daemon %s started", version);

	/* Go daemon mode */
	if (daemon) {
		switch (fork()) {
			case  -1:	
				fprintf(stderr, "fork(): call failed \n"); 
				return 3;
			case   0: 	
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				if (setsid() == -1) {
					exit(1);
				}
				break;
			default :	 	
				return 0;
		}
	}

	parent_pid = getpid();	
	child_pid = fork();

	switch (child_pid) {
		case  -1:	
			fprintf(stderr, "fork(): call failed \n"); 
			return 1;
			break;

		case   0: 	
			agent_main();			
			break;

		default :	 	
			principal_main();		
			break;
	}

	return OK;
}

