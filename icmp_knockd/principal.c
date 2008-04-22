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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stropts.h>

#include "principal.h"
#include "netcom.h"
#include "icmp_knockd.h"
#include "util.h"
#include "log.h"

/*
 * Global variables
 */
extern pid_t child_pid;
extern pid_t parent_pid;
extern int ip_socket_fd;
extern int ip_pipe_in_fd;
extern int ip_pipe_out_fd;
extern int cmd_pipe_in_fd;
extern int cmd_pipe_out_fd;

/*
 * Local variables
 */
static char commands[MAX_CMDS][MAX_CMD_BUFF + 1];

/*
 * Principal process main
 */
void principal_main(void)
{
	char packet[MAX_PACKET + 1];
	ssize_t n_read; 
        fd_set read_fds;
	cmd_msg_t cmd_msg;
	int rc;

	/* close descriptors that we don't need */
	close(ip_pipe_in_fd);
	close(cmd_pipe_out_fd);

	signal(SIGINT, principal_exit);
	signal(SIGKILL, principal_exit);

	while(1) {
		FD_ZERO(&read_fds);
		FD_SET(ip_socket_fd, &read_fds);
		FD_SET(cmd_pipe_in_fd, &read_fds);

		if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0) {
			log_msg(LOG_ERROR, "select(): call failed ");
			exit(1);
		}

		if (FD_ISSET(ip_socket_fd, &read_fds)) {
			n_read = recvfrom(ip_socket_fd, packet, MAX_PACKET, 0, NULL, NULL);
			if (n_read > 42) {
				write(ip_pipe_out_fd, &n_read, sizeof(ssize_t));	/* First send the size of the packet to pipe */ 				
				write(ip_pipe_out_fd, packet, n_read);				/* Send packet to pipe */
			}
		}

		if (FD_ISSET(cmd_pipe_in_fd, &read_fds)) {
			n_read = read(cmd_pipe_in_fd, &cmd_msg, sizeof(cmd_msg_t));
			if (n_read == sizeof(cmd_msg_t))
				process_cmd(cmd_msg);
		}
	}
}

/*
 * Fork and execute command
 */
void exec_cmd(char *command)
{
	pid_t pid;
	int status;
	int ret;

	pid = fork();
	if (pid == 0) {
		ret = system(command);
		exit(ret);
	} else if (pid == -1) {
		log_msg(LOG_ERROR, "Error executing command %s ", command);
	} else {
		wait(&status);
		log_msg(LOG_WARN,  "Executed command %s ", command);
	}
}

/*
 * Process and execute command
 */
void process_cmd(cmd_msg_t cmd_msg) 
{
	int i;
	char cmd_buffer[MAX_CMD_BUFF + 1];
	char cmd_str[MAX_CMD_BUFF + 1];
	char *p;

	for (i = 0; i < MAX_CMDS; i++) {
		if (strlen(commands[i]) < 1)
			continue;

		strncpy(cmd_str, commands[i], MAX_CMD_BUFF);

		/* replace $IP from command with client IP address */
		p = strstr(cmd_str, IP_STR);
		if (p != NULL) {
			*p = '\0';
			p+=3;
			snprintf(cmd_buffer, MAX_CMD_BUFF, "%s%s%s",cmd_str, inet_ntoa(cmd_msg.ip), p);
			exec_cmd(cmd_buffer);
		} else {
			exec_cmd(cmd_str);
		}
	}
}

/*
 * Principal process Exit handler 
 */
void principal_exit(int sig)
{
	close(ip_socket_fd);
	close(ip_pipe_out_fd);
	close(cmd_pipe_in_fd);
	close_log();
	exit(0);
}

/*
 * Called from config file read routine to set command 
 */
int set_cmd(char *option, int oid)
{ 
	switch(oid) {
		case CMD1_OID:
			if (option != NULL)
				strncpy((char *)commands[CMD1_ID], option, MAX_CMD_BUFF);			
			break;
		case CMD2_OID:
			if (option != NULL)
				strncpy((char *)commands[CMD2_ID], option, MAX_CMD_BUFF);				
			break;
		case CMD3_OID:
			if (option != NULL)
				strncpy((char *)commands[CMD3_ID], option, MAX_CMD_BUFF);				
			break;
		case CMD4_OID:
			if (option != NULL)
				strncpy((char *)commands[CMD4_ID], option, MAX_CMD_BUFF);			
			break;
		default:
			return ERROR;
	}	

	return OK;
}
