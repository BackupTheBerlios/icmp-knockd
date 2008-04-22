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
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

#include "icmp_knockd.h"
#include "client.h"
#include "filter.h"
#include "log.h"
#include "principal.h"

/*
 * Global variables
 */
extern int cmd_pipe_out_fd;

/*
 * Local variables
 */
static client_t  *clients_list = NULL;

/*
 * Alloc memory for client structure
 */
client_t* alloc_client(void)
{
	return (client_t*) malloc(sizeof(client_t));
}

/*
 * Free memory for client structure
 */
void free_client(client_t *p)
{
	free(p);
}

/*
 * Insert client in front of list 
 */
void ins_client(client_t *p)
{
	p->next = clients_list; 
	clients_list = p;
}

/*
 * Add new client in client list  
 */
int add_client(unsigned long ip_addr)
{
	client_t *p;
	struct timeval now;
	struct timezone tz;

	p = alloc_client();
	if (p == NULL)
		return ERROR;

	gettimeofday(&now, &tz);

	p->ip_addr = ip_addr;
	p->count = 1;
	p->timestamp = now.tv_sec;

	ins_client(p);

	return OK;
}

/*
 * Delete client from client list  
 */
int del_client(unsigned long ip_addr)
{
	client_t *p;
	client_t *prev = NULL;

	for (p = clients_list; p != NULL; p=p->next) {
		if (p->ip_addr == ip_addr) {
			if (prev == NULL) {
				clients_list = p->next;
			} else {
				prev->next = p->next;
			}
			free_client(p);
			return OK;
		}
		prev = p;	
	}

	return ERROR;
}

/*
 * Find client by IP addres  
 */
client_t* find_client(unsigned long ip_addr)
{
	client_t *p;

	for (p = clients_list; p != NULL; p=p->next) {
		if (p->ip_addr == ip_addr)
			return p;
	}

	return NULL;
}

/*
 * Update client entry when a new packet is received  
 */
void update_client(client_t *p)
{
	struct timeval now;
	struct timezone tz;

	gettimeofday(&now, &tz);
	p->count++;
	p->timestamp = now.tv_sec; 
}

/*
 * Destroy clients list 
 */
void flush_clients(void) 
{
	client_t *p;

	p = clients_list;
	
	while(p != NULL) {
		clients_list = p->next;
		free_client(p);
		p = clients_list;
	}

	clients_list = NULL;
}

/*
 * This function check if clients in the lists have passed the rules,
 * and if clients are ok then send msg to principal process to execute
 * command.
 */
void check_clients(int sig) 
{
	struct timeval now;
	struct timezone tz;
	cmd_msg_t cmd_msg;
	client_t *p;

	gettimeofday(&now, &tz);

	for (p = clients_list; p != NULL; p=p->next) {
		if ((now.tv_sec - p->timestamp) > filter.timeout) { 
			if (p->count == filter.pkt_count) {
				cmd_msg.ip.s_addr = p->ip_addr;
				write(cmd_pipe_out_fd, &cmd_msg, sizeof(cmd_msg_t));
			}
			if (del_client(p->ip_addr) != OK)
				log_msg(LOG_WARN, "Failed to delete client from list");	
		}			
	}
}
