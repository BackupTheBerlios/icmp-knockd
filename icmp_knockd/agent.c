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
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <pthread.h>

#include "agent.h"
#include "icmp_knockd.h"
#include "log.h"
#include "filter.h"
#include "client.h"
#include "netcom.h"
#include "util.h"


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
extern filter_t filter; 

/*
 * Local variables
 */
static sigset_t newmask;
static sigset_t oldmask;
static sigset_t zeromask;


/*
 * Agent process main
 */
int agent_main(void)
{
	int rc = 0;

	/* close descriptors that we don't need */
	close(ip_pipe_out_fd);
	close(cmd_pipe_in_fd);
	close(ip_socket_fd);

	rc = drop_privleges();
	if (rc != OK) {
		log_msg(LOG_ERROR, "Failed to drop privleges");
		exit(2);
	}

	signal(SIGINT, agent_exit);
	signal(SIGKILL, agent_exit);
	signal(SIGALRM, check_clients);

	set_timer();

	do_pipe_read(ip_pipe_in_fd);

	return OK;
}

/*
 * Read packets from IP pipe
 */
void do_pipe_read(int pipe_in_fd) 
{
	char *packet;
	ssize_t n_read;
	ssize_t p_size;

	while(1) {
		n_read = read(ip_pipe_in_fd, &p_size, sizeof(ssize_t));
		if (n_read > 0) {
			packet = (char*) malloc (sizeof(char)* p_size);
			if (packet != NULL) {
				n_read = read(ip_pipe_in_fd, packet, p_size);
				if (n_read > 42) {
					process_packet(packet, n_read);
				}
				free(packet);		
			}
		}
	}
} 

/*
 * Set SIGALRM interrupt timer
 */
void set_timer(void) 
{
	struct itimerval alrm_tv;
	
	alrm_tv.it_interval.tv_sec  = SIGALRM_TV_SEC;
	alrm_tv.it_interval.tv_usec = SIGALRM_TV_USEC;
	alrm_tv.it_value.tv_sec     = SIGALRM_TV_SEC;
	alrm_tv.it_value.tv_usec    = SIGALRM_TV_USEC;
	
	if (setitimer(ITIMER_REAL, &alrm_tv, NULL) == -1) {
		log_msg(LOG_ERROR, "Failed to set timer ");
		exit(1);
	}
}

/*
 * Block SIGALRM
 */
void siglock(void)
{
	/* Initialize the signal sets */
	sigemptyset(&newmask); 
	sigemptyset(&zeromask);
	/* Add the signal to the set */
	sigaddset(&newmask, SIGALRM);
	/* Block SIGALRM and save current signal mask in set variable 'oldmask'*/
	sigprocmask(SIG_BLOCK, &newmask, &oldmask);
}

/*
 * Unblock SIGALRM 
 */
void sigunlock(void)
{
	/* Now allow all signals and pause */
	sigsuspend(&zeromask);
	/* Resume to the original signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

/*
 * Process ICMP packets 
 */
void process_packet(char *packet, unsigned int len)
{
	struct in_addr client_ip;
	client_t *p;

	siglock();			
	if (check_filter(packet, len, &client_ip) == OK) {
		if ((p = find_client(client_ip.s_addr)) == NULL) {
			log_msg(LOG_INF, "Add client: %s", inet_ntoa(client_ip));
			add_client(client_ip.s_addr);
		} else {
			log_msg(LOG_INF, "Update client: %s", inet_ntoa(client_ip));
			update_client(p);
		}		
	} else {
			log_msg(LOG_DBG, "Check filter failed for %s", inet_ntoa(client_ip));
	}
	sigunlock();
}

/*
 * Agent process Exit handler 
 */
void agent_exit(int sig)
{
	close(ip_pipe_in_fd);
	close(cmd_pipe_out_fd);
	close_log();
	flush_clients(); 
	exit(0);
}
