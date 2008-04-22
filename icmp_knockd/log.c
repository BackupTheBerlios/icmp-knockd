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
/*TODO: Rewrite log system this buggy */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "icmp_knockd.h"
#include "util.h"

/*
 * Local variables
 */
static char log_file[MAX_LOG_FILE_PATH + 1];
static int log_fd = ERROR;
static log_level_t log_level =  LOG_INF;


/*
 * Init log system, open log file
 */
int init_log(void) 
{
	log_fd = open(log_file, O_RDWR | O_APPEND | O_CREAT, 0600);
	if (log_fd < 0) {
		return ERROR;
	}

	return OK;
}

/*
 * Close log file descriptor
 */
void close_log(void) 
{
	close(log_fd);
}

/*
 * Log message function 
 */
void log_msg(log_level_t level, char *fmt, ...)
{
	char log_buffer[MAX_LOG_BUFFER + 1];
	char *date;
	unsigned int len;
	va_list args;
	time_t now = time(NULL);

	if (log_level >= level) {
		bzero(log_buffer, MAX_LOG_BUFFER);	
		va_start(args, fmt);
		/* Log time */
		date = ctime(&now);
		date[strlen(date) - 1] = ' '; /* Remove \n */
		snprintf(log_buffer, MAX_LOG_BUFFER, "%s PID %d - ", date, getpid());
		write(log_fd, log_buffer, strlen(log_buffer)	);
		/* Log message */
		bzero(log_buffer, MAX_LOG_BUFFER);	
		vsnprintf(log_buffer, MAX_LOG_BUFFER, fmt, args);
		write(log_fd, log_buffer, strlen(log_buffer));
		write(log_fd, "\n", 1);
		va_end(args);
	}
}

/*
 * Called from config file read routine to set log options
 */
int set_log(char *option, int oid)
{
	switch(oid) {
		case LOG_FILE_OID:
			bzero(log_file, MAX_LOG_FILE_PATH);
			if(option == NULL) {
				strncpy(log_file, DEFAULT_LOG_PATH, MAX_LOG_FILE_PATH);
			} else {
				strncpy(log_file, option, MAX_LOG_FILE_PATH);
			}
			break;
		case LOG_LEVEL_OID:
			if(option != NULL) 
				log_level = atoi(option);
			break;

		default:
			return ERROR;
	}

	return OK;
}

