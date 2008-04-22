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
#ifndef _LOG_H_
#define _LOG_H_

#define DEFAULT_LOG_PATH "/var/log/icmp-knockd.log"
#define MAX_LOG_FILE_PATH  512
#define MAX_LOG_BUFFER	   512
#define MAX_CONF_LINE	   80
#define MAX_CONF_FILE_PATH 256


typedef enum {
	LOG_ERROR = 0,
	LOG_WARN,
	LOG_INF,
	LOG_DBG
}log_level_t;

int init_log(void);
void close_log(void);
int set_log(char *option, int oid);
void log_msg(log_level_t level, char *fmt, ...);

#endif /*_LOG_H_*/
