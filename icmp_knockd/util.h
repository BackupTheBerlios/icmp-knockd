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
#ifndef _UTIL_H_
#define _UTIL_H_

#define NOBODY_UID 98 
#define NOBODY_GID 99
#define CONF_FILE "/usr/local/etc/icmp_knockd.conf"
#define READ_FILE_MODE "r"
#define WRITE_FILE_MODE "w"

typedef struct conf_op_s {
	char *option;
	int (*set_op)(char *option, int oid);
	int  oid;
} conf_op_t;

typedef enum {
	USER_OID = 0,
	LOG_FILE_OID,
	LOG_LEVEL_OID,
	SECRET_KEY_OID, 
	PACKET_COUNT_OID, 
	TIMEOUT_OID, 
	PAYLOAD_LEN_OID,
	IP_ID_OID,
	IP_LEN_OID,
	IP_ICMP_TYPE_OID,
	IP_ICMP_CODE_OID,
	IP_ICMP_ECHO_ID_OID,
	IP_ICMP_ECHO_SEQ_OID,
	CMD1_OID,
	CMD2_OID,
	CMD3_OID,
	CMD4_OID,
	/*add new options here*/
	LAST_OID
} op_id_t;


void set_conf_file(char *file);
void parse_conf(void);
int set_user(char *option, int oid);
int drop_privleges(void);
ssize_t pipe_send(void *buf, size_t count, int fd);

#endif /*_UTIL_H_*/

