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
#ifndef _PRINCIPAL_H_
#define _PRINCIPAL_H_

#include <netinet/in.h>

#define IP_STR	"$IP"
#define MAX_CMD_BUFF	215

typedef enum {
	CMD1_ID = 0,
	CMD2_ID,
	CMD3_ID,
	CMD4_ID,
	/* add new cmds */
	MAX_CMDS
} cmd_id_t;

typedef struct cmd_msg_s {
	struct in_addr ip;
	unsigned short msg_id;	/* Not Used */
} cmd_msg_t;

void principal_main(void);
void principal_exit(int sig);
void process_cmd(cmd_msg_t cmd_msg);
int set_cmd(char *option, int oid);

#endif /*_PRINCIPAL_H_*/

