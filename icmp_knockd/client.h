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
#ifndef _CLIENT_H_
#define _CLIENT_H_

typedef struct client_s {
	unsigned short  count;
	unsigned long   ip_addr;
	time_t timestamp;
	struct client_s *next;
}client_t;


int add_client(unsigned long ip_addr);
int del_client(unsigned long ip_addr);
client_t* find_client(unsigned long ip_addr);
void update_client(client_t *p);
void flush_clients(void);
void check_clients(int sig);


#endif /*_CLIENT_H_*/

