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
#ifndef _FILTER_H_
#define _FILTER_H_

#include <netinet/in.h>

#define  MAX_PASS_LEN 512
#define  KEY_BUFF_LEN (MAX_PASS_LEN + 16)

typedef struct _filter_s {
	struct {
			unsigned short ip_id;
			unsigned short ip_len;
			struct in_addr ip_dst;
			struct in_addr ip_src;		
	} ip; /*IP header filter options */
	struct {
		unsigned char icmp_type;
		unsigned char icmp_code;
		struct {
			unsigned short id;
			unsigned short seq;
		} echo;
	} icmp; /*ICMP header filter options */
	unsigned short payload_len;
	char passphrase[MAX_PASS_LEN + 1];
	int  auth; /* 1: if use secret key 0: not use secret key */
	unsigned short pkt_count; /* Number of expected packets */
	unsigned short timeout; 
}filter_t;

extern filter_t filter; 	

void init_filter(void);
int set_filter(char *option, int oid);
int check_filter(char *packet, unsigned len, struct in_addr *ip);

#endif /*_FILTER_H_*/

