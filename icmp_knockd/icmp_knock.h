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
#ifndef _ICMP_KNOCK_H_
#define _ICMP_KNOCK_H_

struct packet_h {
	struct ip ip_h;				/* Packet ip header */
	struct  {
		unsigned char  icmp_type;
		unsigned char  icmp_code;
		unsigned short icmp_cksum;
		struct {
			unsigned short id;
			unsigned short seq;
		}echo;
	}icmp_h; /*ICMP header */
};

/* ICMP header len */
#define	ICMP_MINLEN		8
/* IP header len + ICMP header len */
#define HDR_LEN		((IP_HDR_HL*4) + ICMP_MINLEN) 
/* IP header default options */
#define IP_HDR_VER		4
#define IP_HDR_HL		5
#define IP_HDR_TTL		64
#define IP_HDR_TOS		0
#define IP_HDR_OFF		0
#define IP_HDR_ID		0xdead

/* ICMP header default options */
#define ICMP_TYPE		8
#define ICMP_CODE		0
#define ICMP_ECHO_ID	0x00aa
#define ICMP_ECHO_SEQ	0x00bb


#define PAYLOAD_SIZE	56
#define PAYLOAD_MIN_SIZE 32	
#define PAYLOAD_MAX_SIZE 512	

#define  MAX_KEY_LEN 512
#define  KEY_BUFF_LEN (MAX_KEY_LEN + 16)

#define	DEFAULT_IF	"ppp0";
#define  MAX_PACKET   65535
#ifndef OK
#define OK	0
#endif

#endif /*_ICMP_KNOCK_H_*/


