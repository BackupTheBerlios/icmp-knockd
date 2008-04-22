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
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include "xyssl/sha2.h"
#include "filter.h"
#include "icmp_knockd.h"
#include "log.h"
#include "util.h"

/*
 * Global variables
 */
filter_t filter;

/*
 * Init filter structure
 */
void init_filter(void) 
{
	memset(&filter, 0, sizeof(filter_t));
}

/*
 * For key auth we use a sha2 hash from client IP and secret passphrase,
 * this function check if client key hash match	
 */
int check_key(char *packet, unsigned short hdr_len)
{
	struct ip *ip_h; 
	char *client_key_hash;
	unsigned char  key_hash[SHA256_HASH_LEN];
	char  key_buffer[KEY_BUFF_LEN + 1];

	ip_h    = (struct ip*) (packet);
	snprintf(key_buffer, KEY_BUFF_LEN,"%s %s",filter.passphrase, inet_ntoa(ip_h->ip_src));
	sha2(key_buffer, strlen(key_buffer), key_hash, 0);
	client_key_hash = packet + hdr_len;

	if (memcmp(client_key_hash, key_hash, SHA256_HASH_LEN) == 0) {
		return OK;
	}

	return ERROR;
}

/*
 * Called from config file read routine to set filter options
 */
int set_filter(char *option, int oid)
{
	switch(oid) {
		case SECRET_KEY_OID:
			if (option != NULL) {
				strncpy(filter.passphrase, option, MAX_PASS_LEN);
				filter.auth = 1;
			}
			break;
		case PACKET_COUNT_OID:
			if (option != NULL)
				filter.pkt_count = atoi(option);
			break;
		case TIMEOUT_OID:
			if (option != NULL)
				filter.timeout = atoi(option);
			break;
		case PAYLOAD_LEN_OID:
			if (option != NULL)
				filter.payload_len = atoi(option);
			break;
		case IP_ID_OID:
			if (option != NULL)
				filter.ip.ip_id = atoi(option);
			break;
		case IP_LEN_OID:
			if (option != NULL)
				filter.ip.ip_len = atoi(option);
			break;
		case IP_ICMP_TYPE_OID:
			if (option != NULL)
				filter.icmp.icmp_type = atoi(option);
			break;
		case IP_ICMP_CODE_OID:
			if (option != NULL)
				filter.icmp.icmp_code = atoi(option);
			break;
		case IP_ICMP_ECHO_ID_OID:
			if (option != NULL)
				filter.icmp.echo.id = atoi(option);
			break;
		case IP_ICMP_ECHO_SEQ_OID:
			if (option != NULL)
				filter.icmp.echo.seq = atoi(option);
			break;
		default:
			return ERROR;
	}

	return OK;
}

/*
 * Check if packet pass filter options
 */
int check_filter(char *packet, unsigned len, struct in_addr *ip)
{
	struct ip *ip_h;            /* Packet ip header */
	struct icmp *icmp_h;	    /* Packet icmp header */
	unsigned short iph_len = 0; /* IP header length */
	unsigned short p_len = 0;   /* Payload length */
	unsigned short h_len = 0;   /* IP header len + icmp header len */

	ip_h    = (struct ip*) (packet);
	iph_len = (ip_h->ip_hl) * 4;
	icmp_h  = (struct icmp *) (packet + iph_len);
	h_len   = (iph_len + ICMP_MINLEN); 
	p_len   = (ntohs(ip_h->ip_len) - h_len);
	
	ip->s_addr = ip_h->ip_src.s_addr;

	if (filter.payload_len) {
		if (filter.payload_len != p_len)
			return ERROR;
	}

	if (filter.auth) {
		if (p_len < SHA256_HASH_LEN)
			return ERROR;

		if (check_key(packet, h_len) != OK) 
			return ERROR;
		
	}

	if (filter.ip.ip_id) {
		if (filter.ip.ip_id != ntohs(ip_h->ip_id))
			return ERROR;	
	}

	if (filter.ip.ip_len) {
		if (filter.ip.ip_len != ntohs(ip_h->ip_len))
			return ERROR;
	}

	if (filter.icmp.icmp_type) {
		if (filter.icmp.icmp_type != icmp_h->icmp_type)
			return ERROR;		
	}

	if (filter.icmp.icmp_code) {
		if (filter.icmp.icmp_code != icmp_h->icmp_code)
			return ERROR;
	}
	if (filter.icmp.echo.id) {
		if (filter.icmp.echo.id != ntohs(icmp_h->icmp_hun.ih_idseq.icd_id))
			return ERROR; 
	}

	if (filter.icmp.echo.seq) {
		if (filter.icmp.echo.seq != ntohs(icmp_h->icmp_hun.ih_idseq.icd_seq))
			return ERROR;
	}

	log_msg(LOG_DBG, "got ok packet from %s ", inet_ntoa(ip_h->ip_src));

	return OK;
}
