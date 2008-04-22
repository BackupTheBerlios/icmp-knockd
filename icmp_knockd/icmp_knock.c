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
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "icmp_knock.h"
#include "xyssl/sha2.h"

static const char version[]="version-current";
static struct {
	unsigned char hash[SHA256_HASH_LEN];
	int used;
} key;
static	struct in_addr 	ip_nat_addr;

/*
 * IP Family checksum routine (from UNP)
 */
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;		/* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer;	/* assumes u_short == 16 bits */

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */

    sum = 0;
    while (nbytes > 1) {
	sum += *ptr++;
	nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
	oddbyte = 0;		/* make sure top half is zero */
	*((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
	sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits.
     */

    sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
    sum += (sum >> 16);		/* add carry */
    answer = ~sum;		/* ones-complement, then truncate to 16 bits */
    return (answer);
}

/*
 * Generate sha2 256 bits hash 
 */
void generate_key(char *passphrase, struct in_addr *ip_addr)
{
	char key_buffer[KEY_BUFF_LEN + 1];

	if (ip_nat_addr.s_addr) {
		snprintf(key_buffer, KEY_BUFF_LEN,"%s %s", passphrase, inet_ntoa(ip_nat_addr));
		sha2(key_buffer, strlen(key_buffer), key.hash, 0);
	} else {
		snprintf(key_buffer, KEY_BUFF_LEN,"%s %s", passphrase, inet_ntoa(*ip_addr));
		sha2(key_buffer, strlen(key_buffer), key.hash, 0);
	}
}

/*
 * Assembly packet and sendit to the wires
 */
ssize_t send_packet(int sock, unsigned src_ip, unsigned dst_ip, unsigned short ip_id, unsigned char type, 
				unsigned char code, unsigned short echo_id, unsigned short echo_seq, unsigned int p_len)
{
	struct sockaddr_in sin;		/* IP address information */
	ssize_t	n_send = 0;	
	unsigned int pkt_len = 0;		/* Packet total lenght */
	char	*payload;		
	char	*pktb; 				/* Packet buffer */
	struct  packet_h *packet;	/* Packet headers */

    /* Setup the sin struct with addressing information */
    sin.sin_family = AF_INET;	    
    sin.sin_addr.s_addr = dst_ip;	
	pkt_len = HDR_LEN + p_len;

	/* Alloc memory for packet */
	pktb = malloc(sizeof(char) * pkt_len + 1);
	if (pktb == NULL) {
		fprintf(stderr, "Failed alloc memory for packet\n");
		exit(1);
	}

	/* Fill packet with 'A' */
	memset(pktb, 'A', pkt_len);
	packet = (struct  packet_h*) pktb;
	/* Copy key to payload */
	if (p_len) {
		payload = pktb + HDR_LEN;
		if (key.used && (p_len > (SHA256_HASH_LEN + 1))) 
			memcpy(payload, key.hash, SHA256_HASH_LEN);
	}
    /* Fill in all the ICMP header information */
    packet->icmp_h.icmp_type 	= type;	
    packet->icmp_h.icmp_code	= code;
    packet->icmp_h.icmp_cksum	= 0;
    packet->icmp_h.echo.id 		= htons(echo_id);
    packet->icmp_h.echo.seq		= htons(echo_seq);

    /* ICMP header checksum */
    packet->icmp_h.icmp_cksum = in_cksum((unsigned short *) &packet->icmp_h, (ICMP_MINLEN + p_len));

    /* Fill in all the IP header information */
    packet->ip_h.ip_v   = IP_HDR_VER;		/* 4-bit Version */
    packet->ip_h.ip_hl  = IP_HDR_HL;			/* 4-bit Header Length */
    packet->ip_h.ip_tos = IP_HDR_TOS;		/* 8-bit Type of service */
    packet->ip_h.ip_len = htons(pkt_len);	/* 16-bit Total length */
    packet->ip_h.ip_id  = htons(ip_id);		/* 16-bit ID field */
    packet->ip_h.ip_off = IP_HDR_OFF;		/* 13-bit Fragment offset */
    packet->ip_h.ip_ttl = IP_HDR_TTL;		/* 8-bit Time To Live */
    packet->ip_h.ip_p   = IPPROTO_ICMP;		/* 8-bit Protocol */
    packet->ip_h.ip_sum = 0;					/* 16-bit Header checksum (filled in below) */
    packet->ip_h.ip_src.s_addr = src_ip;		/* 32-bit Source Address */
    packet->ip_h.ip_dst.s_addr = dst_ip;		/* 32-bit Destination Address */

    /* IP header checksum */
    packet->ip_h.ip_sum = in_cksum((unsigned short *) &packet->ip_h, 20);

    /* Packet is sent to the wire */
    n_send = sendto(sock, pktb, pkt_len, 0, (struct sockaddr *) &sin, sizeof(sin));

	free(pktb);

    return n_send;
}

/*
 * Get ip addres of specified interface
 */
int get_ifip(char *ifname,  struct in_addr *ip) 
{
    struct ifreq ifr;
    register struct sockaddr_in *sin;
    int fd;

    /* create dummy socket to perform an ioctl upon */
    fd = socket(PF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        return (-1);
    }

    sin = (struct sockaddr_in *) &ifr.ifr_addr;

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(fd, SIOCGIFADDR, (int8_t *) & ifr) < 0) {
        close(fd);
        return (-1);
    }
    close(fd);
	ip->s_addr = sin->sin_addr.s_addr;

    return OK;
}

/*
 * Resolv host to ip address
 */
int resolve_address(char *hostname, struct in_addr *ip) 
{
	struct hostent *host;
	unsigned long ip_addr;

	if ((host = gethostbyname(hostname)) == NULL) {
		return -1;
	} else {
		memcpy((char*)&ip_addr,host->h_addr, host->h_length);
		ip->s_addr = ip_addr;
	}

	return 0;
}

/*
 * Print help
 */
void show_usage(char *name)
{
	fprintf(stderr,"%s [-s size] [-c count] [-p] [-i interface or address] [-n nat address]\n"
			"\t\t[-d IP id][-T ICMP type] [-C ICMP code] [-I ICMP echo id]\n" 
			"\t\t[-S ICMP echo sequence] [-h] destination\n"
"Copyright (C) 2008 research@labs.b33r.net %s\n"
"Options:\n"
"  -s size\t\t: packet payload size in bytes (default : 56)\n"
"  -c count\t\t: number of packets to be sent (default : 1)\n"
"  -p\t\t\t: use passphrase (default : no)\n"
"  -i interface | address: outgoing interface, or set source IP address (default : ppp0)\n"
"  -n nat address\t: NAT IP address\n"
"  -d IP id\t\t: set packet IP id (default : 57005)\n"
"  -T ICMP type\t\t: set ICMP type (default : 8)\n"
"  -C ICMP code\t\t: set ICMP code (default : 0)\n"
"  -I ICMP echo id\t: set ICMP echo id (default : 170)\n"
"  -S ICMP echo sequence\t: set ICMP echo sequence (default : 187)\n"
"  -h\t\t\t: show help (this page)\n", name, version);

}

int main(int argc, char *argv[])
{

	char	*passphrase = NULL;	/* Secret passphrase */
	char	*ifname = NULL;			/* Interface name */
	unsigned short	ip_id = IP_HDR_ID;		/* IP Header packet id */
	unsigned  char 	icmp_type = ICMP_TYPE;	/* ICMP type */
	unsigned  char 	icmp_code = ICMP_CODE;	/* ICMP code*/
	unsigned short  icmp_echo_id = ICMP_ECHO_ID; 	/*ICMP echo id */
	unsigned short  icmp_echo_seq = ICMP_ECHO_SEQ; /*ICMP echo seq */
	struct in_addr 	ip_src, ip_dst;		/* Source IP address Destination IP address */
	ssize_t	n_send 	= 0;				/* Number of bytes sent to the wire */
	unsigned int p_len = PAYLOAD_SIZE;		/* Payload size */
	int		count = 1;	/* Number of packets */
	int 	sd;			/* Socket Descriptor */
	int  	i;			
	char 	c;

	key.used = 0;
	ip_nat_addr.s_addr = 0;
	ip_src.s_addr = 0;

	if (getuid() != 0) {
		fprintf(stderr, "Run me as root please\n");
		return 1;
	}

	while ((c = getopt(argc, argv, "s:c:pi:n:d:T:C:I:S:h")) != EOF) {		
		switch (c) {
			case 's':
				p_len =  atoi(optarg);
				break;
			case 'c':
				count =  atoi(optarg);
				break;
			case 'p':
				key.used++;
				break;
			case 'i':
				if ((ip_src.s_addr = inet_addr(optarg)) == -1) {
					ifname = (char*) malloc (sizeof(optarg));
					strncpy(ifname, optarg, IFNAMSIZ);
					ip_src.s_addr = 0;
				}
				break;
			case 'n':
				if ((ip_nat_addr.s_addr = inet_addr(optarg)) == -1) {
					fprintf(stderr,"Invalid IP address %s\n", optarg);
					return 1;
				}
				break;
			case 'd':
				ip_id = atoi(optarg);
				break;
			case 'T':
				icmp_type = atoi(optarg);
				break;
			case 'C':
				icmp_code = atoi(optarg);
				break;
			case 'I':
				icmp_echo_id = atoi(optarg);
				break;
			case 'S':
				icmp_echo_seq = atoi(optarg);
				break;
			case 'h':
				show_usage(argv[0]);
				return 0;
                break;
			default:
				show_usage(argv[0]);
				return 1;
				break;
        	}
	}

	if (ifname == NULL) 
		ifname = DEFAULT_IF;

	if (p_len > (MAX_PACKET - HDR_LEN)) {
		fprintf(stderr,"Packet size larger than %d bytes\n",(MAX_PACKET - HDR_LEN));
		return 1;
	}

	if (key.used) {
		if (p_len < (SHA256_HASH_LEN + 1)) {
			fprintf(stderr,"Packet size smaller than %d bytes\n",(SHA256_HASH_LEN + 1));
			return 1;
		}

		passphrase = getpass("Enter Passphrase: ");
	}

	if (argv[optind] == NULL) {
		show_usage(argv[0]);
		return 1;
	}

	/* Get source IP address */
	if (!ip_src.s_addr)	{
		if (get_ifip(ifname, &ip_src) < 0) {
			fprintf(stderr,"Failed to get interface %s IP address\n", ifname);
			return 1;
		}
	}

	if (resolve_address(argv[optind], &ip_dst) < 0) {
		printf("Failed to resolve %s\n", argv[optind]);
		return 1;
	}

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return 1;
	}

	if (passphrase != NULL)
		generate_key(passphrase, &ip_src);

	printf("Knocking on   : %s\n", inet_ntoa(ip_dst));
	printf("Interface     : %s\n", ifname);
	printf("Using address : %s\n", inet_ntoa(ip_src));
	if (ip_nat_addr.s_addr)
		printf("NAT address   : %s\n", inet_ntoa(ip_nat_addr));
	printf("Sending %d packets:\n",count);

	for (i = 0; i < count; i++) {
		n_send = send_packet(sd, ip_src.s_addr, ip_dst.s_addr, ip_id, icmp_type, icmp_code, icmp_echo_id, 
							icmp_echo_seq, p_len);
		if (n_send > 0) {
			printf("- %d bytes sent on wires\n", n_send);
		} else {
			fprintf(stderr,"- 0 bytes sent on wires\n");
			fprintf(stderr,"Failed to send packet\n");
			exit(1);
		}
	}

	close(sd);
	return 0;
}

