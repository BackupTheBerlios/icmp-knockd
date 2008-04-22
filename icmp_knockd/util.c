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
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <stdlib.h>

#include "util.h"
#include "filter.h"
#include "log.h"
#include "icmp_knockd.h"
#include "principal.h"

/*
 * Local variables
 */
static int   user_gid = NOBODY_GID;
static int   user_uid = NOBODY_UID;
static char  *conf_file = NULL;

static conf_op_t conf_op[]= {
   /* Option string,  Set function,       Option Id   */
	{"user",         &set_user,	              USER_OID},
	{"log_file",     &set_log,		      LOG_FILE_OID},
	{"log_level",    &set_log,           LOG_LEVEL_OID},
	{"passphrase",   &set_filter,       SECRET_KEY_OID},
	{"packet_count", &set_filter,     PACKET_COUNT_OID},
	{"timeout",      &set_filter,          TIMEOUT_OID},
	{"payload_len",  &set_filter,      PAYLOAD_LEN_OID},
	{"ip_id",        &set_filter,            IP_ID_OID},
	{"ip_len",       &set_filter,           IP_LEN_OID},
	{"icmp_type",    &set_filter,     IP_ICMP_TYPE_OID},
	{"icmp_code",    &set_filter,     IP_ICMP_CODE_OID},
	{"icmp_echo_id", &set_filter,  IP_ICMP_ECHO_ID_OID},
	{"icmp_echo_seq",&set_filter, IP_ICMP_ECHO_SEQ_OID},
	{"cmd1",		 &set_cmd,                CMD1_OID},
	{"cmd2",         &set_cmd,                CMD2_OID},
	{"cmd3",         &set_cmd,                CMD3_OID},
	{"cmd4",         &set_cmd,                CMD4_OID},
   /*           Add new options here                   */
	{NULL, NULL, LAST_OID}
};

/*
 * Set config file
 */
void set_conf_file(char *file)
{
	if (file != NULL) {
		conf_file = file;
	} else {
		conf_file = CONF_FILE;
	}
}

/*
 * Open config file
 */
FILE *open_conf_file(void)
{
	return fopen(conf_file, READ_FILE_MODE);	
}

/*
 * String remove spaces
 */
char* str_rm_blank(char *str)
{
	char *p = str;

	while(*p == ' ') {
		p++;
	}

	return p;
}

/*
 *	String remove "\n"
 */
void str_rm_newline(char *str)
{
	char *p = str;

	while((*p != '\n') && p != NULL) {
		p++;
		if(*p == '\n') {
			*p = '\0';
			break;
		}
	}
}

/*
 * Return configuration option value from config file
 */
char *get_conf_option(char *option)
{
	static char line[MAX_CONF_LINE + 1];
	char *p = NULL;
	FILE *fp;

	fp = open_conf_file();
	if (fp == NULL) {
		fprintf(stderr, "Unable to open conf file %s \n", conf_file);
		exit(1);
	}

	bzero(line, MAX_CONF_LINE);
	while ( fgets(line, MAX_CONF_LINE, fp) != NULL) {
		if (line[0] == '#') {
			bzero(line, MAX_CONF_LINE);
			continue;
		}
		p = strstr(line, option);
		if (p != NULL) {
			p = strchr(line, '=');
			if (p != NULL) {
				p++;
				p = str_rm_blank(p);
				str_rm_newline(p);		
				break;
			}
			break;
		}
	}

	fclose(fp);
	return p;
}

/*
 * Parse configuration file
 */
void parse_conf(void)
{
	int i;
	char *option_val;

	printf("Reading configuration file\n");
	for (i = 0; conf_op[i].option != NULL; i++) {
		option_val = get_conf_option(conf_op[i].option);
		printf("  - option %s: %s \n",conf_op[i].option, option_val);
		conf_op[i].set_op(option_val, conf_op[i].oid);
	}

}

/*
 * Called from config file read routine to set user
 */
int set_user(char *option, int oid)
{
	struct passwd *pw;
	
	if (option == NULL)
		return ERROR;

	while((pw = getpwent()) != NULL) {
		if (strcmp(pw->pw_name, option) == 0) {
			user_gid = pw->pw_gid;
			user_uid = pw->pw_uid;
			break;
		}
	}

	return OK;
}

/*
 * drop_privleges
 */
int drop_privleges(void)
{
	int rc = ERROR;

	rc = setgid(user_gid);
	if (rc != OK) 
		return ERROR;


	rc = setuid(user_uid);
	if (rc != OK) 
		return ERROR;

	return rc;
}




