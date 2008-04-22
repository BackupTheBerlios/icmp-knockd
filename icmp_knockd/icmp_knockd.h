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
#ifndef _ICMP_KNOCKD_H_
#define _ICMP_KNOCKD_H_

#ifndef OK
#define OK	0
#endif 

#ifndef ERROR
#define ERROR -1
#endif 

extern pid_t child_pid;
extern pid_t parent_pid;
extern int ip_socket_fd;
extern int ip_pipe_in_fd;
extern int ip_pipe_out_fd;
extern int cmd_pipe_in_fd;
extern int cmd_pipe_out_fd;

#endif /*_ICMP_KNOCKD_H_*/


