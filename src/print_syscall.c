/* print_syscall --  functions to print a strace-like log of syscalls */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "print_syscall.h"
#include "sockets.h"
#include "simterpose.h"
#include "sysdep.h"
#include <xbt.h>

#include <stdio.h>
#include </usr/include/linux/sched.h>   /* For clone flags */

/** @brief print a strace-like log of accept syscall */
void print_accept_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	accept_arg_t arg = &(sysarg->accept);

	int domain = get_domain_socket(proc, arg->sockfd);
	// fprintf(proc->strace_out,"[%d] accept(", pid);
	fprintf(proc->strace_out, "accept(");

	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	if (domain == 2) {            // PF_INET
		fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
				inet_ntoa(arg->sai.sin_addr));
	} else if (domain == 1) {     //PF_UNIX
		fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
	} else if (domain == 16) {    //PF_NETLINK
		fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
	} else {
		fprintf(proc->strace_out, "{sockaddr unknown}, ");
	}

	fprintf(proc->strace_out, "%d", arg->addrlen);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of connect syscall */
void print_connect_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	connect_arg_t arg = &(sysarg->connect);

	int domain = get_domain_socket(proc, arg->sockfd);

	// fprintf(proc->strace_out,"[%d] connect(", pid);
	fprintf(proc->strace_out, "connect(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	if (domain == 2) {
		fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
				inet_ntoa(arg->sai.sin_addr));
	} else if (domain == 1) {     //PF_UNIX
		fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
	} else if (domain == 16) {    //PF_NETLINK
		fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
	} else {
		fprintf(proc->strace_out, "{sockaddr unknown}, ");
	}
	fprintf(proc->strace_out, "%d", arg->addrlen);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of bind syscall */
void print_bind_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	bind_arg_t arg = &(sysarg->bind);
	int domain = get_domain_socket(proc, arg->sockfd);

	// fprintf(proc->strace_out,"[%d] bind(", pid);
	fprintf(proc->strace_out, "bind(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	if (domain == 2) {
		fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
				inet_ntoa(arg->sai.sin_addr));
	} else if (domain == 1) {     //PF_UNIX
		fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
	} else if (domain == 16) {    //PF_NETLINK
		fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
	} else {
		fprintf(proc->strace_out, "{sockaddr unknown}, ");
	}
	fprintf(proc->strace_out, "%d", arg->addrlen);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of socket syscall */
void print_socket_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	socket_arg_t arg = &(sysarg->socket);

	// fprintf(proc->strace_out,"[%d] socket(",pid);
	fprintf(proc->strace_out, "socket(");
	switch (arg->domain) {
	case 0:
		fprintf(proc->strace_out, "PF_UNSPEC, ");
		break;
	case 1:
		fprintf(proc->strace_out, "PF_UNIX, ");
		break;
	case 2:
		fprintf(proc->strace_out, "PF_INET, ");
		switch (arg->type) {
		case 1:
			fprintf(proc->strace_out, "SOCK_STREAM, ");
			break;
		case 2:
			fprintf(proc->strace_out, "SOCK_DGRAM, ");
			break;
		case 3:
			fprintf(proc->strace_out, "SOCK_RAW, ");
			break;
		case 4:
			fprintf(proc->strace_out, "SOCK_RDM, ");
			break;
		case 5:
			fprintf(proc->strace_out, "SOCK_SEQPACKET, ");
			break;
		case 6:
			fprintf(proc->strace_out, "SOCK_DCCP, ");
			break;
		case 10:
			fprintf(proc->strace_out, "SOCK_PACKET, ");
			break;
		default:
			fprintf(proc->strace_out, "TYPE UNKNOWN (%d), ", arg->type);
			break;
		}
		switch (arg->protocol) {
		case 0:
			fprintf(proc->strace_out, "IPPROTO_IP");
			break;
		case 1:
			fprintf(proc->strace_out, "IPPROTO_ICMP");
			break;
		case 2:
			fprintf(proc->strace_out, "IPPROTO_IGMP");
			break;
		case 3:
			fprintf(proc->strace_out, "IPPROTO_GGP");
			break;
		case 6:
			fprintf(proc->strace_out, "IPPROTO_TCP");
			break;
		case 17:
			fprintf(proc->strace_out, "IPPROTO_UDP");
			break;
		case 132:
			fprintf(proc->strace_out, "IPPROTO_STCP");
			break;
		case 255:
			fprintf(proc->strace_out, "IPPROTO_RAW");
			break;
		default:
			fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d)", arg->protocol);
			break;
		}
		break;
		case 16:
			fprintf(proc->strace_out, "PF_NETLINK, ");
			switch (arg->type) {
			case 1:
				fprintf(proc->strace_out, "SOCK_STREAM, ");
				break;
			case 2:
				fprintf(proc->strace_out, "SOCK_DGRAM, ");
				break;
			case 3:
				fprintf(proc->strace_out, "SOCK_RAW, ");
				break;
			case 4:
				fprintf(proc->strace_out, "SOCK_RDM, ");
				break;
			case 5:
				fprintf(proc->strace_out, "SOCK_SEQPACKET, ");
				break;
			case 6:
				fprintf(proc->strace_out, "SOCK_DCCP, ");
				break;
			case 10:
				fprintf(proc->strace_out, "SOCK_PACKET, ");
				break;
			default:
				fprintf(proc->strace_out, "TYPE UNKNOWN (%d), ", arg->type);
				break;
			}
			switch (arg->protocol) {
			case 0:
				fprintf(proc->strace_out, "NETLINK_ROUTE");
				break;
			case 1:
				fprintf(proc->strace_out, "NETLINK_UNUSED");
				break;
			case 2:
				fprintf(proc->strace_out, "NETLINK_USERSOCK");
				break;
			case 3:
				fprintf(proc->strace_out, "NETLINK_FIREWALL");
				break;
			case 4:
				fprintf(proc->strace_out, "NETLINK_INET_DIAG");
				break;
			default:
				fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d)", arg->protocol);
				break;
			}
			break;
			default:
				fprintf(proc->strace_out, "DOMAIN UNKNOWN (%d), ", arg->domain);
				break;
	}
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of getsockopt syscall */
void print_getsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	getsockopt_arg_t arg = &(sysarg->getsockopt);
	// fprintf(proc->strace_out,"[%d] getsockopt(", pid);
	fprintf(proc->strace_out, "getsockopt(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	switch (arg->level) {
	case 0:
		fprintf(proc->strace_out, "SOL_IP, ");
		switch (arg->optname) {
		case 1:
			fprintf(proc->strace_out, "IP_TOS, ");
			break;
		case 2:
			fprintf(proc->strace_out, "IP_TTL, ");
			break;
		case 3:
			fprintf(proc->strace_out, "IP_HDRINCL, ");
			break;
		case 4:
			fprintf(proc->strace_out, "IP_OPTIONS, ");
			break;
		case 6:
			fprintf(proc->strace_out, "IP_RECVOPTS, ");
			break;
		default:
			fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", arg->optname);
			break;
		}
		break;
		case 1:
			fprintf(proc->strace_out, "SOL_SOCKET, ");
			switch (arg->optname) {
			case 1:
				fprintf(proc->strace_out, "SO_DEBUG, ");
				break;
			case 2:
				fprintf(proc->strace_out, "SO_REUSEADDR, ");
				break;
			case 3:
				fprintf(proc->strace_out, "SO_TYPE, ");
				break;
			case 4:
				fprintf(proc->strace_out, "SO_ERROR, ");
				break;
			case 5:
				fprintf(proc->strace_out, "SO_DONTROUTE, ");
				break;
			case 6:
				fprintf(proc->strace_out, "SO_BROADCAST, ");
				break;
			case 7:
				fprintf(proc->strace_out, "SO_SNDBUF, ");
				break;
			case 8:
				fprintf(proc->strace_out, "SO_RCVBUF, ");
				break;
			case 9:
				fprintf(proc->strace_out, "SO_SNDBUFFORCE, ");
				break;
			case 10:
				fprintf(proc->strace_out, "SO_RCVBUFFORCE, ");
				break;
			case 11:
				fprintf(proc->strace_out, "SO_NO_CHECK, ");
				break;
			case 12:
				fprintf(proc->strace_out, "SO_PRIORITY, ");
				break;
			case 13:
				fprintf(proc->strace_out, "SO_LINGER, ");
				break;
			case 14:
				fprintf(proc->strace_out, "SO_BSDCOMPAT, ");
				break;
			case 15:
				fprintf(proc->strace_out, "SO_REUSEPORT, ");
				break;
			default:
				fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", arg->optname);
				break;
			}
			break;
			case 41:
				fprintf(proc->strace_out, "SOL_IPV6, ");
				break;
			case 58:
				fprintf(proc->strace_out, "SOL_ICMPV6, ");
				break;
			default:
				fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d), ", arg->level);
				break;
	}

	fprintf(proc->strace_out, "%d ) = ", arg->optlen);

	fprintf(proc->strace_out, "%d\n", (int) arg->ret);
}

/** @brief print a strace-like log of setsockopt syscall */
void print_setsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	getsockopt_arg_t arg = &(sysarg->setsockopt);
	// fprintf(proc->strace_out,"[%d] setsockopt(", pid);
	fprintf(proc->strace_out, "setsockopt(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	switch (arg->level) {
	case 0:
		fprintf(proc->strace_out, "SOL_IP, ");
		switch (arg->optname) {
		case 1:
			fprintf(proc->strace_out, "IP_TOS, ");
			break;
		case 2:
			fprintf(proc->strace_out, "IP_TTL, ");
			break;
		case 3:
			fprintf(proc->strace_out, "IP_HDRINCL, ");
			break;
		case 4:
			fprintf(proc->strace_out, "IP_OPTIONS, ");
			break;
		case 6:
			fprintf(proc->strace_out, "IP_RECVOPTS, ");
			break;
		default:
			fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", arg->optname);
			break;
		}
		break;
		case 1:
			fprintf(proc->strace_out, "SOL_SOCKET, ");
			switch (arg->optname) {
			case 1:
				fprintf(proc->strace_out, "SO_DEBUG, ");
				break;
			case 2:
				fprintf(proc->strace_out, "SO_REUSEADDR, ");
				break;
			case 3:
				fprintf(proc->strace_out, "SO_TYPE, ");
				break;
			case 4:
				fprintf(proc->strace_out, "SO_ERROR, ");
				break;
			case 5:
				fprintf(proc->strace_out, "SO_DONTROUTE, ");
				break;
			case 6:
				fprintf(proc->strace_out, "SO_BROADCAST, ");
				break;
			case 7:
				fprintf(proc->strace_out, "SO_SNDBUF, ");
				break;
			case 8:
				fprintf(proc->strace_out, "SO_RCVBUF, ");
				break;
			case 9:
				fprintf(proc->strace_out, "SO_SNDBUFFORCE, ");
				break;
			case 10:
				fprintf(proc->strace_out, "SO_RCVBUFFORCE, ");
				break;
			case 11:
				fprintf(proc->strace_out, "SO_NO_CHECK, ");
				break;
			case 12:
				fprintf(proc->strace_out, "SO_PRIORITY, ");
				break;
			case 13:
				fprintf(proc->strace_out, "SO_LINGER, ");
				break;
			case 14:
				fprintf(proc->strace_out, "SO_BSDCOMPAT, ");
				break;
			case 15:
				fprintf(proc->strace_out, "SO_REUSEPORT, ");
				break;
			default:
				fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", arg->optname);
				break;
			}
			break;
			case 41:
				fprintf(proc->strace_out, "SOL_IPV6, ");
				break;
			case 58:
				fprintf(proc->strace_out, "SOL_ICMPV6, ");
				break;
			default:
				fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d), ", arg->level);
				break;
	}

	fprintf(proc->strace_out, "%d ) = ", arg->optlen);

	fprintf(proc->strace_out, "%d\n", (int) arg->ret);
}

/** @brief print a strace-like log of listen syscall */
void print_listen_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	listen_arg_t arg = &(sysarg->listen);

	fprintf(proc->strace_out, "listen(");
	//  fprintf(proc->strace_out,"[%d] listen(", pid);
	fprintf(proc->strace_out, "%d, ", arg->sockfd);
	fprintf(proc->strace_out, "%d ", arg->backlog);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief helper function to print the flags of send syscalls */
static void print_flags_send(process_descriptor_t * proc, int flags)
{
	if (flags & MSG_CONFIRM)
		fprintf(proc->strace_out, " MSG_CONFIRM |");
	if (flags & MSG_DONTROUTE)
		fprintf(proc->strace_out, " MSG_DONTROUTE |");
	if (flags & MSG_DONTWAIT)
		fprintf(proc->strace_out, " MSG_DONTWAIT |");
	if (flags & MSG_EOR)
		fprintf(proc->strace_out, " MSG_EOR |");
	if (flags & MSG_MORE)
		fprintf(proc->strace_out, " MSG_MORE |");
	if (flags & MSG_NOSIGNAL)
		fprintf(proc->strace_out, " MSG_NOSIGNAL |");
	if (flags & MSG_OOB)
		fprintf(proc->strace_out, " MSG_OOB |");
	fprintf(proc->strace_out, ", ");
}

/** @brief helper function to print the flags of recv syscalls */
static void print_flags_recv(process_descriptor_t * proc, int flags)
{
	if (flags & MSG_DONTWAIT)
		fprintf(proc->strace_out, " MSG_DONTWAIT |");
	if (flags & MSG_ERRQUEUE)
		fprintf(proc->strace_out, " MSG_ERRQUEUE |");
	if (flags & MSG_PEEK)
		fprintf(proc->strace_out, " MSG_PEEK |");
	if (flags & MSG_OOB)
		fprintf(proc->strace_out, " MSG_OOB |");
	if (flags & MSG_TRUNC)
		fprintf(proc->strace_out, " MSG_TRUNC |");
	if (flags & MSG_WAITALL)
		fprintf(proc->strace_out, " MSG_WAITALL |");
	fprintf(proc->strace_out, ", ");
}


/** @brief print a strace-like log of recv syscall */
void print_recv_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	recv_arg_t arg = &(sysarg->recv);
	// fprintf(proc->strace_out,"[%d] recv(", pid);
	fprintf(proc->strace_out, "recv(");

	fprintf(proc->strace_out, "%d, ", arg->sockfd);
	fprintf(proc->strace_out, "%d ", (int) arg->len);

	if (arg->flags > 0) {
		print_flags_recv(proc, arg->flags);
	} else
		fprintf(proc->strace_out, "0, ");

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of send syscall */
void print_send_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	recv_arg_t arg = &(sysarg->send);
	// fprintf(proc->strace_out,"[%d] send( ", pid);
	fprintf(proc->strace_out, "send( ");

	fprintf(proc->strace_out, "%d, ", arg->sockfd);
	fprintf(proc->strace_out, "%d ", (int) arg->len);

	if (arg->flags > 0) {
		print_flags_send(proc, arg->flags);
	} else
		fprintf(proc->strace_out, "0, ");

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}


/** @brief print a strace-like log of sendto syscall */
void print_sendto_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	sendto_arg_t arg = &(sysarg->sendto);
	int domain = get_domain_socket(proc, arg->sockfd);

	// fprintf(proc->strace_out,"[%d] sendto(", pid);
	fprintf(proc->strace_out, "sendto(");
#ifndef address_translation
	char buff[200];
	if (arg->len < 200) {
		memcpy(buff, arg->data, arg->len);
		buff[arg->ret] = '\0';
		fprintf(proc->strace_out, "%d, \"%s\" , %d, ", arg->sockfd, buff, arg->len);
	} else {
		memcpy(buff, arg->data, 200);
		buff[199] = '\0';
		fprintf(proc->strace_out, "%d, \"%s...\" , %d, ", arg->sockfd, buff, arg->len);
	}
#else
	fprintf(proc->strace_out, "%d, \"...\" , %d, ", arg->sockfd, arg->len);
#endif
	if (arg->flags > 0) {
		print_flags_send(proc, arg->flags);
	} else
		fprintf(proc->strace_out, "0, ");

	if (domain == 2) {            // PF_INET
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
					inet_ntoa(arg->sai.sin_addr));
		} else
			fprintf(proc->strace_out, "NULL, ");
	} else if (domain == 1) {     //PF_UNIX
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
		} else
			fprintf(proc->strace_out, "NULL, ");

	} else if (domain == 16) {    //PF_NETLINK
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
		} else
			fprintf(proc->strace_out, "NULL, ");
	} else {
		fprintf(proc->strace_out, "{sockaddr unknown}, ");
	}

	fprintf(proc->strace_out, "%d", (int) arg->addrlen);

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of recvfrom syscall */
void print_recvfrom_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	recvfrom_arg_t arg = &(sysarg->recvfrom);
	int domain = get_domain_socket(proc, arg->sockfd);

	// fprintf(proc->strace_out,"[%d] recvfrom(", pid);
	fprintf(proc->strace_out, "recvfrom(");
#ifndef address_translation
	if (arg->ret) {
		char buff[500];
		if (arg->ret <= 500) {
			memcpy(buff, arg->data, arg->ret);
			buff[arg->ret] = '\0';
			fprintf(proc->strace_out, "%d, \"%s\" , %d, ", arg->sockfd, buff, arg->len);
		} else {
			memcpy(buff, arg->data, 500);
			buff[499] = '\0';
			fprintf(proc->strace_out, "%d, \"%s...\" , %d, ", arg->sockfd, buff, arg->len);
		}

		if (arg->flags > 0) {
			print_flags_send(proc, arg->flags);
		} else
			fprintf(proc->strace_out, "0, ");
	} else
		fprintf(proc->strace_out, "%d, \"\" , %d, ", arg->sockfd, arg->len);
#else
	fprintf(proc->strace_out, "%d, \"...\" , %d, ", arg->sockfd, arg->len);
#endif

	if (domain == 2) {            // PF_INET
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
					inet_ntoa(arg->sai.sin_addr));
		} else
			fprintf(proc->strace_out, "NULL, ");
	} else if (domain == 1) {     //PF_UNIX
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
		} else
			fprintf(proc->strace_out, "NULL, ");

	} else if (domain == 16) {    //PF_NETLINK
		if (arg->is_addr) {
			fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
		} else
			fprintf(proc->strace_out, "NULL, ");
	} else {
		fprintf(proc->strace_out, "{sockaddr unknown}, ");
	}

	fprintf(proc->strace_out, "%d", (int) arg->addrlen);

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of recvmsg syscall */
void print_recvmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	recvmsg_arg_t arg = &(sysarg->sendmsg);

	//  fprintf(proc->strace_out,"[%d] recvmsg(", pid);
	fprintf(proc->strace_out, "recvmsg(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);

	fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, msg_controllen=%d, msg_flags=%d}, ", (int) arg->msg.msg_namelen,
			(int) arg->msg.msg_iovlen, (int) arg->msg.msg_controllen, arg->msg.msg_flags);

	if (arg->flags > 0) {
		print_flags_recv(proc, arg->flags);
	} else
		fprintf(proc->strace_out, "0 ");

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of sendmsg syscall */
void print_sendmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	recvmsg_arg_t arg = &(sysarg->sendmsg);

	//  fprintf(proc->strace_out,"[%d] sendmsg(", pid);
	fprintf(proc->strace_out, "sendmsg(");
	fprintf(proc->strace_out, "%d, ", arg->sockfd);
#ifndef address_translation
	char buff[20];
	if (arg->len < 20) {
		memcpy(buff, arg->data, arg->len);
		fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"%s\", msg_controllen=%d, msg_flags=%d}, ",
				(int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, buff, (int) arg->msg.msg_controllen,
				arg->msg.msg_flags);
	} else {
		memcpy(buff, arg->data, 20);
		buff[19] = '\0';

		fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"%s...\", msg_controllen=%d, msg_flags=%d}, ",
				(int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, buff, (int) arg->msg.msg_controllen,
				arg->msg.msg_flags);
	}
#else
	fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"...\", msg_controllen=%d, msg_flags=%d}, ",
			(int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, (int) arg->msg.msg_controllen, arg->msg.msg_flags);
#endif

	if (arg->flags > 0) {
		print_flags_recv(proc, arg->flags);
	} else
		fprintf(proc->strace_out, "0 ");

	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief helper function to print the events flags of poll syscall */
static void get_events_poll(process_descriptor_t * proc, short events)
{
	fprintf(proc->strace_out, "events=");
	if ((events & POLLIN) != 0)
		fprintf(proc->strace_out, "POLLIN |");
	if ((events & POLLPRI) != 0)
		fprintf(proc->strace_out, "POLLPRI |");
	if ((events & POLLOUT) != 0)
		fprintf(proc->strace_out, "POLLOUT |");
	if ((events & POLLERR) != 0)
		fprintf(proc->strace_out, "POLLERR |");
	if ((events & POLLHUP) != 0)
		fprintf(proc->strace_out, "POLLHUP |");
	if ((events & POLLNVAL) != 0)
		fprintf(proc->strace_out, "POLLNVAL |");
}

/** @brief helper function to print the revents flags of poll syscall */
static void get_revents_poll(process_descriptor_t * proc, short revents)
{
	fprintf(proc->strace_out, ", revents=");
	if ((revents & POLLIN) != 0)
		fprintf(proc->strace_out, "POLLIN |");
	if ((revents & POLLPRI) != 0)
		fprintf(proc->strace_out, "POLLPRI |");
	if ((revents & POLLOUT) != 0)
		fprintf(proc->strace_out, "POLLOUT |");
	if ((revents & POLLERR) != 0)
		fprintf(proc->strace_out, "POLLERR |");
	if ((revents & POLLHUP) != 0)
		fprintf(proc->strace_out, "POLLHUP |");
	if ((revents & POLLNVAL) != 0)
		fprintf(proc->strace_out, "POLLNVAL |");
	fprintf(proc->strace_out, "} ");
}

/** @brief helper function to print the fd, events and revents of poll syscall */
static void disp_pollfd(process_descriptor_t * proc, struct pollfd *fds, int nfds)
{
	int i;
	for (i = 0; i < nfds - 1; i++) {
		fprintf(proc->strace_out, "{fd=%d, ", fds[i].fd);
		get_events_poll(proc, fds[i].events);
		get_revents_poll(proc, fds[i].revents);
		if (i > 3) {
			fprintf(proc->strace_out, " ... }");
			break;
		}
	}
	if (nfds < 3) {
		fprintf(proc->strace_out, "{fd=%d, ", fds[nfds - 1].fd);
		get_events_poll(proc, fds[nfds - 1].events);
		get_revents_poll(proc, fds[nfds - 1].revents);
	}

}

/** @brief print a strace-like log of poll syscall */
void print_poll_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	poll_arg_t arg = &(sysarg->poll);

	fprintf(proc->strace_out, "poll([");
	// fprintf(proc->strace_out,"[%d] poll([",pid);
	if (arg->fd_list != NULL)
		disp_pollfd(proc, arg->fd_list, arg->nbfd);
	else
		fprintf(proc->strace_out, "NULL");
	fprintf(proc->strace_out, " ]");
	fprintf(proc->strace_out, "%lf) = %d\n", arg->timeout, arg->ret);
}

/** @brief helper function to print the fd of select syscall */
static void disp_selectfd(process_descriptor_t * proc, fd_set * fd)
{
	int i;
	fprintf(proc->strace_out, "[ ");
	for (i = 0; i < FD_SETSIZE; i++) {
		if (FD_ISSET(i, fd)) {
			fprintf(proc->strace_out, "%d ", i);
		}
	}
	fprintf(proc->strace_out, "]");
}

/** @brief print a strace-like log of select syscall */
void print_select_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	select_arg_t arg = &(sysarg->select);
	// fprintf(proc->strace_out,"[%d] select(%d,", pid, arg->maxfd);
	fprintf(proc->strace_out, "select(%d,", arg->maxfd);

	if (arg->fd_state & SELECT_FDRD_SET)
		disp_selectfd(proc, &arg->fd_read);
	else
		fprintf(proc->strace_out, "NULL");
	fprintf(proc->strace_out, ", ");
	if (arg->fd_state & SELECT_FDWR_SET)
		disp_selectfd(proc, &arg->fd_write);
	else
		fprintf(proc->strace_out, "NULL");
	fprintf(proc->strace_out, ", ");
	if (arg->fd_state & SELECT_FDEX_SET)
		disp_selectfd(proc, &arg->fd_except);
	else
		fprintf(proc->strace_out, "NULL");
	fprintf(proc->strace_out, ", ");

	fprintf(proc->strace_out, "%lf) = %d\n", arg->timeout, arg->ret);
}

/** @brief print a strace-like log of fcntl syscall */
void print_fcntl_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	fcntl_arg_t arg = &(sysarg->fcntl);
	//  fprintf(proc->strace_out,"[%d] fcntl( %d, ", pid, arg->fd);
	fprintf(proc->strace_out, "fcntl(%d, ", arg->fd);
	switch (arg->cmd) {
	case F_DUPFD:
		fprintf(proc->strace_out, "F_DUPFD");
		break;

	case F_DUPFD_CLOEXEC:
		fprintf(proc->strace_out, "F_DUPFD_CLOEXEC");
		break;

	case F_GETFD:
		fprintf(proc->strace_out, "F_GETFD");
		break;

	case F_SETFD:
		fprintf(proc->strace_out, "F_SETFD");
		if (arg->arg)
			fprintf(proc->strace_out, ", FD_CLOEXEC");
		else
			fprintf(proc->strace_out, ", %d", arg->arg);
		break;

	case F_GETFL:
		fprintf(proc->strace_out, "F_GETFL");
		break;

	case F_SETFL:
		fprintf(proc->strace_out, "F_SETFL");
		break;

	case F_SETLK:
		fprintf(proc->strace_out, "F_SETLK");
		break;

	case F_SETLKW:
		fprintf(proc->strace_out, "F_SETLKW");
		break;

	case F_GETLK:
		fprintf(proc->strace_out, "F_GETLK");
		break;

	default:
		fprintf(proc->strace_out, "Unknown command");
		break;
	}
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}

/** @brief print a strace-like log of read syscall */
void print_read_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	read_arg_t arg = &(sysarg->read);
	fprintf(proc->strace_out, "[%d] read(%d, \"...\", %d) = %d\n", proc->pid, arg->fd, arg->count, arg->ret);
	//fprintf(proc->strace_out, "read(%d, \"...\", %d) = %d\n", arg->fd, arg->count, arg->ret);
}

/** @brief print a strace-like log of write syscall */
void print_write_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	write_arg_t arg = &(sysarg->read);
	fprintf(proc->strace_out, "[%d] write(%d, \"...\", %d) = %d\n", proc->pid, arg->fd, arg->count, arg->ret);
	//fprintf(proc->strace_out, "write(%d, \"...\", %d) = %d\n", arg->fd, arg->count, arg->ret);
}

/** @brief helper function to print options of shutdown syscall */
static void print_shutdown_option(process_descriptor_t * proc, int how)
{
	switch (how) {
	case 0:
		fprintf(proc->strace_out, "SHUT_RD");
		break;
	case 1:
		fprintf(proc->strace_out, "SHUT_WR");
		break;
	case 2:
		fprintf(proc->strace_out, "SHUT_RDWR");
		break;
	}
}

/** @brief print a strace-like log of shutdown syscall */
void print_shutdown_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	shutdown_arg_t arg = &(sysarg->shutdown);
	//  fprintf(proc->strace_out,"[%d] shutdown (%d, ", pid, arg->fd);
	fprintf(proc->strace_out, "shutdown (%d, ", arg->fd);
	print_shutdown_option(proc, arg->how);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}


/** @brief print a strace-like log of getpeername syscall */
void print_getpeername_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	getpeername_arg_t arg = &(sysarg->getpeername);
	//  fprintf(proc->strace_out,"[%d] getpeername (%d, ", pid, arg->sockfd);
	fprintf(proc->strace_out, "getpeername (%d, ", arg->sockfd);
	fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", arg->in.sin_port,
			inet_ntoa(arg->in.sin_addr));
	fprintf(proc->strace_out, "%d ) = %d\n", arg->len, arg->ret);
}

/** @brief print a strace-like log of time syscall */
void print_time_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	time_arg_t arg = &(sysarg->time);
	//fprintf(proc->strace_out,"[%d] time = %ld\n", pid, arg->ret);
	fprintf(proc->strace_out, "time = %ld\n", arg->ret);
}

/** @brief print a strace-like log of gettimeofday syscall */
void print_gettimeofday_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	//gettimeofday_arg_t arg = &(sysarg->gettimeofday);
	//  fprintf(proc->strace_out,"[%d] gettimeofday, tv = %ld\n", pid, arg->tv);
	//fprintf(proc->strace_out, "gettimeofday, tv = %ld\n", arg->tv);
	THROW_UNIMPLEMENTED;
}

/** @brief helper function to print the flags of clone syscall */
static void print_flags_clone(process_descriptor_t * proc, int flags)
{
	if (flags & CSIGNAL)
		fprintf(proc->strace_out, " CSIGNAL |");
	if (flags & CLONE_VM)
		fprintf(proc->strace_out, " CLONE_VM |");
	if (flags & CLONE_FS)
		fprintf(proc->strace_out, " CLONE_FS |");
	if (flags & CLONE_FILES)
		fprintf(proc->strace_out, " CLONE_FILES |");
	if (flags & CLONE_SIGHAND)
		fprintf(proc->strace_out, " CLONE_SIGHAND |");
	if (flags & CLONE_PTRACE)
		fprintf(proc->strace_out, " CLONE_PTRACE |");
	if (flags & CLONE_VFORK)
		fprintf(proc->strace_out, " CLONE_VFORK |");
	if (flags & CLONE_PARENT)
		fprintf(proc->strace_out, " CLONE_PARENT |");
	if (flags & CLONE_THREAD)
		fprintf(proc->strace_out, " CLONE_THREAD |");
	if (flags & CLONE_NEWNS)
		fprintf(proc->strace_out, " CLONE_NEWNS |");
	if (flags & CLONE_SYSVSEM)
		fprintf(proc->strace_out, " CLONE_SYSVSEM |");
	if (flags & CLONE_SETTLS)
		fprintf(proc->strace_out, " CLONE_SETTLS |");
	if (flags & CLONE_PARENT_SETTID)
		fprintf(proc->strace_out, " CLONE_PARENT_SETTID |");
	if (flags & CLONE_CHILD_CLEARTID)
		fprintf(proc->strace_out, " CLONE_CHILD_CLEARTID |");
	if (flags & CLONE_DETACHED)   // unused
		fprintf(proc->strace_out, " CLONE_DETACHED |");
	if (flags & CLONE_UNTRACED)
		fprintf(proc->strace_out, " CLONE_UNTRACED |");
	if (flags & CLONE_CHILD_SETTID)
		fprintf(proc->strace_out, " CLONE_CHILD_SETTID |");
	if (flags & CLONE_NEWUTS)
		fprintf(proc->strace_out, " CLONE_NEWUTS |");
	if (flags & CLONE_NEWIPC)
		fprintf(proc->strace_out, " CLONE_NEWIPC |");
	if (flags & CLONE_NEWUSER)
		fprintf(proc->strace_out, " CLONE_NEWUSER |");
	if (flags & CLONE_NEWPID)
		fprintf(proc->strace_out, " CLONE_NEWPID |");
	if (flags & CLONE_NEWNET)
		fprintf(proc->strace_out, " CLONE_NEWNET |");
	if (flags & CLONE_IO)
		fprintf(proc->strace_out, " CLONE_IO |");
	fprintf(proc->strace_out, ", ");
}

/** @brief print a strace-like log of clone syscall */
void print_clone_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{

	clone_arg_t arg = &(sysarg->clone);
	fprintf(proc->strace_out, "clone(child_stack=%ld, flags=", arg->newsp);

	print_flags_clone(proc, (long int) arg->clone_flags);
	fprintf(proc->strace_out, "child_tidptr=0x%lx) = %d \n", (long int) arg->child_tid, arg->ret);
}

/** @brief helper function to retrieve the information of execve syscall */
static int get_string(int pid, long ptr, char *buf, int size)
{
	long data;
	char *p = (char *) &data;
	int j = 0;

	while ((data = ptrace(PTRACE_PEEKTEXT, pid, (void *) ptr, 0)) && j < size) {
		int i;
		for (i = 0; i < sizeof(data) && j < size; i++, j++) {
			if (!(buf[j] = p[i]))
				goto done;
		}
		ptr += sizeof(data);
	}
	done:
	buf[j] = '\0';
	return j;
}

/** @brief print a strace-like log of execve syscall, without the return */
void print_execve_syscall_pre(process_descriptor_t * proc, syscall_arg_u * sysarg)
{

	execve_arg_t arg = &(sysarg->execve);
	pid_t pid = proc->pid;
	char bufstr[4096];
	long ptr_filename, ptr_argv;

	ptr_filename = arg->ptr_filename;
	fprintf(proc->strace_out, "execve(");
	if (ptr_filename) {
		get_string(pid, ptr_filename, bufstr, sizeof(bufstr));
		fprintf(proc->strace_out, "\"%s\", [", bufstr);
	}
	ptr_argv = arg->ptr_argv;
	int first = 1;
	for (; ptr_argv; ptr_argv += sizeof(unsigned long)) {
		ptr_filename = ptr_argv;
		/* Indirect through ptr since we have char *argv[] */
		ptr_filename = ptrace(PTRACE_PEEKTEXT, pid, (void *) ptr_filename, 0);

		if (!ptr_filename) {
			fprintf(proc->strace_out, "]");
			break;
		}

		get_string(pid, ptr_filename, bufstr, sizeof(bufstr));
		if (first) {
			fprintf(proc->strace_out, "\"%s\"", bufstr);
			first = 0;
		} else {
			fprintf(proc->strace_out, ", \"%s\"", bufstr);
		}
	}
	fprintf(proc->strace_out, ") = ");
}

/** @brief print the return of execve syscall */
void print_execve_syscall_post(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	execve_arg_t arg = &(sysarg->execve);
	fprintf(proc->strace_out, "%d\n", arg->ret);
}

static void print_flags_open(process_descriptor_t * proc, int flags)
{
	fprintf(proc->strace_out, ", ");
	if (flags & O_CLOEXEC)
		fprintf(proc->strace_out, " O_CLOEXEC |");
	if (flags & O_CREAT)
		fprintf(proc->strace_out, " O_CREAT |");
	if (flags & O_DIRECTORY)
		fprintf(proc->strace_out, " O_DIRECTORY |");
	if (flags & O_EXCL)
		fprintf(proc->strace_out, " O_EXCL |");
	if (flags & O_NOCTTY)
		fprintf(proc->strace_out, " O_NOCTTY |");
	if (flags & O_NOFOLLOW)
		fprintf(proc->strace_out, " O_NOFOLLOW |");
	if (flags & O_TRUNC)
		fprintf(proc->strace_out, " O_TRUNC |");
}

/** @brief print open syscall */
void print_open_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	open_arg_t arg = &(sysarg->open);
	pid_t pid = proc->pid;
	char bufstr[4096];
	long ptr_filename;

	ptr_filename = arg->ptr_filename;
	// fprintf(proc->strace_out, "[%d] open(", proc->pid);
	fprintf(proc->strace_out, "open(");
	if (ptr_filename) {
		get_string(pid, ptr_filename, bufstr, sizeof(bufstr));
		fprintf(proc->strace_out, "\"%s\"", bufstr);
	}
	if (arg->flags > 0)
		print_flags_open(proc, arg->flags);
	fprintf(proc->strace_out, ") = %d\n", arg->ret);
}
