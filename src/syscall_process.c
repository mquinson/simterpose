/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/socket.h>
#include <fcntl.h>
#include <msg/datatypes.h>
#include <msg/msg.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <xbt/asserts.h>
#include <xbt/dynar.h>
#include <xbt/ex.h>
#include <xbt/log.h>
#include <xbt/misc.h>
#include <xbt/sysdep.h>

#include "syscall_process.h"

#include "communication.h"
#include "data_utils.h"
#include "sockets.h"

#ifndef unknown_error // that stupid eclipse seems to not find that symbol (which comes from SimGrid logging features)
#define unknown_error 0
#endif

#define SYSCALL_ARG1 rdi
const char *state_names[4] = { "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND" };

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, simterpose, "Syscall process log");

/** @brief helper function to send task */
int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc)
{
	XBT_DEBUG("Entering process_send_call");
	sendto_arg_t arg = &(sysarg->sendto);
	if (socket_registered(proc, arg->sockfd) != -1) {
		if (!socket_netlink(proc, arg->sockfd)) {
			XBT_DEBUG("%d This is not a netlink socket", arg->sockfd);
			//   compute_computation_time(proc);   // cree la computation task
			struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
			struct infos_socket *s = comm_get_peer(is);
			is->ref_nb++;
			s->ref_nb++;

			XBT_DEBUG("%d->%d", arg->sockfd, arg->ret);
			XBT_DEBUG("Sending data(%d) on socket %d", arg->ret, s->fd.fd);
			handle_new_send(is, sysarg);

			msg_task_t task = create_send_communication_task(proc, is, arg->ret, proc->host, s->fd.proc->host);
			XBT_DEBUG("hosts: %s send to %s (size: %d)", MSG_host_get_name(proc->host), MSG_host_get_name(s->fd.proc->host),
					arg->ret);
			MSG_task_set_data_size(task, arg->ret);
			MSG_task_set_data(task, arg->data);

			send_task(s->fd.proc->host, task);

			is->ref_nb--;
			s->ref_nb--;
			return 1;
		}
		return 0;
	} else
		xbt_die("The socket is not registered");
	return 0;
}

/** @brief helper function to close a file descriptor */
void process_close_call(process_descriptor_t * proc, int fd)
{
	fd_descriptor_t *file_desc = proc->fd_list[fd];
	if (file_desc != NULL) {
		file_desc->refcount++;
		if (file_desc->type == FD_SOCKET)
			socket_close(proc, fd);
		else {
			if (file_desc->type == FD_PIPE) {
				pipe_t *pipe = file_desc->pipe;
				xbt_assert(pipe != NULL);

				unsigned int cpt_in;
				pipe_end_t end_in;
				xbt_dynar_t read_end = pipe->read_end;
				xbt_dynar_foreach(read_end, cpt_in, end_in) {
					if (end_in->fd == fd && end_in->proc->pid == proc->pid) {
						xbt_dynar_remove_at(read_end, cpt_in, NULL);
						cpt_in--;
					}
				}

				unsigned int cpt_out;
				pipe_end_t end_out;
				xbt_dynar_t write_end = pipe->write_end;
				xbt_dynar_foreach(write_end, cpt_out, end_out) {
					if (end_out->fd == fd && end_out->proc->pid == proc->pid) {
						xbt_dynar_remove_at(write_end, cpt_out, NULL);
						cpt_out--;
					}
				}

				// if both sides are closed we can free the pipe
				if (xbt_dynar_is_empty(read_end) && xbt_dynar_is_empty(write_end)) {
					xbt_dynar_free(&read_end);
					xbt_dynar_free(&write_end);
					free(pipe);
				}

			}
		}
		file_desc->refcount--;
		proc->fd_list[fd] = NULL;
	}
}

/** @brief helper function to handle connect syscall */
int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	connect_arg_t arg = &(sysarg->connect);
	XBT_DEBUG("CONNEXION: process_connect_in_call");
	pid_t pid = proc->pid;
	int domain = get_domain_socket(proc, arg->sockfd);

	if (domain == 2)              //PF_INET
	{
		struct sockaddr_in *sai = &(arg->sai);

		msg_host_t host;
		int device;
		struct in_addr in;

		if (sai->sin_addr.s_addr == inet_addr("127.0.0.1")) {
			in.s_addr = inet_addr("127.0.0.1");
			device = PORT_LOCAL;
			host = proc->host;
		} else {
			in.s_addr = get_ip_of_host(proc->host);
			device = PORT_REMOTE;
			host = get_host_by_ip(sai->sin_addr.s_addr);
			if (host == NULL) {
				arg->ret = -ECONNREFUSED;       /* ECONNREFUSED       111 Connection refused */
				ptrace_neutralize_syscall(pid);
				proc_outside(proc);
				connect_arg_t arg = &(sysarg->connect);
				ptrace_restore_syscall(pid, SYS_connect, arg->ret);
				return 0;
			}
		}

		//We ask for a connection on the socket
		process_descriptor_t *acc_proc = comm_ask_connect(host, ntohs(sai->sin_port), proc, arg->sockfd, device);

		//if the process is waiting for connection
		if (acc_proc) {
			//Now attribute ip and port to the socket.
			int port = get_random_port(proc->host);

			XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
			set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(in), port);
			register_port(proc->host, port);
			XBT_DEBUG("Free port found on host %s (%s:%d)", MSG_host_get_name(proc->host), inet_ntoa(in), port);
		} else {
			XBT_DEBUG("No peer found");
			arg->ret = -ECONNREFUSED; /* ECONNREFUSED 111 Connection refused */
			ptrace_neutralize_syscall(pid);
			proc_outside(proc);
			connect_arg_t arg = &(sysarg->connect);
			ptrace_restore_syscall(pid, SYS_connect, arg->ret);
			return 0;
		}
#ifndef address_translation
		//Now we try to see if the socket is blocking of not
		int flags = socket_get_flags(proc, arg->sockfd);
		if (flags & O_NONBLOCK)
			arg->ret = -EINPROGRESS;  /* EINPROGRESS  115      Operation now in progress */
		else
			arg->ret = 0;

		ptrace_neutralize_syscall(pid);
		connect_arg_t arg = &(sysarg->connect);
		ptrace_restore_syscall(pid, SYS_connect, arg->ret);

		//now mark the process as waiting for connection
		if (flags & O_NONBLOCK)
			return 0;

		return 1;
#else
		XBT_DEBUG("connect_in address translation");
		sys_translate_connect_in(proc, sysarg);
		int flags = socket_get_flags(proc, arg->sockfd);
		if (flags & O_NONBLOCK)
			return 0;

		return 1;
#endif
	} else
		return 0;
}

/** @brief Handle all syscalls of the tracked pid until it does a blocking action.
 *
 *  Blocking actions are stuff that must be reported to the simulator and which
 *  completion takes time. The most prominent examples are related to sending and
 *  receiving data.
 *
 *  The tracked pid can run more than one syscall in this function if theses calls
 *  are about the metadata that we maintain in simterpose without exposing them to
 *  simgrid. For example, if you call socket() or accept(), we only have to maintain
 *  our metadata but there is no need to inform the simulator, nor to ask for the
 *  completion time of these things.
 */
int process_handle(process_descriptor_t * proc)
{
	reg_s arg;
	syscall_arg_u *sysarg = &(proc->sysarg);
	pid_t pid = proc->pid;
	XBT_DEBUG("PROCESS HANDLE MSG");
	while (1) {
		ptrace_get_register(pid, &arg);
		int ret;
		XBT_DEBUG("found syscall: [%d] %s (%ld) = %ld, in_syscall = %d", pid, syscall_list[arg.reg_orig], arg.reg_orig,
				arg.ret, proc->in_syscall);

		switch (arg.reg_orig) {
		case SYS_read:
			syscall_read(&arg, sysarg, proc);
			break;

		case SYS_write:
			if ((ret = syscall_write(&arg, sysarg, proc)))
				return ret;
			break;

		case SYS_open:
			syscall_open(&arg, sysarg, proc);
			break;

		case SYS_close:
			syscall_close(&arg, sysarg, proc);
			break;

		case SYS_poll:
			if (proc_entering(proc))
				syscall_poll_pre(&arg, sysarg, proc);
			else
				syscall_poll_post(&arg, sysarg, proc);
			break;

		case SYS_pipe:
			if (proc_entering(proc))
				proc_inside(proc);
			else
				syscall_pipe_post(&arg, sysarg, proc);
			break;

		case SYS_select:
			if (proc_entering(proc))
				syscall_select_pre(&arg, sysarg, proc);
			else {
				proc_outside(proc);
			}
			break;

		case SYS_dup2:
			if (proc_entering(proc))
				proc_inside(proc);
			else
				syscall_dup2_post(&arg, sysarg, proc);
			break;

		case SYS_socket:
			syscall_socket(&arg, sysarg, proc);
			break;

		case SYS_connect:
			if (proc_entering(proc))
				syscall_connect_pre(&arg, sysarg, proc);
			else
				syscall_connect_post(&arg, sysarg, proc);
			break;

		case SYS_accept:
			syscall_accept(&arg, sysarg, proc);
			break;

		case SYS_sendto:
			if (proc_entering(proc))
				ret = syscall_sendto_pre(pid, &arg, sysarg, proc);
			else
				ret = syscall_sendto_post(pid, &arg, sysarg, proc);
			if (ret)
				return ret;
			break;

		case SYS_recvfrom:
			if (proc_entering(proc))
				syscall_recvfrom_pre(pid, &arg, sysarg, proc);
			else
				syscall_recvfrom_post(pid, &arg, sysarg, proc);
			break;

		case SYS_sendmsg:
			if ((ret = syscall_sendmsg(pid, &arg, sysarg, proc)))
				return ret;
			break;

		case SYS_recvmsg:
			if (proc_entering(proc))
				syscall_recvmsg_pre(pid, &arg, sysarg, proc);
			else
				syscall_recvmsg_post(pid, &arg, sysarg, proc);
			break;

		case SYS_shutdown:
			if (proc_entering(proc))
				syscall_shutdown_pre(&arg, sysarg, proc);
			else
				syscall_shutdown_post(&arg, sysarg, proc);
			break;

		case SYS_bind:
			if (proc_entering(proc))
				syscall_bind_pre(&arg, sysarg, proc);
			else
				syscall_bind_post(&arg, sysarg, proc);
			break;

		case SYS_listen:
			syscall_listen(&arg, sysarg, proc);
			break;

		case SYS_getpeername:
			if (proc_entering(proc))
				syscall_getpeername_pre(&arg, sysarg, proc);
			else
				proc_outside(proc);
			break;

		case SYS_setsockopt:
			if (proc_entering(proc))
				syscall_setsockopt_pre(&arg, sysarg, proc);
			else
				syscall_setsockopt_post(&arg, sysarg, proc);
			break;

		case SYS_getsockopt:
			if (proc_entering(proc))
				syscall_getsockopt_pre(&arg, sysarg, proc);
			else
				syscall_getsockopt_post(&arg, sysarg, proc);
			break;

		case SYS_clone:
			syscall_clone(&arg, sysarg, proc);
			break;

		case SYS_execve:
			syscall_execve(&arg, sysarg, proc);
			break;


		case SYS_exit:
			XBT_DEBUG("exit(%ld) called", arg.arg[0]);
			return syscall_exit(pid, &arg, sysarg, proc);
			break;

		case SYS_exit_group:
			XBT_DEBUG("exit_group(%ld) called", arg.arg[0]);
			return syscall_exit(pid, &arg, sysarg, proc);
			break;

		case SYS_fcntl:
			syscall_fcntl(&arg, sysarg, proc);
			break;

		case SYS_creat:
			if (proc_entering(proc))
				proc_inside(proc);
			else
				syscall_creat_post(&arg, sysarg, proc);
			break;

		case SYS_brk:
			syscall_brk(&arg,sysarg, proc);
			break;

		default:
			if (proc_entering(proc))
				proc_inside(proc);
			else {
				fprintf(stderr,"Unhandled syscall: [%d] %s = %ld\n", pid, syscall_list[arg.reg_orig], arg.ret);
				proc_outside(proc);
			}
			break;
		}

		// Step the traced process
		ptrace_resume_process(pid);
		// XBT_DEBUG("process resumed, waitpid");
		waitpid(pid, &(proc->status), __WALL);
	}                             // while(1)

	THROW_IMPOSSIBLE;             //There's no way to quit the loop
	return 0;
}
