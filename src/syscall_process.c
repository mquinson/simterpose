/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "syscall_process.h"

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/socket.h>
#include <bits/fcntl-linux.h>
//#include <linux/futex.h>
#include <linux/sched.h>   /* For clone flags */
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
//#include <time.h>
#include <unistd.h>
#include <xbt/asserts.h>
#include <xbt/dynar.h>
#include <xbt/ex.h>
#include <xbt/log.h>
#include <xbt/misc.h>
#include <xbt/sysdep.h>
//#include "xbt.h"

#include "args_trace.h"
#include "communication.h"
#include "data_utils.h"
#include "print_syscall.h"
//#include "process_descriptor.h"
//#include "ptrace_utils.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_data.h"
//#include "sysdep.h"

#ifndef unknown_error // that stupid eclipse seems to not find that symbol
#define unknown_error 0
#endif

#define SYSCALL_ARG1 rdi
const char *state_names[4] = { "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND" };

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, simterpose, "Syscall process log");

int clone_number = 0;

/** @brief helper function to send task */
static int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc)
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

/** @brief handle sendmsg syscall at the entrance
 *
 * In case of full mediation, everything is done when entering the syscall:
 *   - We retrieve the message intended to be sent by the application
 *   - We send it through MSG
 *   - We neutralize the real syscall so that we never exit the syscall afterward
 *
 * In case of address translation we send the MSG task in order to return
 * control to the MSG process receiving the message
 */
static int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
#ifndef address_translation
		XBT_DEBUG("sendmsg_pre");
		get_args_sendmsg(proc, reg, sysarg);
		process_descriptor_t remote_proc;
		if (process_send_call(proc, sysarg, &remote_proc)) {
			ptrace_neutralize_syscall(pid);

			sendmsg_arg_t arg = &(sysarg->sendmsg);
			proc_outside(proc);
			ptrace_restore_syscall(pid, SYS_sendmsg, arg->ret);

			if (strace_option)
				print_sendmsg_syscall(proc, sysarg);
			return PROCESS_TASK_FOUND;
		}
#endif
		return PROCESS_CONTINUE;
	} else {
		proc_outside(proc);
		// XBT_DEBUG("[%d] sendmsg_out", pid);
		XBT_DEBUG("sendmsg_post");
		get_args_sendmsg(proc, reg, sysarg);
		if (strace_option)
			print_sendmsg_syscall(proc, sysarg);
#ifdef address_translation
		if (reg->ret > 0) {
			process_descriptor_t remote_proc;
			if (process_send_call(proc, sysarg, &remote_proc)) {
				return PROCESS_TASK_FOUND;
			}
		}
#endif
		return PROCESS_CONTINUE;
	}
}


/** @brief handle sendto syscall at the entrance
 *
 * In case of full mediation, we retrieve the message intended to be sent by
 * the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_sendto_post afterwards.
 *
 * In case of address translation we translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall
 */
static int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
#ifndef address_translation
	//  XBT_DEBUG("[%d] sendto_pre", pid);
	XBT_DEBUG("sendto_pre");
	get_args_sendto(proc, reg, sysarg);
	process_descriptor_t remote_proc;
	if (process_send_call(proc, sysarg, &remote_proc)) {
		ptrace_neutralize_syscall(pid);

		sendto_arg_t arg = &(sysarg->sendto);
		proc_outside(proc);
		ptrace_restore_syscall(pid, SYS_sendto, arg->ret);

		if (strace_option)
			print_sendto_syscall(proc, sysarg);
		return PROCESS_TASK_FOUND;
	}
#else
	if (socket_registered(proc, reg->arg[0]) != -1) {
		if (socket_network(proc, reg->arg[0]))
			sys_translate_sendto_in(proc, sysarg);
	}
#endif
	return PROCESS_CONTINUE;
}

/** @brief handle sendto syscall at the exit
 *
 * In case of address translation we translate the arguments back (from the
 * real local address to the global simulated one) to wrong the application.
 * We also send the MSG task in order to return control to the MSG process
 * receiving the message
 */
static int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	// XBT_DEBUG("[%d] sendto_out", pid);
	XBT_DEBUG("sendto_post");
	get_args_sendto(proc, reg, sysarg);
	if (strace_option)
		print_sendto_syscall(proc, sysarg);
#ifdef address_translation
	if (socket_registered(proc, reg->arg[0]) != -1) {
		if (socket_network(proc, reg->arg[0])) {
			sys_translate_sendto_out(proc, sysarg);
		}
	}
	if ((int) reg->ret > 0) {
		process_descriptor_t remote_proc;
		if (process_send_call(proc, sysarg, &remote_proc))
			return PROCESS_TASK_FOUND;
	}
#endif
	return PROCESS_CONTINUE;
}

/** @brief handle write syscall at the entrance
 *
 * At entrance, in case of full mediation and if the socket is registered we retrieve the message intended
 * to be written by the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_write_post afterwards.
 *
 * At exit, we send the MSG task in order to return control to the MSG process reading the message
 */
static int syscall_write(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
		XBT_DEBUG(" write_pre");
		get_args_write(proc, reg, sysarg);

#ifndef address_translation
		// XBT_DEBUG("[%d] write_in", pid);
		if (socket_registered(proc, sysarg->write.fd) != -1) {
			process_descriptor_t remote_proc;
			if (process_send_call(proc, sysarg, &remote_proc)) {
				ptrace_neutralize_syscall(proc->pid);

				write_arg_t arg = &(sysarg->write);
				ptrace_restore_syscall(proc->pid, SYS_write, arg->ret);
				if (strace_option)
					print_write_syscall(proc, sysarg);
				proc_outside(proc);
				return PROCESS_TASK_FOUND;
			}
		} else {
			// FIXME: if the socket is not registered, for now we do nothing
			// and let the kernel run the syscall
			//XBT_WARN("socket unregistered");
		}
#endif
		return PROCESS_CONTINUE;
	} else {
		proc_outside(proc);
		XBT_DEBUG("write_post");
		//    XBT_DEBUG("[%d] write_out", pid);
		get_args_write(proc, reg, sysarg);

		write_arg_t arg = &(sysarg->write);
		fd_descriptor_t *file_desc = proc->fd_list[arg->fd];
		file_desc->ref_nb++;

		// If we're writing into a pipe, we handle things differently
		if (file_desc != NULL && file_desc->type == FD_PIPE) {
			if (strace_option)
				print_write_syscall(proc, sysarg);
			pipe_t *pipe = file_desc->pipe;
			if (pipe == NULL)
				THROW_IMPOSSIBLE;

			pipe_end_t end_in = NULL;
			xbt_dynar_get_cpy(pipe->read_end, 0, &end_in);

			char buff[256];
			sprintf(buff, "%d", end_in->fd);
			msg_host_t receiver = end_in->proc->host;

			XBT_WARN("host %s trying to send to %s in pipe %d (size: %d). Buff = %s", MSG_host_get_name(proc->host),
					MSG_host_get_name(receiver), end_in->fd, arg->ret, buff);

			double amount = arg->ret;
			msg_task_t task = MSG_task_create(buff, 0, amount, arg->data);
			XBT_WARN("hosts: %s send to %s in pipe %d (size: %d)", MSG_host_get_name(proc->host), MSG_host_get_name(receiver),
					end_in->fd, arg->ret);
			MSG_task_send(task, buff);
		} else if (strace_option)
			print_write_syscall(proc, sysarg);

		file_desc->ref_nb--;
		file_desc = NULL;

#ifdef address_translation
		if ((int) reg->ret > 0) {
			if (socket_registered(proc, sysarg->write.fd) != -1) {
				process_descriptor_t remote_proc;
				if (process_send_call(proc, sysarg, &remote_proc))
					return PROCESS_TASK_FOUND;
			}
		}
#endif
		return PROCESS_CONTINUE;
	}
}

/** @brief handle recvmsg syscall at the entrance
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_recvmsg_post afterwards.
 */
static void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	//  XBT_DEBUG("[%d] recvmsg_in", pid);
	XBT_DEBUG("recvmsg_pre");
	get_args_recvmsg(proc, reg, sysarg);
	recvmsg_arg_t arg = &(sysarg->recvmsg);

	if (reg->ret > 0) {
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->ref_nb++;

		if (socket_registered(proc, arg->sockfd) != -1) {
			if (!socket_netlink(proc, arg->sockfd)) {
				const char *mailbox;
				if (MSG_process_self() == file_desc->stream->client)
					mailbox = file_desc->stream->to_client;
				else if (MSG_process_self() == file_desc->stream->server)
					mailbox = file_desc->stream->to_server;
				else
					THROW_IMPOSSIBLE;

				msg_task_t task = NULL;
				msg_error_t err = MSG_task_receive(&task, mailbox);

				arg->ret = (int) MSG_task_get_data_size(task);
				arg->data = MSG_task_get_data(task);

				if (err != MSG_OK) {
					struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
					int sock_status = socket_get_state(is);
#ifdef address_translation
					if (sock_status & SOCKET_CLOSED)
						sys_build_recvmsg(proc, &(proc->sysarg));
#else
					if (sock_status & SOCKET_CLOSED)
						sysarg->recvmsg.ret = 0;
					ptrace_neutralize_syscall(pid);
					proc_outside(proc);
					sys_build_recvmsg(proc, &(proc->sysarg));
				} else {
					ptrace_neutralize_syscall(pid);
					proc_outside(proc);
					sys_build_recvmsg(proc, &(proc->sysarg));
#endif
				}
				MSG_task_destroy(task);
			}
		}
		file_desc->ref_nb--;
		file_desc = NULL;
	}
	XBT_DEBUG("recvmsg_pre");
}

/** @brief print recvmsg syscall at the exit */
static void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	// XBT_DEBUG("[%d] recvmsg_out", pid);
	XBT_DEBUG("recvmsg_post");
	get_args_recvmsg(proc, reg, sysarg);
	if (strace_option)
		print_recvmsg_syscall(proc, sysarg);
}

/** @brief helper function to deal with recvfrom syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
static void process_recvfrom_out_call(process_descriptor_t * proc)
{
	XBT_DEBUG("Entering process_RECVFROM_out_call");
	pid_t pid = proc->pid;
	// process_reset_state(proc);
	syscall_arg_u *sysarg = &(proc->sysarg);
	recvfrom_arg_t arg = &(sysarg->recvfrom);
	if (strace_option)
		print_recvfrom_syscall(proc, &(proc->sysarg));
	ptrace_restore_syscall(pid, SYS_recvfrom, arg->ret);
	ptrace_poke(pid, (void *) arg->dest, arg->data, arg->ret);
	free(arg->data);
}

/** @brief handle recvfrom syscall at the entrance
 *
 * In case of address translation, we first translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall. We also
 * receive the MSG task in order to unblock the MSG process sending the message
 *
 * In case of full mediation we receive the MSG task and we neutralize the
 * real syscall. We don't go to syscall_recvmsg_post afterwards.
 */
static void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	// XBT_DEBUG("[%d] RECVFROM_pre", pid);
	XBT_DEBUG("RECVFROM_pre");
	get_args_recvfrom(proc, reg, sysarg);

#ifdef address_translation
	if (socket_registered(proc, reg->arg[0]) != -1) {
		if (socket_network(proc, reg->arg[0])) {
			sys_translate_recvfrom_out(proc, sysarg);
		}
	}
#endif

	recvfrom_arg_t arg = &(sysarg->recvfrom);

	if (reg->ret > 0) {
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->ref_nb++;

		if (socket_registered(proc, arg->sockfd) != -1) {
			if (!socket_netlink(proc, arg->sockfd)) {
				const char *mailbox;
				if (MSG_process_self() == file_desc->stream->client)
					mailbox = file_desc->stream->to_client;
				else if (MSG_process_self() == file_desc->stream->server)
					mailbox = file_desc->stream->to_server;
				else
					THROW_IMPOSSIBLE;

				msg_task_t task = NULL;
				msg_error_t err = MSG_task_receive(&task, mailbox);

				arg->ret = (int) MSG_task_get_data_size(task);
				arg->data = MSG_task_get_data(task);

				if (err != MSG_OK) {
					struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
					int sock_status = socket_get_state(is);
#ifdef address_translation
					if (sock_status & SOCKET_CLOSED)
						process_recvfrom_out_call(proc);
#else
					if (sock_status & SOCKET_CLOSED)
						sysarg->recvfrom.ret = 0;
					ptrace_neutralize_syscall(pid);
					proc_outside(proc);
					process_recvfrom_out_call(proc);
				} else {
					ptrace_neutralize_syscall(pid);
					proc_outside(proc);
					process_recvfrom_out_call(proc);
#endif
				}
				MSG_task_destroy(task);
				file_desc->ref_nb--;
				file_desc = NULL;
			}
		}
	}
	XBT_DEBUG("recvfrom_pre");
}

/** @brief print recvfrom syscall at the exit */
static void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	// XBT_DEBUG("[%d] recvfrom_out", pid);
	XBT_DEBUG("recvfrom_post");
	get_args_recvfrom(proc, reg, sysarg);
	if (strace_option)
		print_recvfrom_syscall(proc, &(proc->sysarg));
}

/** @brief helper function to deal with read syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
static void process_read_out_call(process_descriptor_t * proc)
{
	XBT_DEBUG("Entering process_read_out_call");
	syscall_arg_u *sysarg = &(proc->sysarg);
	read_arg_t arg = &(sysarg->read);
	ptrace_restore_syscall(proc->pid, SYS_read, arg->ret);
	if (arg->ret > 0) {
		ptrace_poke(proc->pid, (void *) arg->dest, arg->data, arg->ret);
		free(arg->data);
	}
}

/** @brief handle read syscall at the entrance
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_read_post afterwards.
 */
static void syscall_read(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
		XBT_DEBUG(" read_pre");
		get_args_read(proc, reg, sysarg);
		read_arg_t arg = &(sysarg->read);
		fd_descriptor_t *file_desc = proc->fd_list[arg->fd];
		file_desc->ref_nb++;

		if (socket_registered(proc, reg->arg[0]) != -1) {
			const char *mailbox;
			if (MSG_process_self() == file_desc->stream->client)
				mailbox = file_desc->stream->to_client;
			else if (MSG_process_self() == file_desc->stream->server)
				mailbox = file_desc->stream->to_server;
			else
				THROW_IMPOSSIBLE;

			msg_task_t task = NULL;
			msg_error_t err = MSG_task_receive(&task, mailbox);

			arg->ret = (int) MSG_task_get_data_size(task);
			arg->data = MSG_task_get_data(task);

			if (err != MSG_OK) {
				struct infos_socket *is = get_infos_socket(proc, arg->fd);
				int sock_status = socket_get_state(is);
#ifdef address_translation
				if (sock_status & SOCKET_CLOSED)
					process_read_out_call(proc);
#else
				if (sock_status & SOCKET_CLOSED)
					sysarg->read.ret = 0;
				ptrace_neutralize_syscall(proc->pid);
				proc_outside(proc);
				process_read_out_call(proc);
			} else {
				ptrace_neutralize_syscall(proc->pid);
				proc_outside(proc);
				process_read_out_call(proc);
#endif
			}
			MSG_task_destroy(task);
		} else if (file_desc != NULL && file_desc->type == FD_PIPE) {
			if (strace_option)
				print_read_syscall(proc, sysarg);
			fprintf(stderr, "[%d] read pre, pipe \n", proc->pid);
			pipe_t *pipe = file_desc->pipe;
			if (pipe == NULL)
				THROW_IMPOSSIBLE;

			XBT_WARN("host %s trying to receive from pipe %d", MSG_host_get_name(proc->host), arg->fd);
			char buff[256];
			sprintf(buff, "%d", arg->fd);

			msg_task_t task = NULL;
			MSG_task_receive(&task, buff);
			arg->ret = (int) MSG_task_get_data_size(task);
			arg->data = MSG_task_get_data(task);
			XBT_WARN("hosts: %s received from pipe %d (size: %d)", MSG_host_get_name(proc->host), arg->fd, arg->ret);

			MSG_task_destroy(task);
		}
		file_desc->ref_nb--;
		file_desc = NULL;

	} else { // ---- Exiting syscall ---- //
		proc_outside(proc);
		XBT_DEBUG("read_post");
		get_args_read(proc, reg, sysarg);
		if (strace_option)
			print_read_syscall(proc, sysarg);
	}
}

/** @brief handle poll syscall */
// TODO: doesn't work. We do irecv on each file descriptor and then a waitany
static void syscall_poll_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	get_args_poll(proc, reg, sysarg);
	if (strace_option)
		print_poll_syscall(proc, sysarg);

	poll_arg_t arg = (poll_arg_t) & (proc->sysarg.poll);

	//  XBT_WARN("Poll: Timeout not handled\n");

	/*  int i;
  xbt_dynar_t comms = xbt_dynar_new(sizeof(msg_comm_t), NULL);
  xbt_dynar_t backup = xbt_dynar_new(sizeof(int), NULL);*/

	// for (i = 0; i < arg->nbfd; ++i) {
	if (arg->nbfd > 1)
		XBT_WARN("Poll only handles one fd\n");

	struct pollfd *temp = &(arg->fd_list[0]);
	msg_comm_t comm;
	struct infos_socket *is = get_infos_socket(proc, temp->fd);

	if (is != NULL) {
		is->ref_nb++;
		//   continue;
		//  else {
		int sock_status = socket_get_state(is);
		XBT_DEBUG("%d-> %d\n", temp->fd, sock_status);
		if (temp->events & POLLIN) {
			msg_task_t task = NULL;
			XBT_DEBUG("irecv");
			comm = MSG_task_irecv(&task, MSG_host_get_name(is->host));
			//   xbt_dynar_push(comms, comm);
			//   xbt_dynar_push(backup, &i);
		} else
			XBT_WARN("Poll only handles POLLIN for now\n");

		is->ref_nb--;
	}
	//  }
	XBT_DEBUG("wait");
	//  int nb = MSG_comm_waitany(comms);
	//  msg_comm_t comm = xbt_dynar_get_ptr(comms, nb);
	//  int j = xbt_dynar_get_as(comms, nb, int);
	msg_error_t err = MSG_comm_wait(comm, arg->timeout);
	if (err == MSG_OK) {
		//  struct pollfd *temp = &(arg->fd_list[j]);
		temp->revents = temp->revents | POLLIN;

		XBT_DEBUG("Result for poll\n");
		sys_build_poll(proc, &(proc->sysarg), 1);
		if (strace_option)
			print_poll_syscall(proc, &(proc->sysarg));
		free(proc->sysarg.poll.fd_list);
	} else if (err == MSG_TIMEOUT) {
		XBT_DEBUG("Time out on poll\n");
		sys_build_poll(proc, &(proc->sysarg), 0);
		if (strace_option)
			print_poll_syscall(proc, &(proc->sysarg));
		free(proc->sysarg.poll.fd_list);
	}
}

/** @brief print poll syscall at the exit */
static void syscall_poll_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_poll(proc, reg, sysarg);
	if (strace_option)
		print_poll_syscall(proc, sysarg);
}

/** @brief create a SimTerpose pipe and the corresponding file descriptors */
static void syscall_pipe_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_pipe(proc, reg, sysarg);
	pipe_arg_t arg = &(sysarg->pipe);

	// TODO: add gestion of O_NONBLOCK and O_CLOEXEC flags

	if (arg->ret == 0) {
		// we create the pipe
		int p0 = *arg->filedes;
		int p1 = *(arg->filedes + 1);

		pipe_end_t in = malloc(sizeof(pipe_end_s));
		in->fd = p0;
		in->proc = proc;

		pipe_end_t out = malloc(sizeof(pipe_end_s));
		out->fd = p1;
		out->proc = proc;

		xbt_dynar_t end_in = xbt_dynar_new(sizeof(pipe_end_t), NULL);
		xbt_dynar_t end_out = xbt_dynar_new(sizeof(pipe_end_t), NULL);

		xbt_dynar_push(end_in, &in);
		xbt_dynar_push(end_out, &out);

		pipe_t *pipe = malloc(sizeof(pipe_t));
		pipe->read_end = end_in;
		pipe->write_end = end_out;

		// we create the fd
		fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
		file_desc->ref_nb = 0;
		file_desc->fd = p0;
		file_desc->proc = proc;
		file_desc->type = FD_PIPE;
		file_desc->pipe = pipe;
		proc->fd_list[p0] = file_desc;
		file_desc->ref_nb++;

		file_desc = malloc(sizeof(fd_descriptor_t));
		file_desc->ref_nb = 0;
		file_desc->fd = p1;
		file_desc->proc = proc;
		file_desc->type = FD_PIPE;
		file_desc->pipe = pipe;
		proc->fd_list[p1] = file_desc;
		file_desc->ref_nb++;

		if (strace_option)
			fprintf(stderr, "[%d] pipe([%d,%d]) = %d \n", proc->pid, p0, p1, arg->ret);
	} else {
		if (strace_option)
			fprintf(stderr, "[%d] pipe = %d \n", proc->pid, arg->ret);
	}
}

// TODO
static void syscall_select_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	THROW_UNIMPLEMENTED;

	get_args_select(proc, reg, sysarg);
	if (strace_option)
		print_select_syscall(proc, sysarg);

	XBT_WARN("Select: Timeout not handled\n");

	XBT_DEBUG("Entering process_select_call");
	select_arg_t arg = &(proc->sysarg.select);
	int i;

	fd_set fd_rd, fd_wr, fd_ex;

	fd_rd = arg->fd_read;
	fd_wr = arg->fd_write;
	fd_ex = arg->fd_except;

	int match = 0;

	for (i = 0; i < arg->maxfd; ++i) {
		struct infos_socket *is = get_infos_socket(proc, i);
		//if i is NULL that means that i is not a socket
		if (is == NULL) {
			FD_CLR(i, &(fd_rd));
			FD_CLR(i, &(fd_wr));
			continue;
		}

		int sock_status = socket_get_state(is);
		if (FD_ISSET(i, &(fd_rd))) {
			if (sock_status & SOCKET_READ_OK || sock_status & SOCKET_CLOSED || sock_status & SOCKET_SHUT)
				++match;
			else
				FD_CLR(i, &(fd_rd));
		}
		if (FD_ISSET(i, &(fd_wr))) {
			if (sock_status & SOCKET_WR_NBLK && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
				++match;
			else
				FD_CLR(i, &(fd_wr));
		}
		if (FD_ISSET(i, &(fd_ex))) {
			XBT_WARN("Select does not handle exception states for now");
		}
	}
	if (match > 0) {
		XBT_DEBUG("match for select");
		arg->fd_read = fd_rd;
		arg->fd_write = fd_wr;
		arg->fd_except = fd_ex;
		arg->ret = match;
		sys_build_select(proc, &(proc->sysarg), match);
		if (strace_option)
			print_select_syscall(proc, &(proc->sysarg));
	}
}

/** @brief handle clone syscall at the exit
 *
 * We're at the exit of the syscall, so we need to check whether we are in
 * the parent or the clone. If we are in the clone we actually create a new
 * MSG process which inherits the file descriptors from the parent.
 */
static void syscall_clone_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	int ret = reg->ret;
	proc_outside(proc);

	if (ret > 0) {
		// we are in the parent
		int pid_clone = ptrace_get_pid_clone(proc->pid);
		XBT_DEBUG("clone_post in parent, ret = %d, pid_clone = %d", ret, pid_clone);
	} else {
		// we are in the clone
		int pid_clone = ptrace_get_pid_clone(proc->pid);
		XBT_DEBUG("clone_post in clone, ret = %d, pid_clone = %d", ret, pid_clone);
		proc_outside(proc);

		get_args_clone(proc, reg, sysarg);
		clone_arg_t arg = &(sysarg->clone);

		process_descriptor_t *clone = process_descriptor_new(proc->name, bprintf("cloned_%d",pid_clone), pid_clone);

		// the clone inherits the fd_list but subsequent actions on fd
		// do NOT affect the parent unless CLONE_FILES is set
		int i;
		for (i = 0; i < MAX_FD; ++i) {
			clone->fd_list[i] = malloc(sizeof(fd_descriptor_t));
			clone->fd_list[i]->proc = clone;
			clone->fd_list[i]->ref_nb = 0;
			if (proc->fd_list[i] != NULL) {
				clone->fd_list[i]->fd = proc->fd_list[i]->fd;
				clone->fd_list[i]->flags = proc->fd_list[i]->flags;
				clone->fd_list[i]->pipe = proc->fd_list[i]->pipe;
				clone->fd_list[i]->stream = proc->fd_list[i]->stream;
				clone->fd_list[i]->type = proc->fd_list[i]->type;
			}
			// deal with pipes
			if (clone->fd_list[i]->type == FD_PIPE) {
				pipe_t *pipe = clone->fd_list[i]->pipe;
				xbt_assert(pipe != NULL);

				// copy all the fds in the read end of the pipe
				unsigned int cpt_in;
				pipe_end_t end_in;
				xbt_dynar_t read_end = pipe->read_end;
				xbt_dynar_foreach(read_end, cpt_in, end_in) {
					// we have to make sure we don't add endlessly the fd from the clone
					//FIXME we still add pipes twice sometimes
					if (end_in->proc != clone && end_in->proc->pid != clone->pid) {
						xbt_assert(end_in != NULL);
						pipe_end_t clone_end = malloc(sizeof(pipe_end_s));
						clone_end->fd = end_in->fd;
						clone_end->proc = clone;
						xbt_dynar_push(read_end, &clone_end);
					}
				}

				// copy all the fds in the write end of the pipe
				xbt_dynar_t write_end = pipe->write_end;
				unsigned int cpt_out;
				pipe_end_t end_out;
				xbt_dynar_foreach(write_end, cpt_out, end_out) {
					// we have to make sure we don't add endlessly the fd from the clone
					if (end_out->proc != clone && end_out->proc->pid != clone->pid) {
						xbt_assert(end_out != NULL);
						pipe_end_t clone_end = malloc(sizeof(pipe_end_s));
						clone_end->fd = end_out->fd;
						clone_end->proc = clone;
						xbt_dynar_push(write_end, &clone_end);
					}
				}

			}
		}

		unsigned long flags = arg->clone_flags;

		if (flags & CLONE_VM)
			XBT_WARN("CLONE_VM unhandled");
		if (flags & CLONE_FS)
			XBT_WARN("CLONE_FS unhandled");
		if (flags & CLONE_FILES)
			xbt_die("CLONE_FILES unhandled");
		if (flags & CLONE_SIGHAND)
			XBT_WARN("CLONE_SIGHAND unhandled");
		if (flags & CLONE_PTRACE)
			XBT_WARN("CLONE_PTRACE ignored");
		if (flags & CLONE_VFORK)
			XBT_WARN("CLONE_VFORK unhandled");
		if (flags & CLONE_PARENT)
			XBT_WARN("CLONE_PARENT unhandled");
		if (flags & CLONE_THREAD)
			XBT_WARN("CLONE_THREAD unhandled");
		if (flags & CLONE_NEWNS)
			XBT_WARN("CLONE_NEWNS unhandled");
		if (flags & CLONE_SYSVSEM)
			XBT_WARN("CLONE_SYSVSEM unhandled");
		if (flags & CLONE_SETTLS)
			XBT_WARN("CLONE_SETTLS unhandled");
		if (flags & CLONE_UNTRACED)
			XBT_WARN("CLONE_UNTRACED unhandled");
		if (flags & CLONE_NEWUTS)
			XBT_WARN("CLONE_NEWUTS unhandled");
		if (flags & CLONE_NEWIPC)
			XBT_WARN("CLONE_NEWIPC unhandled");
		if (flags & CLONE_NEWUSER)
			XBT_WARN("CLONE_NEWUSER unhandled");
		if (flags & CLONE_NEWPID)
			XBT_WARN("CLONE_NEWPID unhandled");
		if (flags & CLONE_NEWNET)
			XBT_WARN("CLONE_NEWNET unhandled");
		if (flags & CLONE_IO)
			XBT_WARN("CLONE_IO unhandled");

		// TODO handle those flags
		if (flags & CLONE_PARENT_SETTID)
			XBT_WARN("CLONE_PARENT_SETTID unhandled");
		if (flags & CLONE_CHILD_CLEARTID)
			XBT_WARN("CLONE_CHILD_CLEARTID unhandled");
		if (flags & CLONE_CHILD_SETTID)
			XBT_WARN("CLONE_CHILD_SETTID unhandled");

		arg->ret = clone->pid;
		ptrace_restore_syscall(proc->pid, SYS_clone, arg->ret);

		if (strace_option)
			print_clone_syscall(proc, sysarg);

		char name[256];
		sprintf(name, "clone n°%d of %s", ++clone_number, MSG_process_get_name(MSG_process_self()));
		XBT_DEBUG("Creating %s, pid = %d", name, clone->pid);
		// FIXME: the current MSG process should not continue past that point:
		//        the clone is started, current can go back to its own considerations.
		// but maybe we want to start the clone in a different manner?
		MSG_process_create(name, main_loop, clone, MSG_host_self());
		proc_inside(proc);
	}
}

static void process_close_call(process_descriptor_t * proc, int fd);

/** @brief print execve syscall at the entrance */
static void syscall_execve_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	get_args_execve(proc, reg, sysarg);
	XBT_DEBUG("execve_pre");
	if (strace_option)
		print_execve_syscall_pre(proc, sysarg);

}

/** @brief handle execve syscall at the exit
 *
 * If execve real syscall is successful it returns one more time so we add a
 * third state for this syscall (in addition to "in" or "out")
 */
static void syscall_execve_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc->in_syscall == 1) {
		get_args_execve(proc, reg, sysarg);
		if (reg->ret == 0)
			proc->in_syscall = 2;
		else
			proc_outside(proc);
		if (strace_option)
			print_execve_syscall_post(proc, sysarg);
		XBT_DEBUG("execve_post");
	} else {
		proc_outside(proc);
		int i;
		for (i = 0; i < MAX_FD; ++i) {
			if (proc->fd_list[i] != NULL) {
				// XBT_WARN("fd n° %d; proc->fd_list[i]->flags = %d\n ", i, proc->fd_list[i]->flags);
				if (proc->fd_list[i]->flags == FD_CLOEXEC)
					XBT_WARN("FD_CLOEXEC not handled");
				//process_close_call(proc, i);
			}
		}
		XBT_DEBUG("execve retour");
	}
}

/** @brief create a file descriptor */
static void syscall_creat_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	if ((int) reg->ret >= 0) {
		fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
		file_desc->ref_nb = 0;
		file_desc->fd = (int) reg->ret;
		file_desc->proc = proc;
		file_desc->type = FD_CLASSIC;
		proc->fd_list[(int) reg->ret] = file_desc;
		file_desc->ref_nb++;
	}
}

/** @brief open a new file descriptor */
static void syscall_open(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
	} else {
		proc_outside(proc);

		open_arg_t arg = &(sysarg->open);
		arg->ret = reg->ret;
		arg->ptr_filename = reg->arg[0];
		arg->flags = reg->arg[1]; // FIXME arg[1] value is always 0, so we don't print actual flags for now

		if (arg->ret >= 0) {
			fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
			file_desc->ref_nb = 0;
			file_desc->fd = arg->ret;
			file_desc->proc = proc;
			file_desc->type = FD_CLASSIC;
			proc->fd_list[(int) reg->ret] = file_desc;
			file_desc->ref_nb++;
		}
		// TODO handle flags
		if (strace_option)
			print_open_syscall(proc, sysarg);
	}
}

/** @brief helper function to close a file descriptor */
static void process_close_call(process_descriptor_t * proc, int fd)
{
	fd_descriptor_t *file_desc = proc->fd_list[fd];
	if (file_desc != NULL) {
		file_desc->ref_nb++;
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
		file_desc->ref_nb--;
		proc->fd_list[fd] = NULL;
	}
}

static void syscall_close(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
	} else {
		proc_outside(proc);
		int fd = reg->arg[0];
		process_close_call(proc, fd);
		if(strace_option) {
			fprintf(proc->strace_out, "close(%d)                  %s%s            = %ld\n",
					fd,  (fd>9? "":" "), (fd>99?"":" "),reg->ret);
		}
	}
}

/** @brief handle shutdown syscall at the entrace if in full mediation
 *
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_shutdown_post afterwards.
 */
static void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
#ifndef address_translation
	XBT_DEBUG(" shutdown_pre");
	shutdown_arg_t arg = &(sysarg->shutdown);
	arg->fd = reg->arg[0];
	arg->how = reg->arg[1];
	arg->ret = reg->ret;

	ptrace_neutralize_syscall(proc->pid);
	arg->ret = 0;
	ptrace_restore_syscall(proc->pid, SYS_shutdown, arg->ret);
	proc_outside(proc);
	if (strace_option)
		print_shutdown_syscall(proc, sysarg);
#endif
}

/** @brief handle shutdown syscall at the exit in case of address translation */
static void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	XBT_DEBUG(" shutdown_post");
	proc_outside(proc);
	shutdown_arg_t arg = &(sysarg->shutdown);
	arg->fd = reg->arg[0];
	arg->how = reg->arg[1];
	arg->ret = reg->ret;

	struct infos_socket *is = get_infos_socket(proc, arg->fd);
	if (is == NULL) {
		arg->ret = -EBADF;
		return;
	}
	comm_shutdown(is);

	if (strace_option)
		print_shutdown_syscall(proc, sysarg);
}

static int syscall_exit(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
		ptrace_detach_process(pid);
		return PROCESS_DEAD;
	} else {
		THROW_IMPOSSIBLE;
	}
}

/** @brief handle getpeername syscall */
static void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	getpeername_arg_t arg = &(sysarg->getpeername);
	pid_t pid = proc->pid;

	arg->ret = reg->ret;
	arg->sockfd = reg->arg[0];
	arg->sockaddr_dest = (void *) reg->arg[1];
	arg->len_dest = (void *) reg->arg[2];
	ptrace_cpy(proc->pid, &(arg->len), arg->len_dest, sizeof(socklen_t), "getpeername");

	if (socket_registered(proc, arg->sockfd)) {
		if (socket_network(proc, arg->sockfd)) {
			struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
			struct sockaddr_in in;
			socklen_t size = 0;
			if (!comm_getpeername(is, &in, &size)) {
				if (size < arg->len)
					arg->len = size;
				arg->in = in;
				arg->ret = 0;
			} else
				arg->ret = -ENOTCONN;   /* ENOTCONN 107 End point not connected */

			ptrace_neutralize_syscall(pid);
			proc_outside(proc);
			ptrace_restore_syscall(pid, SYS_getpeername, arg->ret);
			if (arg->ret == 0) {
				ptrace_poke(pid, arg->len_dest, &(arg->len), sizeof(socklen_t));
				ptrace_poke(pid, arg->sockaddr_dest, &(arg->in), sizeof(struct sockaddr_in));
			}
			if (strace_option)
				print_getpeername_syscall(proc, sysarg);
		}
	}
}

/** @brief handle getsockopt syscall at entrance if in full mediation */
static void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
#ifndef address_translation
	get_args_getsockopt(proc, reg, sysarg);
	getsockopt_arg_t arg = &(sysarg->getsockopt);
	pid_t pid = proc->pid;

	arg->ret = 0;
	if (arg->optname == SO_REUSEADDR) {
		arg->optlen = sizeof(int);
		arg->optval = malloc(arg->optlen);
		*((int *) arg->optval) = socket_get_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR);
	} else {
		XBT_WARN("Option non supported by Simterpose.");
		arg->optlen = 0;
		arg->optval = NULL;
	}

	ptrace_neutralize_syscall(pid);
	ptrace_restore_syscall(pid, SYS_getsockopt, arg->ret);

	if (arg->optname == SO_REUSEADDR) {
		ptrace_poke(pid, (void *) arg->dest, &(arg->optval), sizeof(arg->optlen));
		ptrace_poke(pid, (void *) arg->dest_optlen, &(arg->optlen), sizeof(socklen_t));
	}

	free(arg->optval);
	proc_outside(proc);
	if (strace_option)
		print_getsockopt_syscall(proc, sysarg);
#endif
}

/** @brief print getsockopt syscall at the exit */
static void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_getsockopt(proc, reg, sysarg);
	if (strace_option)
		print_getsockopt_syscall(proc, sysarg);
}

/** @brief handle setsockopt syscall at entrance if in full mediation */
static void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
#ifndef address_translation
	get_args_setsockopt(proc, reg, sysarg);
	setsockopt_arg_t arg = &(sysarg->setsockopt);
	pid_t pid = proc->pid;
	//TODO really handle setsockopt that currently raise a warning
	arg->ret = 0;

	if (arg->optname == SO_REUSEADDR)
		socket_set_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR, *((int *) arg->optval));
	else
		XBT_WARN("Option non supported by Simterpose.");

	ptrace_neutralize_syscall(pid);
	ptrace_restore_syscall(pid, SYS_setsockopt, arg->ret);

	proc_outside(proc);
	if (strace_option)
		print_setsockopt_syscall(proc, sysarg);
	free(sysarg->setsockopt.optval);
#endif
}

/** @brief print setsockopt syscall at the exit */
static void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_setsockopt(proc, reg, sysarg);
	if (strace_option)
		print_setsockopt_syscall(proc, sysarg);
}

/** @brief helper function to handle fcntl syscall */
// TODO: handle the other flags
static void process_fcntl_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	XBT_DEBUG("process fcntl");
	fcntl_arg_t arg = &(sysarg->fcntl);
	switch (arg->cmd) {

	case F_DUPFD:
		XBT_WARN("F_DUPFD unhandled");
		break;

	case F_DUPFD_CLOEXEC:
		XBT_WARN("F_DUPFD_CLOEXEC unhandled");
		break;

	case F_GETFD:
#ifndef address_translation
		arg->ret = proc->fd_list[arg->fd]->flags;
#endif
		break;

	case F_SETFD:
		proc->fd_list[arg->fd]->flags = arg->arg;
		break;

	case F_GETFL:
		XBT_WARN("F_GETFL unhandled");
		break;

	case F_SETFL:
		socket_set_flags(proc, arg->fd, arg->arg);
		break;

	case F_SETLK:
		XBT_WARN("F_SETLK unhandled");
		break;

	case F_SETLKW:
		XBT_WARN("F_SETLKW unhandled");
		break;

	case F_GETLK:
		XBT_WARN("F_GETLK unhandled");
		break;

	default:
		XBT_WARN("Unknown fcntl flag");
		break;
	}
#ifndef address_translation
	ptrace_neutralize_syscall(proc->pid);
	ptrace_restore_syscall(proc->pid, SYS_fcntl, arg->ret);
	proc_outside(proc);
#endif
}

static void syscall_fcntl(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
		XBT_DEBUG("fcntl pre");
#ifndef address_translation
		get_args_fcntl(proc, reg, sysarg);
		process_fcntl_call(proc, sysarg);
		if (strace_option)
			print_fcntl_syscall(proc, sysarg);
		sleep(4);
#endif
	} else {
		proc_outside(proc);
		XBT_DEBUG("fcntl post");
		get_args_fcntl(proc, reg, sysarg);
		if (strace_option)
			print_fcntl_syscall(proc, sysarg);
#ifdef address_translation
		process_fcntl_call(proc, sysarg);
#endif
	}
}

/** @brief handle dup2 by updating the table of file descriptors, and also the pipe objects if needed */
static void syscall_dup2_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	unsigned int oldfd = (int) reg->arg[0];
	unsigned int newfd = (int) reg->arg[1];

	fd_descriptor_t *file_desc = proc->fd_list[oldfd];
	file_desc->ref_nb++;
	proc->fd_list[newfd]->ref_nb--;
	process_close_call(proc, newfd);
	proc->fd_list[newfd] = file_desc;
	file_desc->ref_nb++;

	if (strace_option)
		fprintf(stderr, "[%d] dup2(%d, %d) = %ld \n", proc->pid, oldfd, newfd, reg->ret);

	if (file_desc->type == FD_PIPE) {
		pipe_t *pipe = file_desc->pipe;

		// look for the fd in the read end of the pipe
		xbt_dynar_t read_end = pipe->read_end;
		unsigned int cpt_in;
		pipe_end_t end_in;
		xbt_dynar_foreach(read_end, cpt_in, end_in) {
			if (end_in->fd == oldfd && end_in->proc == proc) {
				pipe_end_t dup_end = malloc(sizeof(pipe_end_s));
				dup_end->fd = newfd;
				dup_end->proc = end_in->proc;
				xbt_dynar_push(read_end, &dup_end);
			}
		}

		// look for the fd in the write end of the pipe
		xbt_dynar_t write_end = pipe->write_end;
		unsigned int cpt_out;
		pipe_end_t end_out;
		xbt_dynar_foreach(write_end, cpt_out, end_out) {
			if (end_out->fd == oldfd && end_out->proc == proc) {
				pipe_end_t dup_end = malloc(sizeof(pipe_end_s));
				dup_end->fd = newfd;
				dup_end->proc = end_out->proc;
				xbt_dynar_push(write_end, &dup_end);
			}
		}
	}
}

/** @brief handle socket syscall by creating and registering a new socket */
static void syscall_socket_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);

	socket_arg_t arg = &sysarg->socket;
	arg->ret = reg->ret;
	arg->domain = (int) reg->arg[0];
	arg->type = (int) reg->arg[1];
	arg->protocol = (int) reg->arg[2];

	if (strace_option)
		print_socket_syscall(proc, sysarg);

	if (arg->ret > 0)
		register_socket(proc, arg->ret, arg->domain, arg->protocol);
}

/** @brief helper function to handle listen syscall
 *
 * We create a new communication and put it in a listening state.
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_listen_post afterwards.
 *
 */
static void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	listen_arg_t arg = &(sysarg->listen);
	struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
	comm_t comm = comm_new(is);
	comm_set_listen(comm);

#ifndef address_translation
	pid_t pid = proc->pid;
	arg->ret = 0;
	ptrace_neutralize_syscall(pid);
	arg = &(sysarg->listen);
	ptrace_restore_syscall(pid, SYS_listen, arg->ret);
	proc_outside(proc);
#endif
}

static void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {

		proc_inside(proc);
#ifndef address_translation
		get_args_listen(proc, reg, sysarg);
		process_listen_call(proc, sysarg);
		if (strace_option)
			print_listen_syscall(proc, sysarg);
#endif
	} else {
		proc_outside(proc);
#ifdef address_translation
		get_args_listen(proc, reg, sysarg);
		process_listen_call(proc, sysarg);
		if (strace_option)
			print_listen_syscall(proc, sysarg);
#else
		THROW_IMPOSSIBLE;
#endif
	}
}

/** @brief handle bind syscall */
static void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	get_args_bind_connect(proc, reg, sysarg);
	bind_arg_t arg = &(sysarg->bind);
	pid_t pid = proc->pid;
	if (socket_registered(proc, arg->sockfd)) {
		if (socket_network(proc, arg->sockfd)) {

			if (!is_port_in_use(proc->host, ntohs(arg->sai.sin_port))) {
				XBT_DEBUG("Port %d is free", ntohs(arg->sai.sin_port));
				register_port(proc->host, ntohs(arg->sai.sin_port));

				struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
				int device = 0;
				if (arg->sai.sin_addr.s_addr == INADDR_ANY)
					device = (PORT_LOCAL | PORT_REMOTE);
				else if (arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
					device = PORT_LOCAL;
				else
					device = PORT_REMOTE;

				set_port_on_binding(proc->host, ntohs(arg->sai.sin_port), is, device);

				is->binded = 1;

				set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(arg->sai.sin_addr), ntohs(arg->sai.sin_port));
				arg->ret = 0;
#ifdef address_translation
				int port = ptrace_find_free_binding_port(pid);
				XBT_DEBUG("Free port found %d", port);
				proc_outside(proc);
				set_real_port(proc->host, ntohs(arg->sai.sin_port), port);
				add_new_translation(port, ntohs(arg->sai.sin_port), get_ip_of_host(proc->host));
				if (strace_option)
					print_bind_syscall(proc, sysarg);
				return;
#endif
			} else {
				XBT_DEBUG("Port %d isn't free", ntohs(arg->sai.sin_port));
				arg->ret = -EADDRINUSE; /* EADDRINUSE 98 Address already in use */
				ptrace_neutralize_syscall(pid);
				bind_arg_t arg = &(sysarg->bind);
				ptrace_restore_syscall(pid, SYS_bind, arg->ret);
				proc_outside(proc);
				if (strace_option)
					print_bind_syscall(proc, sysarg);
				return;
			}
#ifndef address_translation
			ptrace_neutralize_syscall(pid);
			bind_arg_t arg = &(sysarg->bind);
			ptrace_restore_syscall(pid, SYS_bind, arg->ret);
			proc_outside(proc);
#endif
		}
	}
	if (strace_option)
		print_bind_syscall(proc, sysarg);
}

/** @brief print bind syscall at the exit */
static void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_bind_connect(proc, reg, sysarg);
	if (strace_option)
		print_bind_syscall(proc, sysarg);
}


/** @brief helper function to handle accept syscall
 *
 * We use semaphores to synchronize client and server during a connection.
 */
static void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
	XBT_DEBUG(" CONNEXION: process_accept_out_call");
	accept_arg_t arg = &(sysarg->accept);

	if (arg->ret >= 0) {
		int domain = get_domain_socket(proc, arg->sockfd);
		int protocol = get_protocol_socket(proc, arg->sockfd);

		struct infos_socket *is = register_socket(proc, arg->ret, domain, protocol);

#ifdef address_translation
		sys_translate_accept_out(proc, sysarg);
#endif

		comm_join_on_accept(is, proc, arg->sockfd);

		struct infos_socket *s = get_infos_socket(proc, arg->sockfd);
		register_port(proc->host, s->port_local);

		struct in_addr in;
		if (s->ip_local == 0) {
			struct infos_socket *temp = is->comm->info[0].socket;

			if (temp->ip_local == inet_addr("127.0.0.1"))
				in.s_addr = inet_addr("127.0.0.1");
			else
				in.s_addr = get_ip_of_host(proc->host);
		} else
			in.s_addr = s->ip_local;

		set_localaddr_port_socket(proc, arg->ret, inet_ntoa(in), s->port_local);

		fd_descriptor_t *file_desc_is = (fd_descriptor_t *) is;
		fd_descriptor_t *file_desc_s = (fd_descriptor_t *) s;
		// we need to give the stream to the new socket
		file_desc_is->stream = file_desc_s->stream;
	}
}

/** @brief handle accept syscall at entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
static void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		XBT_DEBUG("syscall_accept_pre");
		proc_inside(proc);
		get_args_accept(proc, reg, sysarg);

		accept_arg_t arg = &(sysarg->accept);
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->ref_nb++;

		// We create the stream object for semaphores
		XBT_INFO("stream initialization by accept syscall");
		stream_t *stream = malloc(sizeof(stream_t));
		stream->sem_client = MSG_sem_init(0);
		stream->sem_server = MSG_sem_init(0);
		stream->server = MSG_process_self();
		stream->to_server = MSG_host_get_name(MSG_host_self());

		file_desc->stream = stream;
		XBT_DEBUG("accept_in: trying to take server semaphore ...");
		MSG_sem_acquire(file_desc->stream->sem_server);
		XBT_DEBUG("accept_in: took server semaphore! trying to release client");
		MSG_sem_release(file_desc->stream->sem_client);
		XBT_DEBUG("accept_in: client semaphore released !");

		//We try to find here if there's a connection to accept
		if (comm_has_connect_waiting(get_infos_socket(proc, arg->sockfd))) {
			struct sockaddr_in in;

#ifdef address_translation
			process_descriptor_t *conn_proc = comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
			arg->sai = in;
			ptrace_resume_process(conn_proc->pid);
#else
			comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
			arg->sai = in;
#endif

#ifndef address_translation
			pid_t pid = proc->pid;
			//Now we rebuild the syscall.
			int new_fd = ptrace_record_socket(pid);

			arg->ret = new_fd;
			ptrace_neutralize_syscall(pid);
			proc_outside(proc);

			accept_arg_t arg = &(sysarg->accept);
			ptrace_restore_syscall(pid, SYS_accept, arg->ret);

			ptrace_poke(pid, arg->addr_dest, &(arg->sai), sizeof(struct sockaddr_in));

			process_accept_out_call(proc, sysarg);

			if (strace_option)
				print_accept_syscall(proc, sysarg);

			XBT_DEBUG("accept_in: did the accept_out, before I go on I'm trying to take server semaphore ...");
			MSG_sem_acquire(file_desc->stream->sem_server);
			XBT_DEBUG("accept_in: took server semaphore! (2nd time)");
#endif
		}
		file_desc->ref_nb--;
		file_desc = NULL;


	} else { // **** Exit syscall ****

		proc_outside(proc);
		get_args_accept(proc, reg, sysarg);
#ifdef address_translation
		process_accept_out_call(proc, sysarg);
#endif

		if (strace_option)
			print_accept_syscall(proc, sysarg);

		// Never called by full mediation
		get_args_accept(proc, reg, sysarg);
		accept_arg_t arg = &(sysarg->accept);
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->ref_nb++;

		XBT_DEBUG("accept_post: trying to take server semaphore ...");
		MSG_sem_acquire(file_desc->stream->sem_server);
		XBT_DEBUG("accept_post: took server semaphore!");

		file_desc->ref_nb--;
		file_desc = NULL;
	}
}

/** @brief handle the return of a brk syscall (just display it in strace) */

static void syscall_brk_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {
	if (!strace_option)
		return;

	char buff[1024];
	if (reg->arg[0]) {
		sprintf(buff, "brk(                                    = ");
		int offset = sprintf(buff+4,"%#lx)",reg->arg[0]);
		buff[offset+4] = ' '; // kill the \0
	} else {
		sprintf(buff, "brk(0)                                  = ");
	}
	sprintf(buff+42,"%#lx\n",reg->ret);
	fprintf(proc->strace_out,buff);
}


/** @brief helper function to handle connect syscall */
static int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
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

/** @brief handle connect syscall at entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
static int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	XBT_DEBUG("syscall_connect_pre");
	get_args_bind_connect(proc, reg, sysarg);
	if (process_connect_in_call(proc, sysarg)) {
		connect_arg_t arg = &(sysarg->connect);

		struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
		struct infos_socket *s = comm_get_peer(is);
		fd_descriptor_t *file_desc = (fd_descriptor_t *) is;
		fd_descriptor_t *file_desc_remote = (fd_descriptor_t *) s;

		// We copy the stream to have it in both sides
		file_desc->stream = file_desc_remote->stream;
		file_desc->stream->client = MSG_process_self();
		file_desc->stream->to_client = MSG_host_get_name(MSG_host_self());

		XBT_DEBUG("connect_pre: trying to release server semaphore ...");
		MSG_sem_release(file_desc->stream->sem_server);
		XBT_DEBUG("connect_pre: server semaphore released, trying to take client semaphore ...");
		MSG_sem_acquire(file_desc->stream->sem_client);
		XBT_DEBUG("connect_pre: took client semaphore!");

		int status = 0;
		return process_handle(proc, status);
	} else {
		XBT_WARN("syscall_connect_pre: process_connect_in_call == 0  <--------- ");
		proc_outside(proc);
	}
	return PROCESS_CONTINUE;
}

/** @brief handle connect syscall at exit
 *
 * We use semaphores to synchronize client and server during a connection. */
static void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	XBT_DEBUG("connect_post");
	get_args_bind_connect(proc, reg, sysarg);

	connect_arg_t arg = &(sysarg->connect);
#ifdef address_translation
	int domain = get_domain_socket(proc, arg->sockfd);
	if (domain == 2 && arg->ret >= 0) {
		struct infos_socket *is = get_infos_socket(proc, arg->sockfd);

		sys_translate_connect_out(proc, sysarg);
		int port = socket_get_local_port(proc, arg->sockfd);
		set_real_port(proc->host, is->port_local, ntohs(port));
		add_new_translation(ntohs(port), is->port_local, get_ip_of_host(proc->host));
	}
#endif
	if (strace_option)
		print_connect_syscall(proc, sysarg);

	fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
	file_desc->ref_nb++;

	XBT_DEBUG("connect_post: trying to release server semaphore ...");
	MSG_sem_release(file_desc->stream->sem_server);
	XBT_DEBUG("connect_post: server semaphore released");

	file_desc->ref_nb--;
	file_desc = NULL;
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
int process_handle(process_descriptor_t * proc, int status)
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
			if (proc_entering(proc))
				proc_inside(proc);
			else
				syscall_socket_post(&arg, sysarg, proc);
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
			if (proc_entering(proc))
				proc_inside(proc);
			else
				syscall_clone_post(&arg, sysarg, proc);
			break;

		case SYS_execve:
			if (proc_entering(proc))
				syscall_execve_pre(&arg, sysarg, proc);
			else
				syscall_execve_post(&arg, sysarg, proc);
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
			if (proc_entering(proc)) {
				proc_inside(proc);
			} else {
				proc_outside(proc);
				syscall_brk_post(&arg,sysarg, proc);
			}
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
		waitpid(pid, &status, 0);
	}                             // while(1)

	THROW_IMPOSSIBLE;             //There's no way to quit the loop
	return 0;
}
