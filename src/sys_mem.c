/* sys_mem -- handlers of all memory-related syscalls                        */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "simterpose.h"
#include "syscall_process.h"
#include "print_syscall.h"

#include "args_trace.h"
#include <unistd.h>
#include <xbt/asserts.h>
#include <xbt/dynar.h>
#include <xbt/ex.h>
#include <xbt/log.h>
#include <xbt/misc.h>
#include <xbt/sysdep.h>
//#include "xbt.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_MEM_PROCESS, simterpose, "Syscall memory process log");

void syscall_brk(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {
	if (proc_entering(proc)) {
		proc_inside(proc);
	} else {
		proc_outside(proc);

		if (!strace_option)
			return;

		if (reg->arg[0])
			stprintf(proc,"brk(%#lx)",reg->arg[0]);
		else
			stprintf(proc,"brk(0)");
		stprintf_tabto(proc);
		stprintf(proc,"= %#lx",reg->ret);
		stprintf_eol(proc);
	}
}


/** @brief handle read syscall at the entrance
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_read_post afterwards.
 */
void syscall_read(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
		XBT_DEBUG(" read_pre");
		get_args_read(proc, reg, sysarg);
		read_arg_t arg = &(sysarg->read);
		fd_descriptor_t *file_desc = proc->fd_list[arg->fd];
		file_desc->refcount++;

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
		file_desc->refcount--;
		file_desc = NULL;

	} else { // ---- Exiting syscall ---- //
		proc_outside(proc);
		XBT_DEBUG("read_post");
		get_args_read(proc, reg, sysarg);
		if (strace_option)
			print_read_syscall(proc, sysarg);
	}
}


/** @brief helper function to deal with read syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_read_out_call(process_descriptor_t * proc)
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

/** @brief handle write syscall at the entrance
 *
 * At entrance, in case of full mediation and if the socket is registered we retrieve the message intended
 * to be written by the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_write_post afterwards.
 *
 * At exit, we send the MSG task in order to return control to the MSG process reading the message
 */
int syscall_write(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
		file_desc->refcount++;

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

		file_desc->refcount--;
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

/** @brief open a new file descriptor */
void syscall_open(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
			file_desc->refcount = 0;
			file_desc->fd = arg->ret;
			file_desc->proc = proc;
			file_desc->type = FD_CLASSIC;
			proc->fd_list[(int) reg->ret] = file_desc;
			file_desc->refcount++;
		}
		// TODO handle flags
		if (strace_option)
			print_open_syscall(proc, sysarg);
	}
}


void syscall_close(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		proc_inside(proc);
	} else {
		proc_outside(proc);
		int fd = reg->arg[0];
		process_close_call(proc, fd);
		if(strace_option) {
			stprintf(proc,"close(%d)",fd);
			stprintf_tabto(proc);
			stprintf(proc,"= %ld",reg->ret);
			stprintf_eol(proc);
		}
	}
}

/** @brief handle poll syscall */
// TODO: doesn't work. We do irecv on each file descriptor and then a waitany
void syscall_poll_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_poll_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_poll(proc, reg, sysarg);
	if (strace_option)
		print_poll_syscall(proc, sysarg);
}

/** @brief create a SimTerpose pipe and the corresponding file descriptors */
void syscall_pipe_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
		file_desc->refcount = 0;
		file_desc->fd = p0;
		file_desc->proc = proc;
		file_desc->type = FD_PIPE;
		file_desc->pipe = pipe;
		proc->fd_list[p0] = file_desc;
		file_desc->refcount++;

		file_desc = malloc(sizeof(fd_descriptor_t));
		file_desc->refcount = 0;
		file_desc->fd = p1;
		file_desc->proc = proc;
		file_desc->type = FD_PIPE;
		file_desc->pipe = pipe;
		proc->fd_list[p1] = file_desc;
		file_desc->refcount++;

		if (strace_option)
			fprintf(stderr, "[%d] pipe([%d,%d]) = %d \n", proc->pid, p0, p1, arg->ret);
	} else {
		if (strace_option)
			fprintf(stderr, "[%d] pipe = %d \n", proc->pid, arg->ret);
	}
}

// TODO
void syscall_select_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
			if ((sock_status & SOCKET_READ_OK) || (sock_status & SOCKET_CLOSED) || (sock_status & SOCKET_SHUT))
				++match;
			else
				FD_CLR(i, &(fd_rd));
		}
		if (FD_ISSET(i, &(fd_wr))) {
			if ((sock_status & SOCKET_WR_NBLK) && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
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

/** @brief handle dup2 by updating the table of file descriptors, and also the pipe objects if needed */
void syscall_dup2_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	unsigned int oldfd = (int) reg->arg[0];
	unsigned int newfd = (int) reg->arg[1];

	fd_descriptor_t *file_desc = proc->fd_list[oldfd];
	file_desc->refcount++;
	proc->fd_list[newfd]->refcount--;
	process_close_call(proc, newfd);
	proc->fd_list[newfd] = file_desc;
	file_desc->refcount++;

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
