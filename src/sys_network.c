/* sys_net -- Handlers of all network-related syscalls                       */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_network.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "sockets.h"
#include "syscall_process.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc))
		proc_inside(proc);
	else {
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
}

/** @brief handle connect syscall at entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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

		return process_handle(proc);
	} else {
		XBT_WARN("syscall_connect_pre: process_connect_in_call == 0  <--------- ");
		proc_outside(proc);
	}
	return PROCESS_CONTINUE;
}

/** @brief handle connect syscall at exit
 *
 * We use semaphores to synchronize client and server during a connection. */
void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
	file_desc->refcount++;

	XBT_DEBUG("connect_post: trying to release server semaphore ...");
	MSG_sem_release(file_desc->stream->sem_server);
	XBT_DEBUG("connect_post: server semaphore released");

	file_desc->refcount--;
	file_desc = NULL;
}

/** @brief handle accept syscall at entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc)) {
		XBT_DEBUG("syscall_accept_pre");
		proc_inside(proc);
		get_args_accept(proc, reg, sysarg);

		accept_arg_t arg = &(sysarg->accept);
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->refcount++;

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
		file_desc->refcount--;
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
		file_desc->refcount++;

		XBT_DEBUG("accept_post: trying to take server semaphore ...");
		MSG_sem_acquire(file_desc->stream->sem_server);
		XBT_DEBUG("accept_post: took server semaphore!");

		file_desc->refcount--;
		file_desc = NULL;
	}
}

/** @brief helper function to handle accept syscall
 *
 * We use semaphores to synchronize client and server during a connection.
 */
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
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





/** @brief handle sendto syscall at the entrance
 *
 * In case of full mediation, we retrieve the message intended to be sent by
 * the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_sendto_post afterwards.
 *
 * In case of address translation we translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall
 */
int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
/** @brief handle recvfrom syscall at the entrance
 *
 * In case of address translation, we first translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall. We also
 * receive the MSG task in order to unblock the MSG process sending the message
 *
 * In case of full mediation we receive the MSG task and we neutralize the
 * real syscall. We don't go to syscall_recvmsg_post afterwards.
 */
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
		file_desc->refcount++;

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
				file_desc->refcount--;
				file_desc = NULL;
			}
		}
	}
	XBT_DEBUG("recvfrom_pre");
}

/** @brief print recvfrom syscall at the exit */
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	// XBT_DEBUG("[%d] recvfrom_out", pid);
	XBT_DEBUG("recvfrom_post");
	get_args_recvfrom(proc, reg, sysarg);
	if (strace_option)
		print_recvfrom_syscall(proc, &(proc->sysarg));
}


/** @brief helper function to deal with recvfrom syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_recvfrom_out_call(process_descriptor_t * proc)
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
int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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

/** @brief handle recvmsg syscall at the entrance
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_recvmsg_post afterwards.
 */
void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_inside(proc);
	//  XBT_DEBUG("[%d] recvmsg_in", pid);
	XBT_DEBUG("recvmsg_pre");
	get_args_recvmsg(proc, reg, sysarg);
	recvmsg_arg_t arg = &(sysarg->recvmsg);

	if (reg->ret > 0) {
		fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
		file_desc->refcount++;

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
		file_desc->refcount--;
		file_desc = NULL;
	}
	XBT_DEBUG("recvmsg_pre");
}

/** @brief print recvmsg syscall at the exit */
void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	// XBT_DEBUG("[%d] recvmsg_out", pid);
	XBT_DEBUG("recvmsg_post");
	get_args_recvmsg(proc, reg, sysarg);
	if (strace_option)
		print_recvmsg_syscall(proc, sysarg);
}

/** @brief handle shutdown syscall at the entrace if in full mediation
 *
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_shutdown_post afterwards.
 */
void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
/** @brief handle bind syscall */
void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_bind_connect(proc, reg, sysarg);
	if (strace_option)
		print_bind_syscall(proc, sysarg);
}

/** @brief helper function to handle listen syscall
 *
 * We create a new communication and put it in a listening state.
 * In case of full mediation, we neutralize the real syscall and don't
 * go to syscall_listen_post afterwards.
 *
 */
void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
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

void syscall_listen(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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

/** @brief handle getpeername syscall */
void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_getsockopt(proc, reg, sysarg);
	if (strace_option)
		print_getsockopt_syscall(proc, sysarg);
}

/** @brief handle setsockopt syscall at entrance if in full mediation */
void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
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
void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	proc_outside(proc);
	get_args_setsockopt(proc, reg, sysarg);
	if (strace_option)
		print_setsockopt_syscall(proc, sysarg);
}
