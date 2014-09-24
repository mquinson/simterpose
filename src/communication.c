/* communication --  functions to deal with accept, connect and communications between processes */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sockets.h"
#include "communication.h"
#include "xbt.h"
#include "data_utils.h"
#include "sysdep.h"

#include <sys/types.h>
#include <stdlib.h>
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(COMMUNICATION, simterpose, "communication log");

xbt_dynar_t comm_list;

/** @brief create the list containing all communications */
void comm_init()
{
	comm_list = xbt_dynar_new(sizeof(comm_t), NULL);
}

/** @brief destroy the list containing all communications */
void comm_exit()
{
	xbt_dynar_free(&comm_list);
}

/** @brief create a new communication object and add it to the list */
comm_t comm_new(struct infos_socket *socket)
{
	comm_t res = malloc(sizeof(comm_s));

	socket->comm = res;
	res->info[0].socket = socket;
	socket->ref_nb++;

	res->info[0].recv = recv_information_new();
	res->info[1].socket = NULL;
	res->info[1].recv = recv_information_new();

	res->state = COMM_OPEN;
	res->conn_wait = xbt_dynar_new(sizeof(comm_t), NULL);

	xbt_dynar_push(comm_list, &res);
	res->ref_nb++;

	return res;
}

/** @brief destroy a communication and remove it from the list */
void comm_destroy(comm_t comm)
{
	if (comm->info[0].socket != NULL)
		comm->info[0].socket->ref_nb--;
	if (comm->info[1].socket != NULL)
		comm->info[1].socket->ref_nb--;

	recv_information_destroy(comm->info[0].recv);
	recv_information_destroy(comm->info[1].recv);
	xbt_dynar_free(&comm->conn_wait);
	xbt_ex_t e;
	TRY {
		int i = xbt_dynar_search(comm_list, &comm);
		comm->ref_nb--;
		xbt_dynar_remove_at(comm_list, i, NULL);
	}
	CATCH(e) {
		XBT_DEBUG("Communication not found");
	}
	free(comm);
}

/** @brief retrieve the infos_socket at the other end of the communication */
struct infos_socket *comm_get_peer(struct infos_socket *is)
{
	comm_t comm = is->comm;
	if (comm->info[0].socket == is)
		return comm->info[1].socket;
	else
		return comm->info[0].socket;
}

/** @brief retrieve the information received on the socket */
recv_information *comm_get_own_recv(struct infos_socket * is)
{
	comm_t comm = is->comm;
	if (!comm)
		return NULL;

	if (comm->info[0].socket == is)
		return comm->info[0].recv;
	else
		return comm->info[1].recv;
}

/** @brief retrieve the information received at the other end of the communication */
recv_information *comm_get_peer_recv(struct infos_socket * is)
{
	comm_t comm = is->comm;
	if (comm->info[0].socket == is)
		return comm->info[1].recv;
	else
		return comm->info[0].recv;
}

/** @brief close the communication corresponding to the socket */
void comm_close(struct infos_socket *is)
{
	comm_t comm = is->comm;
	if (comm == NULL)
		return;

	if (comm->state == COMM_LISTEN) {
		struct infos_socket *is = comm->info[0].socket;
		unset_socket(is->fd.proc->pid, is);
		delete_socket(is);
		if (!is->ref_nb)
			free(is);
		else
			XBT_ERROR("info_socket refcount = %d", is->ref_nb);
		comm_destroy(comm);
	} else if (comm->state == COMM_CLOSED) {
		struct infos_socket *is = comm->info[0].socket;
		unset_socket(is->fd.proc->pid, is);
		delete_socket(is);
		if (!is->ref_nb)
			free(is);
		else
			XBT_ERROR("info_socket refcount = %d", is->ref_nb);
		is = comm->info[1].socket;
		unset_socket(is->fd.proc->pid, is);
		delete_socket(is);
		if (!is->ref_nb)
			free(is);
		else
			XBT_ERROR("info_socket refcount = %d", is->ref_nb);
		comm_destroy(comm);
	} else
		comm->state = COMM_CLOSED;
}

/** @brief shutdown the communication corresponding to the socket */
void comm_shutdown(struct infos_socket *is)
{
	comm_t comm = is->comm;
	if (comm == NULL)
		return;
	comm->state = COMM_SHUT;
}

/** @brief put the communication in listening state */
void comm_set_listen(comm_t comm)
{
	comm->state = COMM_LISTEN;
	XBT_DEBUG("Listen do %d", comm->state & COMM_LISTEN);
}

/** @brief ask for a connection on a given socket */
process_descriptor_t *comm_ask_connect(msg_host_t host, int port, process_descriptor_t * proc, int fd, int device)
{
	struct infos_socket *conn = get_binding_socket_host(host, port, device);
	if (!conn)
		return 0;

	comm_t comm = comm_new(get_infos_socket(proc, fd));
	xbt_dynar_push(conn->comm->conn_wait, &comm);
	comm->ref_nb++;

	struct infos_socket *is = get_infos_socket(proc, fd);

	if (conn->ip_local == 0) {
		if (conn->fd.proc == is->fd.proc)
			comm->remote_ip = inet_addr("127.0.0.1");
		else
			comm->remote_ip = get_ip_of_host(conn->fd.proc->host);
	} else
		comm->remote_ip = conn->ip_local;
	comm->remote_port = conn->port_local;


	if (comm->info[0].socket == is)
		comm->info[1].socket = conn;
	else
		comm->info[0].socket = conn;
	conn->ref_nb++;

	struct in_addr in = { comm->remote_ip };
	XBT_DEBUG("%s:%d", inet_ntoa(in), comm->remote_port);

	return conn->fd.proc;
}

/** @brief get the communication object after an accept */
void comm_join_on_accept(struct infos_socket *is, process_descriptor_t * proc, int fd_listen)
{
	struct infos_socket *sock_listen = get_infos_socket(proc, fd_listen);
	comm_t comm = sock_listen->comm;
	if (comm == NULL)
		THROW_IMPOSSIBLE;

	comm_t comm_conn;
	xbt_dynar_shift(comm->conn_wait, &comm_conn);
	comm_conn->ref_nb--;

	comm_conn->info[1].socket = is;
	is->ref_nb++;

	is->comm = comm_conn;
	comm_conn->ref_nb++;
}

/** @brief retrieve the address and port of the waiting process */
void comm_get_ip_port_accept(struct infos_socket *is, struct sockaddr_in *in)
{
	comm_t comm = is->comm;
	if (comm == NULL)
		THROW_IMPOSSIBLE;

	if (xbt_dynar_is_empty(comm->conn_wait))
		return;

	XBT_DEBUG("Store connected information");
	comm_t comm_conn;
	xbt_dynar_get_cpy(comm->conn_wait, 0, &comm_conn);

	//Store the ip and port of the process waiting to connect
	struct infos_socket *s = comm_conn->info[0].socket;
	memset(in, 0, sizeof(struct sockaddr_in));
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = s->ip_local;
	in->sin_port = htons(s->port_local);
}

/** @brief accept the connection of the waiting process */
process_descriptor_t *comm_accept_connect(struct infos_socket *is, struct sockaddr_in *in)
{
	comm_t comm = is->comm;
	if (comm == NULL)
		THROW_IMPOSSIBLE;

	if (xbt_dynar_is_empty(comm->conn_wait))
		return 0;
	comm_t comm_conn;
	xbt_dynar_get_cpy(comm->conn_wait, 0, &comm_conn);

	//Store the ip and port of the process waiting to connect
	struct infos_socket *s = comm_conn->info[0].socket;
	memset(in, 0, sizeof(struct sockaddr_in));
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = s->ip_local;
	in->sin_port = htons(s->port_local);

	XBT_DEBUG("Accept connection from %d", comm_conn->info[0].socket->port_local);
	return comm_conn->info[0].socket->fd.proc;
}


/** @brief retrieve sockaddr_in for getpeername syscall */
int comm_getpeername(struct infos_socket *is, struct sockaddr_in *in, socklen_t * sock)
{
	comm_t comm = is->comm;
	if (comm == NULL)
		return -1;

	struct infos_socket *peer = comm_get_peer(is);

	if (!peer) {
		struct in_addr in2 = { comm->remote_ip };
		XBT_DEBUG("%s:%d", inet_ntoa(in2), comm->remote_port);

		in->sin_addr.s_addr = comm->remote_ip;
		in->sin_port = comm->remote_port;
		in->sin_family = AF_INET;
		*sock = sizeof(struct sockaddr_in);
		return 0;
	}

	in->sin_addr.s_addr = peer->ip_local;
	in->sin_port = peer->port_local;
	in->sin_family = AF_INET;
	*sock = sizeof(struct sockaddr_in);
	return 0;
}

/** @brief check if there is a process waiting to connect */
int comm_has_connect_waiting(struct infos_socket *is)
{
	if (is == NULL)
		xbt_die("The socket does not exist");
	comm_t comm = is->comm;
	if (comm == NULL)
		xbt_die("The communication does not exist");
	return !xbt_dynar_is_empty(comm->conn_wait);
}

/** @brief retrieve the state of the socket */
int comm_get_socket_state(struct infos_socket *is)
{

	comm_t comm = is->comm;
	if (comm == NULL)
		return 0;
	int res = 0;
	recv_information *recv = comm_get_own_recv(is);
	struct infos_socket *peer = comm_get_peer(is);
	//    XBT_DEBUG("[%d](%d) Comm state %d %d %d",is->fd.pid, is->fd.fd, xbt_fifo_size(recv->data_fifo), !xbt_dynar_is_empty(comm->conn_wait), comm->state);
	XBT_DEBUG("(%d) Comm state %d %d %d", is->fd.fd, xbt_fifo_size(recv->data_fifo), !xbt_dynar_is_empty(comm->conn_wait),
			comm->state);
	if (xbt_fifo_size(recv->data_fifo))
		res = res | SOCKET_READ_OK;
	if (!xbt_dynar_is_empty(comm->conn_wait))
		res = res | SOCKET_READ_OK;
	if (comm->state == COMM_CLOSED)
		res = res | SOCKET_CLOSED;
	if (peer != NULL)
		res = res | SOCKET_WR_NBLK;
	if (comm->state == COMM_SHUT)
		res = res | SOCKET_SHUT;

	return res;
}

/** @brief send data to a process by putting it in his recv_task list */
void comm_send_data(struct infos_socket *is, task_comm_info * tci)
{
	recv_information *recv = comm_get_peer_recv(is);
	xbt_fifo_push(recv->recv_task, tci);
}

/** @brief retrieve data from the recv_task list */
task_comm_info *comm_get_send(struct infos_socket *is)
{
	recv_information *recv = comm_get_own_recv(is);
	return xbt_fifo_shift(recv->recv_task);
}

/** @brief create a MSG task and send it to a host */
msg_task_t create_send_communication_task(process_descriptor_t * proc_sender, struct infos_socket * is, double amount,
		msg_host_t sender, msg_host_t receiver)
{
	char buff[256];
	sprintf(buff, "%s send", proc_sender->name);

	msg_host_t *work_list = malloc(sizeof(msg_host_t) * 2);
	work_list[0] = sender;
	work_list[1] = receiver;

	msg_task_t task = MSG_parallel_task_create(buff, 2, work_list, 0, &amount, &(proc_sender->pid));

	task_comm_info *temp = malloc(sizeof(task_comm_info));
	temp->task = task;
	temp->sender_host = proc_sender->host;

	comm_send_data(is, temp);

	return task;
}

/** @brief send a task to a host */
void send_task(msg_host_t receiver, msg_task_t task)
{
	XBT_DEBUG("Entering send_task %s", MSG_task_get_name(task));
	MSG_task_send(task, MSG_host_get_name(receiver));
}
