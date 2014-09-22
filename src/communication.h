/* communication --  functions to deal with accept, connect and communications between processes */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#define UNDECLARED_PGID -1

#define COMM_OPEN       0x001
#define COMM_CLOSED     0x002
#define COMM_LISTEN     0x004
#define COMM_SHUT       0x008

typedef struct comm_s comm_s;
typedef comm_s *comm_t;

#include "xbt.h"
#include "process_descriptor.h"
#include "sockets.h"
#include <sys/types.h>

typedef struct {
  struct infos_socket *socket;
  recv_information *recv;
} comm_info;


struct comm_s {
  unsigned int remote_ip;
  int remote_port;
  comm_info info[2];
  int state;
  xbt_dynar_t conn_wait;
  int ref_nb;                   // reference counting
};

typedef struct task_comm_info task_comm_info;

struct task_comm_info {
  msg_task_t task;
  msg_host_t sender_host;
};


void comm_init(void);

void comm_exit(void);

//Create a new communication and register socket passed into
comm_t comm_new(struct infos_socket *socket);

void comm_destroy(comm_t comm);

comm_t comm_find_incomplete(unsigned int ip, int port, struct infos_socket *is);

//Add a socket to a communication
void comm_join_on_accept(struct infos_socket *socket, process_descriptor_t * proc, int fd_listen);

struct infos_socket *comm_get_peer(struct infos_socket *is);

recv_information *comm_get_own_recv(struct infos_socket *is);

recv_information *comm_get_peer_recv(struct infos_socket *is);

void comm_shutdown(struct infos_socket *is);

void comm_set_listen(comm_t comm);

process_descriptor_t *comm_ask_connect(msg_host_t host, int port, process_descriptor_t * proc, int fd, int device);

process_descriptor_t *comm_accept_connect(struct infos_socket *is, struct sockaddr_in *in);

int comm_get_socket_state(struct infos_socket *is);

//Indicate if theres process which wait for connection on this socket
int comm_has_connect_waiting(struct infos_socket *is);

void comm_close(struct infos_socket *is);

void comm_send_data(struct infos_socket *is, task_comm_info * tci);

task_comm_info *comm_get_send(struct infos_socket *is);

int comm_getpeername(struct infos_socket *is, struct sockaddr_in *in, socklen_t * sock);

void comm_get_ip_port_accept(struct infos_socket *is, struct sockaddr_in *in);


msg_task_t create_send_communication_task(process_descriptor_t * proc_sender, struct infos_socket *is, double amount,
                                          msg_host_t sender, msg_host_t receiver);

void send_task(msg_host_t receiver, msg_task_t task);

#endif
