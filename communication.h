#ifndef INCLUDE_COMMUNICATION_H
#define INCLUDE_COMMUNICATION_H

#define UNDECLARED_PGID -1

#define COMM_OPEN     0x000
#define COMM_CLOSED   ~COMM_OPEN
#define COMM_LISTEN   0x001

typedef struct comm_s comm_s;
typedef comm_s *comm_t;

#include "sockets.h"
#include "xbt.h"
#include "task.h"
#include <sys/types.h>

typedef struct{
  struct infos_socket* socket;
  recv_information *recv;
}comm_info;


struct comm_s{
  unsigned int remote_ip;
  int remote_port;
  comm_info info[2];
  int state;
  xbt_dynar_t conn_wait;
};

void init_comm();

//Create a new communication and register socket passed into
comm_t comm_new(struct infos_socket* socket);

comm_t comm_find_incomplete(unsigned int ip, int port, struct infos_socket* is);

//Add a socket to a communication
void comm_join_on_accept(struct infos_socket* socket, pid_t pid, int fd_listen);

struct infos_socket* comm_get_peer(struct infos_socket* is);

recv_information* comm_get_own_recv(struct infos_socket* is);

recv_information* comm_get_peer_recv(struct infos_socket* is);

void comm_set_state(comm_t comm, int new_state);

void comm_set_close(comm_t comm);

void comm_set_listen(comm_t comm);

int comm_ask_connect(unsigned int ip, int port, pid_t tid, int fd);

pid_t comm_accept_connect(struct infos_socket* is);

int comm_get_socket_state(struct infos_socket* is);

//Indicate if theres process which wait for connection on this socket
int comm_has_connect_waiting(struct infos_socket* is);

void comm_close(struct infos_socket* is);

void comm_send_data(struct infos_socket *is, task_comm_info *tci);

task_comm_info* comm_get_send(struct infos_socket* is);

#endif