#ifndef INCLUDE_COMMUNICATION_H
#define INCLUDE_COMMUNICATION_H

#define UNDECLARED_PGID -1

typedef struct comm_s comm_s;
typedef comm_s *comm_t;

#include "sockets.h"
#include <sys/types.h>

typedef struct{
  struct infos_socket* socket;
  recv_information *recv;
}comm_info;


struct comm_s{
  unsigned int remote_ip;
  int remote_port;
  comm_info info[2];
};

void init_comm();

//Create a new communication and register socket passed into
comm_t comm_new(struct infos_socket* socket, unsigned int remote_ip, int remote_port);

comm_t comm_find_incomplete(unsigned int ip, int port, struct infos_socket* is);

//Add a socket to a communication
void comm_join(comm_t comm, struct infos_socket* socket);

#endif