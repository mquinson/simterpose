#ifndef INCLUDE_COMMUNICATION_H
#define INCLUDE_COMMUNICATION_H

#define UNDECLARED_PGID -1

typedef struct communication_s communication_s;
typedef communication_s *comm_t;

#include "sockets.h"
#include <sys/types.h>

typedef struct{
  struct socket_infos* socket;
  recv_information *recv;
}comm_info;

struct communication_s{
  pid_t pgids[2];
  comm_info info[2];
};


comm_t communication_new(pid_t pgid, struct socket_infos* socket);

#endif