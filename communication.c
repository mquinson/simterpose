#include "communication.h"
#include "sockets.h"

#include <sys/types.h>
#include <stdlib.h>


comm_t communication_new(pid_t pgid, struct socket_infos* socket)
{
  comm_t res = malloc(sizeof(communication_s));
  
  res->pgids[0] = pgid;
  res->pgids[1] = UNDECLARED_PGID;
  
  res->info[0].socket = socket;
  res->info[0].recv = recv_information_new();
  res->info[1].socket = NULL;
  res->info[1].recv = recv_information_new();
  
  return res;
}