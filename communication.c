#include "sockets.h"
#include "communication.h"
#include "xbt.h"

#include <sys/types.h>
#include <stdlib.h>

xbt_dynar_t comm_list;

void init_comm()
{
  comm_list = xbt_dynar_new(sizeof(comm_t), NULL); 
}

comm_t comm_new(struct infos_socket* socket, unsigned int remote_ip, int remote_port)
{
//   printf("Creating new communication with peer %d %d\n", remote_ip, remote_port);
  comm_t res = malloc(sizeof(comm_s));
  
  socket->comm=res;
  
  printf("Register new connection for (%d,%d) (%d, %d)\n", 
                socket->ip_local, socket->port_local, remote_ip, remote_port);
  
  res->info[0].socket = socket;
  res->info[0].recv = recv_information_new();
  res->info[1].socket = NULL;
  res->info[1].recv = recv_information_new();
  
  res->remote_port = remote_port;
  res->remote_ip = remote_ip;
  
  res->state = COMM_OPEN;
  res->conn_wait = xbt_dynar_new(sizeof(pid_t), NULL);
  
  xbt_dynar_push(comm_list, &res);
  
  return res;
}


comm_t comm_find_incomplete(unsigned int ip, int port, struct infos_socket* is)
{
  comm_t temp;
  unsigned int cpt = 0;
  
  xbt_dynar_foreach(comm_list, cpt, temp)
  {
    struct infos_socket* socket = temp->info[0].socket;
    if(socket->ip_local == ip &&  socket->port_local == port)
    {
      //Now verify if it's the good one we want
      if(is->ip_local == temp->remote_ip && is->port_local == temp->remote_port) 
        return temp;
    }
  }
  printf("No communication found\n");
  return NULL;
}

void comm_join(comm_t comm, struct infos_socket* socket)
{
  socket->comm = comm;
  comm->info[1].socket = socket;
}

struct infos_socket* comm_get_peer(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if( comm->info[0].socket == is)
    return comm->info[1].socket;
  else
    return comm->info[0].socket;
}

recv_information* comm_get_own_recv(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if( comm->info[0].socket == is)
    return comm->info[0].recv;
  else
    return comm->info[1].recv;
}

recv_information* comm_get_peer_recv(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if( comm->info[0].socket == is)
    return comm->info[1].recv;
  else
    return comm->info[0].recv;
}

void comm_set_state(comm_t comm, int new_state)
{
  comm->state = new_state; 
}

void comm_set_close(comm_t comm)
{
  //Here we have to make an and.
  comm->state = comm->state & COMM_CLOSED;
}


int comm_close(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if( comm->info[0].socket == is)
    return 0;
  else
    return 1;
}


void comm_set_listen(comm_t comm)
{
  comm->state =  comm->state | COMM_LISTEN;
  printf("Listen do %d\n", comm->state & COMM_LISTEN);
}

int comm_ask_connect(unsigned int ip, int port, pid_t tid)
{
  comm_t temp;
  unsigned int cpt = 0;
  
  xbt_dynar_foreach(comm_list, cpt, temp)
  {
    if(temp->state & COMM_LISTEN)
    {
      struct infos_socket* socket = temp->info[0].socket;
      printf("Checking %d %d\n", socket->ip_local, socket->port_local);
      if((socket->ip_local == ip || socket->ip_local == 1)&&  socket->port_local == port)
      {
        //Now verify if it's a listening socket
        if(temp->state & COMM_LISTEN)
        {
          printf("Add to connection asking queue\n");
          xbt_dynar_push(temp->conn_wait, &tid);
          return socket->proc->pid;
        }
      }
    }
  }
  printf("Don't found listened socket %ud %d\n", ip, port);
  return 0;
}

pid_t comm_accept_connect(struct infos_socket* is)
{
  comm_t comm = is->comm;
  pid_t tid;
  if(comm==NULL)
    THROW_IMPOSSIBLE;
  if(xbt_dynar_is_empty(comm->conn_wait))
    return 0;
  xbt_dynar_shift(comm->conn_wait, &tid);
  return tid;
}

int comm_has_connect_waiting(struct infos_socket* is)
{
  comm_t comm = is->comm;
  return !xbt_dynar_is_empty(comm->conn_wait);
}

int comm_get_socket_state(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if(comm == NULL)
    THROW_IMPOSSIBLE;
  int res=0;
  recv_information* recv = comm_get_own_recv(is);
  if(recv->quantity_recv > 0 )
    res = res | SOCKET_READ_OK;
  if(!xbt_dynar_is_empty(comm->conn_wait))
    res = res | SOCKET_READ_OK;
  if(comm->state == COMM_CLOSED)
    res = res | SOCKET_CLOSED;
  
  return res;
}

