#include "sockets.h"
#include "communication.h"
#include "xbt.h"
#include "task.h"

#include <sys/types.h>
#include <stdlib.h>

xbt_dynar_t comm_list;

void init_comm()
{
  comm_list = xbt_dynar_new(sizeof(comm_t), NULL); 
}

comm_t comm_new(struct infos_socket* socket)
{
//   printf("Creating new communication with peer %d %d\n", remote_ip, remote_port);
  comm_t res = malloc(sizeof(comm_s));
  
  socket->comm=res;
//    printf("New communication init by %d\n", socket->proc->pid); 
  res->info[0].socket = socket;
  res->info[0].recv = recv_information_new();
  res->info[1].socket = NULL;
  res->info[1].recv = recv_information_new();
  
  //TODO do a real gestion of communication state
  res->state = COMM_OPEN;
  res->conn_wait = xbt_dynar_new(sizeof(comm_t), NULL);
  
  xbt_dynar_push(comm_list, &res);
  
  return res;
}

void comm_destroy(comm_t comm)
{
  recv_information_destroy(comm->info[0].recv);
  recv_information_destroy(comm->info[1].recv);
  xbt_dynar_free(&comm->conn_wait);
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(comm_list, &comm);
    xbt_dynar_remove_at(comm_list, i, NULL);
  }
  CATCH(e){
    printf("Communication not found\n");
  } 
  free(comm);
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


void comm_close(struct infos_socket* is)
{
  printf("Closing communication\n");
  comm_t comm = is->comm;
  if(comm == NULL)
    return;
  if( comm->info[0].socket == is)
  {
    comm->info[0].socket = NULL;
    if(comm->state == COMM_CLOSED || comm->state == COMM_LISTEN)
      comm_destroy(comm);
    else
      comm->state = COMM_CLOSED;
  }
  else
  {
    comm->info[1].socket = NULL;
    if(comm->state == COMM_CLOSED)
      comm_destroy(comm);
    else
      comm->state = COMM_CLOSED;
  }
}

void comm_shutdown(struct infos_socket *is)
{
  comm_t comm = is->comm;
  if(comm == NULL)
    return;
  comm->state = COMM_SHUT;
}


void comm_set_listen(comm_t comm)
{
  comm->state =  comm->state | COMM_LISTEN;
  printf("Listen do %d\n", comm->state & COMM_LISTEN);
}

int comm_ask_connect(unsigned int ip, int port, pid_t tid, int fd)
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
          printf("Add to connection asking queue %d\n", socket->proc->pid);
          comm_t comm = comm_new(get_infos_socket(tid, fd));
          xbt_dynar_push(temp->conn_wait, &comm);
          return socket->proc->pid;
        }
      }
    }
  }
  printf("Don't found listened socket %ud %d\n", ip, port);
  return 0;
}

void comm_join_on_accept(struct infos_socket *is, pid_t pid, int fd_listen)
{
  struct infos_socket *sock_listen = get_infos_socket(pid, fd_listen);
  comm_t comm = sock_listen->comm;
  if(comm==NULL)
    THROW_IMPOSSIBLE;
  
  comm_t comm_conn;
  xbt_dynar_shift(comm->conn_wait, &comm_conn);
  
  comm_conn->info[1].socket = is;
  is->comm = comm_conn;
}

pid_t comm_accept_connect(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if(comm==NULL)
    THROW_IMPOSSIBLE;
  if(xbt_dynar_is_empty(comm->conn_wait))
    return 0;
  comm_t comm_conn;
  xbt_dynar_get_cpy(comm->conn_wait, 0, &comm_conn);

//   printf("Accept connection from %d\n", comm_conn->info[0].socket->fd);
  return comm_conn->info[0].socket->proc->pid;
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
  struct infos_socket* peer = comm_get_peer(is);
  printf("Comm state %d %d %d\n", xbt_fifo_size(recv->send_fifo), !xbt_dynar_is_empty(comm->conn_wait), comm->state);
  if(xbt_fifo_size(recv->send_fifo))
    res = res | SOCKET_READ_OK;
  if(!xbt_dynar_is_empty(comm->conn_wait))
    res = res | SOCKET_READ_OK;
  if(comm->state == COMM_CLOSED)
    res = res | SOCKET_CLOSED;
  if(peer != NULL)
    res = res | SOCKET_WR_NBLK;
  if(comm->state == COMM_SHUT)
    res = res | SOCKET_SHUT;
  
  
  
  return res;
}


void comm_send_data(struct infos_socket *is, task_comm_info *tci)
{
  recv_information* recv = comm_get_peer_recv(is);
  xbt_fifo_push(recv->recv_task, tci);
}

task_comm_info* comm_get_send(struct infos_socket* is)
{
  recv_information* recv = comm_get_own_recv(is);
  
  return xbt_fifo_shift(recv->recv_task);
}

