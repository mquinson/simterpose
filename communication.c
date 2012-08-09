#include "sockets.h"
#include "communication.h"
#include "xbt.h"
#include "task.h"
#include "data_utils.h"
#include "simdag/simdag.h"
#include "sysdep.h"

#include <sys/types.h>
#include <stdlib.h>

xbt_dynar_t comm_list;

void init_comm()
{
  comm_list = xbt_dynar_new(sizeof(comm_t), NULL); 
}

void comm_exit()
{
  xbt_dynar_free(&comm_list);
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
  if(!comm)
    return NULL;
  
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

void comm_close(struct infos_socket* is)
{
  comm_t comm = is->comm;
  if(comm == NULL)
    return;
  
  if(comm->state == COMM_LISTEN)
  {
    struct infos_socket *is = comm->info[0].socket;
    unset_socket(is->fd.pid, is);
    delete_socket(is);
    free(is);
    comm_destroy(comm);
  }
  else if (comm->state == COMM_CLOSED)
  {
    struct infos_socket *is = comm->info[0].socket;
    unset_socket(is->fd.pid, is);
    delete_socket(is);
    free(is);
    is = comm->info[1].socket;
    unset_socket(is->fd.pid, is);
    delete_socket(is);
    free(is);
    comm_destroy(comm);
  }
  else
    comm->state = COMM_CLOSED;
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
  comm->state =   COMM_LISTEN;
//   printf("Listen do %d\n", comm->state & COMM_LISTEN);
}

int comm_ask_connect(SD_workstation_t station, int port, pid_t tid, int fd, int device)
{
  struct infos_socket *conn = get_binding_socket_workstation(station, port, device);
  if(!conn)
    return 0;
  
  comm_t comm = comm_new(get_infos_socket(tid, fd));
  xbt_dynar_push(conn->comm->conn_wait, &comm);
  
  struct infos_socket *is = get_infos_socket(tid, fd);
  
  if(conn->ip_local ==0)
  {
    if(conn->fd.proc == is->fd.proc)
      comm->remote_ip = inet_addr("127.0.0.1");
    else
      comm->remote_ip = get_ip_of_station(conn->fd.proc->station);
  }
  else
    comm->remote_ip = conn->ip_local;
  comm->remote_port = conn->port_local;
  
  struct in_addr in = {comm->remote_ip};
  printf("%s:%d\n", inet_ntoa(in), comm->remote_port);
  
  return conn->fd.proc->pid;
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

void comm_get_ip_port_accept(struct infos_socket *is, struct sockaddr_in *in)
{
  comm_t comm = is->comm;
  if(comm==NULL)
    THROW_IMPOSSIBLE;
  
  if(xbt_dynar_is_empty(comm->conn_wait))
    return;
  
  printf("Store connected information\n");
  comm_t comm_conn;
  xbt_dynar_get_cpy(comm->conn_wait, 0, &comm_conn);
  
  //Store ip and port of process which wait for connect
  struct infos_socket *s = comm_conn->info[0].socket;
  in->sin_addr.s_addr = s->ip_local;
  in->sin_port = htons(s->port_local);
}

pid_t comm_accept_connect(struct infos_socket* is, struct sockaddr_in *in)
{
  comm_t comm = is->comm;
  if(comm==NULL)
    THROW_IMPOSSIBLE;
  
  if(xbt_dynar_is_empty(comm->conn_wait))
    return 0;
  comm_t comm_conn;
  xbt_dynar_get_cpy(comm->conn_wait, 0, &comm_conn);
  
  //Store ip and port of process which wait for connect
  struct infos_socket *s = comm_conn->info[0].socket;
  in->sin_addr.s_addr = s->ip_local;
  in->sin_port = s->port_local;

  fprintf(stderr, "Accept connection from %d\n", comm_conn->info[0].socket->port_local);
  return comm_conn->info[0].socket->fd.proc->pid;
}


int comm_getpeername(struct infos_socket *is, struct sockaddr_in *in, socklen_t* sock)
{
  comm_t comm = is->comm;
  if(comm==NULL)
    return -1;
  
  struct infos_socket *peer = comm_get_peer(is);
  
  if(!peer)
  {
    struct in_addr in2 = {comm->remote_ip};
    printf("%s:%d\n", inet_ntoa(in2), comm->remote_port);
    
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

int comm_has_connect_waiting(struct infos_socket* is)
{
  comm_t comm = is->comm;
  return !xbt_dynar_is_empty(comm->conn_wait);
}

int comm_get_socket_state(struct infos_socket* is)
{
  
  comm_t comm = is->comm;
  if(comm == NULL)
    return 0;
  int res=0;
  recv_information* recv = comm_get_own_recv(is);
  struct infos_socket* peer = comm_get_peer(is);
//   printf("Comm state %d %d %d\n", xbt_fifo_size(recv->send_fifo), !xbt_dynar_is_empty(comm->conn_wait), comm->state);
  if(xbt_fifo_size(recv->data_fifo))
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

