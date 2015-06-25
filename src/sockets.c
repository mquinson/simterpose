/* sockets -- Helpers functions to deal with sockets */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sockets.h"
#include "simterpose.h"

#define LOCAL 1
#define REMOTE 2

#define TCP_PROTOCOL 0
#define UDP_PROTOCOL 1
#define RAW_PROTOCOL 2

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SOCKETS, simterpose, "sockets log");

typedef struct {
  void *data;
  int size;
} data_send_s;

xbt_dynar_t all_sockets;
int nb_sockets = 0;

void print_infos_socket(struct infos_socket *is);

/** @brief create the list containing all sockets */
void init_socket_gestion(void)
{
  all_sockets = xbt_dynar_new(sizeof(struct infos_socket *), NULL);
}

/** @brief free the list containing all sockets */
void socket_exit(void)
{
  xbt_dynar_free(&all_sockets);
}

/** @brief create and initialize a recv_information object */
recv_information *recv_information_new(void)
{
  recv_information *res = xbt_malloc0(sizeof(recv_information));
  res->quantity_recv = 0;
  res->recv_task = xbt_fifo_new();
  res->data_fifo = xbt_fifo_new();
  return res;
}

/** @brief free the given recv_information */
void recv_information_destroy(recv_information * recv)
{
  xbt_fifo_free(recv->recv_task);
  xbt_fifo_free(recv->data_fifo);
  free(recv);
}

/** @brief creates infos_socket and put it into the global list */
static struct infos_socket *confirm_register_socket(process_descriptor_t * proc, int sockfd, int domain, int protocol)
{

  struct infos_socket *is = xbt_malloc0(sizeof(struct infos_socket));

  process_descriptor_set_fd(proc, sockfd, (fd_descriptor_t *) is);
  is->ref_nb = 0;
  is->fd.type = FD_SOCKET;
  is->fd.fd = sockfd;
  is->fd.proc = proc;

  is->host = proc->host;
  is->comm = NULL;
  is->domain = domain;
  is->protocol = protocol;
  is->ip_local = -1;
  is->port_local = 0;
  is->option = 0;
  is->binded = 0;

  is->flags = O_RDWR;

  xbt_dynar_push(all_sockets, &is);
  is->ref_nb++;

  return is;
}

/** @brief retrieve the socket flags */
int socket_get_flags(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is == NULL)
    return 0;
  return is->flags;
}

/** @brief modify the socket flags */
void socket_set_flags(process_descriptor_t * proc, int fd, int flags)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is == NULL)
    return;
  is->flags = flags;
}

/** @brief retrieve the socket options */
int socket_get_option(process_descriptor_t * proc, int fd, int option)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is == NULL)
    return 0;
  return is->option & option;
}

/** @brief modify the socket options */
void socket_set_option(process_descriptor_t * proc, int fd, int option, int value)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is == NULL)
    return;
  if (value)
    is->option = is->option | option;
  else
    is->option = is->option & ~option;
}

/** @brief remove the socket from the global list */
void delete_socket(struct infos_socket *is)
{
  xbt_ex_t e;
  TRY {
    int i = xbt_dynar_search(all_sockets, &is);
    is->ref_nb--;
    xbt_dynar_remove_at(all_sockets, i, NULL);
  }
  CATCH(e) {
    XBT_ERROR("Socket not found");
  }
}

/** @brief close a socket */
void socket_close(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);
  if (is != NULL) {
    // There is probably something wrong here:
    process_descriptor_get_fd(proc, fd)->refcount--;
    is->ref_nb--;
    if (socket_network(proc, fd))
      comm_close(is);
    else {
      free(is);
    }
    process_descriptor_set_fd(proc, fd, NULL);
  }
}

/** @brief register a socket for the given process */
struct infos_socket *register_socket(process_descriptor_t * proc, int sockfd, int domain, int protocol)
{
  XBT_DEBUG("Registering socket %d for process %d", sockfd, proc->pid);
  if (process_descriptor_get_fd(proc, sockfd) != NULL) {
    xbt_die("Inconsistency found in model. Socket already exist");
  }
  return confirm_register_socket(proc, sockfd, domain, protocol);
}

/** @brief set the local ip and local port of the socket */
void set_localaddr_port_socket(process_descriptor_t * proc, int fd, char *ip, int port)
{
  struct infos_socket *is = get_infos_socket(proc, fd);
  is->ip_local = inet_addr(ip);
  is->port_local = port;
  //   print_infos_socket(is);
}

/** @brief print information about the socket */
void print_infos_socket(struct infos_socket *is)
{
  fprintf(stdout, "\n%5s %5s %10s %10s %21s\n", "pid", "fd", "domain", "protocol", "locale_ip:port");
  if (is->fd.proc != NULL) {

    fprintf(stdout, "%5d %5d %10d %10d %15d:%5d\n",
	    is->fd.proc->pid, is->fd.fd, is->domain, is->protocol, is->ip_local, is->port_local);
  }
}

#define INODE_OFFSET 91

static int get_addr_port(int type, int num_sock, struct sockaddr_in *addr_port, int addr)
{
  FILE *file;

  XBT_DEBUG("Socket number : %d", num_sock);
  if (type == TCP_PROTOCOL)     // TCP
    file = fopen("/proc/net/tcp", "r");
  else if (type == UDP_PROTOCOL)        // UDP
    file = fopen("/proc/net/udp", "r");
  else                          // RAW
    file = fopen("/proc/net/raw", "r");
  if (file == NULL) {
    xbt_die("ERROR while opening file /proc/net/???. Bailing out now (%s)",strerror(errno));
  }
  char buff[512];
  char *loc_addr_hex;
  char *rem_addr_hex;
  char addrs[27];
  char part_inode[512 - INODE_OFFSET];  // size buff = 512 - all informations before inode
  char *inode;
  while (fgets(buff, sizeof(buff), file)) {
    strncpy(part_inode, buff + INODE_OFFSET, 512 - INODE_OFFSET);
    inode = strtok(part_inode, " ");
    if (atoi(inode) == num_sock) {
      strncpy(addrs, buff + 6, 27);
      loc_addr_hex = strtok(addrs, " ");
      rem_addr_hex = strtok(NULL, " ");
      if (addr == LOCAL)        // 1 -> locale
	sscanf(loc_addr_hex, "%X:%hX", &addr_port->sin_addr.s_addr, &addr_port->sin_port);
      else                      // remote
	sscanf(rem_addr_hex, "%X:%hX", &addr_port->sin_addr.s_addr, &addr_port->sin_port);
      fclose(file);
      return 1;
    }
  }
  fclose(file);
  return -1;
}

/** @brief retrieve the local port of socket */
int socket_get_local_port(process_descriptor_t * proc, int fd)
{

  struct infos_socket *is = get_infos_socket(proc, fd);
  pid_t pid = proc->pid;
  int protocol = is->protocol;

  char path[512];
  char dest[512];
  sprintf(path, "/proc/%d/fd/%d", pid, fd);
  if (readlink(path, dest, 512) == -1) {
    XBT_ERROR("Failed reading /proc/%d/fd/%d", pid, fd);
    return -1;
  }

  char *token;
  token = strtok(dest, "[");    // left part before socket id
  token = strtok(NULL, "]");    // socket id
  int num_socket = atoi(token);

  struct sockaddr_in addr_port;

  int res = 0;

  if (protocol == 1) {          // case IPPROTO_ICMP -> protocol unknown -> test TCP
    res = get_addr_port(TCP_PROTOCOL, num_socket, &addr_port, LOCAL);
    if (res == -1) {            // not tcp -> test UDP
      res = get_addr_port(UDP_PROTOCOL, num_socket, &addr_port, LOCAL);
      if (res == -1)            // not udp -> test RAW
	res = get_addr_port(RAW_PROTOCOL, num_socket, &addr_port, LOCAL);
    }
  }

  if (protocol == 6 || protocol == 0)   // case IPPROTO_TCP ou IPPROTO_IP
    res = get_addr_port(TCP_PROTOCOL, num_socket, &addr_port, LOCAL);
  if (protocol == 17)           // case IPPROTO_UDP
    res = get_addr_port(UDP_PROTOCOL, num_socket, &addr_port, LOCAL);
  if (protocol == 255)          // case IPPROTO_RAW
    res = get_addr_port(RAW_PROTOCOL, num_socket, &addr_port, LOCAL);

  return ntohs(addr_port.sin_port);
}

/** @brief retrieve the domain of socket */
int get_domain_socket(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is != NULL)
    return is->domain;
  return -1;
}

/** @brief check if socket is registered */
int socket_registered(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is != NULL)
    return 1;
  return -1;
}

/** @brief retrieve information about socket */
struct infos_socket *get_infos_socket(process_descriptor_t * proc, int fd)
{
  // XBT_DEBUG("Info socket %d %d", proc->pid, fd);
  fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, fd);

  if (file_desc == NULL || file_desc->type != FD_SOCKET)
    return NULL;

  struct infos_socket *is = (struct infos_socket *) file_desc;

  return is;
}


/** @brief retrieve the protocol of socket */
int get_protocol_socket(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is != NULL)
    return is->protocol;
  return -1;
}

/** @brief check if socket is a netlink socket */
int socket_netlink(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);

  if (is != NULL) {
    XBT_DEBUG("Socket %d of %d : domain %d", fd, proc->pid, is->domain);
    return is->domain == 16;
  }
  return 0;
}

/** @brief check if socket is a network socket */
int socket_network(process_descriptor_t * proc, int fd)
{
  struct infos_socket *is = get_infos_socket(proc, fd);
  if (is != NULL) {
    XBT_DEBUG("Socket %d of %d : domain %d", fd, proc->pid, is->domain);
    return is->domain != 16 && is->domain != 0 && is->domain != 1;
  }
  return 0;
}

/** @brief send syscall data by putting it in data_fifo */
void handle_new_send(struct infos_socket *is, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  recv_information *recv = comm_get_peer_recv(is);

#ifndef address_translation
  data_send_s *ds = xbt_malloc0(sizeof(data_send_s));
  ds->data = arg->data;
  ds->size = arg->len;

  xbt_fifo_push(recv->data_fifo, ds);

  arg->ret = arg->len;
#else
  int *data = xbt_malloc(sizeof(int));
  *data = arg->ret;

  xbt_fifo_push(recv->data_fifo, data);
#endif
  //   XBT_DEBUG("New queue size %d", xbt_fifo_size(recv->data_fifo));
}

/** @brief close all the communications */
int close_all_communication(process_descriptor_t * proc)
{
  int result = 0;

  xbt_dict_cursor_t cursor = NULL;
  char *key;
  fd_descriptor_t* file_desc;
  xbt_dict_foreach(proc->fd_map, cursor, key, file_desc) {
    int i = *(int*) key;
    if (file_desc != NULL && file_desc->type == FD_SOCKET) {
      recv_information *recv = comm_get_own_recv((struct infos_socket *) file_desc);

      if (!recv)
        continue;

      xbt_fifo_t tl = recv->recv_task;
      task_comm_info *tci;
      while (xbt_fifo_size(tl)) {
        tci = (task_comm_info *) xbt_fifo_shift(tl);
        MSG_task_destroy(tci->task);
        free(tci);
      }

      xbt_fifo_t dl = recv->data_fifo;
#ifndef address_translation
      data_send_s *ds;
#else
      int *ds;
#endif
      while (xbt_fifo_size(dl)) {
        ds = xbt_fifo_shift(dl);
#ifndef address_translation
        free(((data_send_s *) ds)->data);
#endif
        free(ds);
      }
      socket_close(proc, i);
    }
    // TODO: close pipes
  }
  return result;
}

/** @brief retrieve the state of socket */
int socket_get_state(struct infos_socket *is)
{
  return comm_get_socket_state(is);
}
