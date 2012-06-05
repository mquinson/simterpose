#ifndef __SOCKETS_H 
#define __SOCKETS_H

#include "sysdep.h"
#include "xbt.h"
#include "xbt/fifo.h"

#define MAX_SOCKETS 512
/*
 * Sendto prio dès qu'on en trouve un on le met dnas la trace
 * pour les recv on les stacks dans un accu par couple ip-port
 * send => stack d'une longueur dans le recv.
 * Consomation de la pile
 * 	->voir handle_new_reception
 * A chaque recv et send on effectue le traitement
 */

typedef struct {
  xbt_fifo_t send_fifo;
  int quantity_recv;
}recv_information;

struct infos_socket{
  recv_information *recv_info;
  pid_t pid;
  int sockfd;
  int domain;
  int protocol;
  char *ip_local;
  int port_local;
  char *ip_remote;
  int port_remote;
  int incomplete;
  int closed;
};

void handle_new_receive(int pid, int sockfd, int length);

int handle_new_send(struct infos_socket *is,  int length);

void finish_all_communication(int pid);

void handle_communication_stat(struct infos_socket* is);

void register_socket(pid_t pid, int sockfd, int domain, int protocol);

void update_socket(pid_t pid, int fd);

int get_domain_sockfd(pid_t pid, int fd);

int socket_registered(pid_t pid, int fd);

void get_infos_socket(pid_t pid, int fd, struct infos_socket *res);

void get_localaddr_port_socket(pid_t pid, int fd);

void set_localaddr_port_socket(pid_t pid, int fd, char *ip, int port);

int get_pid_socket_dest(struct infos_socket *is);

void close_sockfd(pid_t pid, int fd);

int get_protocol_socket(pid_t pid, int fd);

int get_domain_socket(pid_t pid, int fd);

int socket_incomplete(pid_t pid, int fd);

int socket_closed(pid_t pid, int fd);

int socket_netlink(pid_t pid, int fd);

struct infos_socket* getSocketInfoFromContext(char* remote_ip, int remote_port, char* locale_ip, int locale_port);

#endif
