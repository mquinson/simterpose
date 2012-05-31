#ifndef __SOCKETS_H 
#define __SOCKETS_H

#include "sysdep.h"

#define MAX_SOCKETS 512

struct infos_socket{
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

#endif
