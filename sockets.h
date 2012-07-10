#ifndef __SOCKETS_H 
#define __SOCKETS_H

/*Declaration of state for socket*/
#define SOCKET_READ_OK 0x000001
#define SOCKET_CLOSED  0x000002

/*Decalration of all typedef of structure declared below*/
typedef struct recv_information recv_information;
typedef struct process_info process_info;
struct infos_socket;

#include "sysdep.h"
#include "xbt.h"
#include "xbt/fifo.h"
#include "run_trace.h"
#include "communication.h"


struct recv_information{
  xbt_fifo_t send_fifo;
  xbt_fifo_t recv_task;
  int quantity_recv;
};

struct infos_socket{
  comm_t comm;//point to the communication which socket involved in
  process_descriptor* proc;//contain information of proc which handle the socket
  int fd;
  int domain;
  int protocol;
  unsigned int ip_local;
  int port_local;
  int incomplete;
  int closed;
};

recv_information* recv_information_new();

void init_socket_gestion();

int handle_new_receive(int pid, int sockfd, int length);

void handle_new_send(struct infos_socket *is,  int length);

int close_all_communication(int pid);

int handle_communication_stat(struct infos_socket* is, pid_t pid);

struct infos_socket* register_socket(pid_t pid, int sockfd, int domain, int protocol);

void update_socket(pid_t pid, int fd);

int socket_registered(pid_t pid, int fd);

struct infos_socket* get_infos_socket(pid_t pid, int fd);

void get_localaddr_port_socket(pid_t pid, int fd);

void set_localaddr_port_socket(pid_t pid, int fd, char *ip, int port);

void close_sockfd(pid_t pid, int fd);

int get_protocol_socket(pid_t pid, int fd);

int get_domain_socket(pid_t pid, int fd);

int socket_incomplete(pid_t pid, int fd);

int socket_closed(pid_t pid, int fd);

int socket_netlink(pid_t pid, int fd);

int socket_get_remote_addr(pid_t pid, int fd, struct sockaddr_in* addr_port);

struct infos_socket* getSocketInfoFromContext(unsigned int locale_ip, int locale_port);

int socket_get_state(struct infos_socket* is);

int socket_read_event(pid_t pid, int fd);

#endif
