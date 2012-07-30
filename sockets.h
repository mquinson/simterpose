#ifndef __SOCKETS_H 
#define __SOCKETS_H

/*Declaration of state for socket*/
#define SOCKET_READ_OK  0x0001
#define SOCKET_CLOSED   0x0002
#define SOCKET_WR_NBLK  0x0004
#define SOCKET_SHUT     0x0008

/*Decalration of all typedef of structure declared below*/
typedef struct recv_information recv_information;
typedef struct process_info process_info;
struct infos_socket;

#define SOCK_OPT_REUSEADDR      0x0001


#include "sysdep.h"
#include "xbt.h"
#include "xbt/fifo.h"
#include "run_trace.h"
#include "communication.h"
#include "syscall_data.h"
#include "process_descriptor.h"


struct recv_information{
  xbt_fifo_t data_fifo;
  xbt_fifo_t recv_task;
  int quantity_recv;
};

struct infos_socket{
  fd_s fd;
  comm_t comm;//point to the communication which socket involved in
  int domain;
  int protocol;
  unsigned int ip_local;
  int port_local;
  int flags;
  int option;
};

recv_information* recv_information_new();

void recv_information_destroy(recv_information *recv);

void init_socket_gestion();

void socket_exit();

int handle_new_receive(int pid, syscall_arg_u* sysarg);

void handle_new_send(struct infos_socket *is,  syscall_arg_u* sysarg);

int close_all_communication(int pid);

struct infos_socket* register_socket(pid_t pid, int sockfd, int domain, int protocol);

void update_socket(pid_t pid, int fd);

int socket_registered(pid_t pid, int fd);

struct infos_socket* get_infos_socket(pid_t pid, int fd);

void get_localaddr_port_socket(pid_t pid, int fd);

void set_localaddr_port_socket(pid_t pid, int fd, char *ip, int port);

int get_protocol_socket(pid_t pid, int fd);

int get_domain_socket(pid_t pid, int fd);

int socket_incomplete(pid_t pid, int fd);

int socket_netlink(pid_t pid, int fd);

int socket_get_remote_addr(pid_t pid, int fd, struct sockaddr_in* addr_port);

struct infos_socket* getSocketInfoFromContext(unsigned int locale_ip, int locale_port);

int socket_get_state(struct infos_socket* is);

int socket_read_event(pid_t pid, int fd);

void socket_close(pid_t pid, int fd);

int socket_network(pid_t pid, int fd);

void socket_set_flags(pid_t pid, int fd, int flags);

int socket_get_flags(pid_t pid, int fd);

void socket_set_option(pid_t pid, int fd, int option, int value);

int socket_get_option(pid_t pid, int fd, int option);

#endif
