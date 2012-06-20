#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

#include <stdlib.h>

#define MAX_FD 1024
#define MAX_PID 32768  

#include "simdag/simdag.h"
#include "xbt/fifo.h"
#include "process_descriptor.h"

//For num syscall see 
//file:///usr/share/gdb/syscalls/amd64-linux.xml
/***********************************************
 * Define various constant for 32 bits syscalls
 * ********************************************/
#define SYS_socket_32 		1
#define SYS_bind_32 		2
#define SYS_connect_32 		3
#define SYS_listen_32 		4
#define SYS_accept_32 		5
#define SYS_send_32 		9
#define SYS_recv_32 		10
#define SYS_sendto_32 		11
#define SYS_recvfrom_32 	12
#define SYS_shutdown_32		13
#define SYS_setsockopt_32 	14
#define SYS_getsockopt_32 	15
#define SYS_sendmsg_32 		16
#define SYS_recvmsg_32 		17


/*********************************************/


//#define DEBUG

typedef struct simterpose_data simterpose_data_t;
simterpose_data_t* global_data;


struct simterpose_data{
  double last_clock;
  int not_assigned;
  int launcher_com;
  xbt_fifo_t time_to_next;
  pid_t last_pid_create;
  process_descriptor *process_desc[MAX_PID];
  int child_amount;
  int idle_amount;
  float flops_per_second;
  float micro_s_per_flop;
};
#endif