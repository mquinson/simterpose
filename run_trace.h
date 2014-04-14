#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

//#define address_translation

#include <sys/types.h>

#define MAX_FD 1024
#define MAX_PID 32768  

#define PORT_BIND       0x1
#define PORT_LOCAL      0x2
#define PORT_REMOTE     0x4

typedef struct time_desc time_desc;
typedef struct simterpose_station simterpose_station;
typedef struct port_desc port_desc;
typedef struct translate_desc translate_desc;

#include "process_descriptor.h"
#include "sockets.h"
#include "xbt.h"

//For num syscall see 
//file:///usr/share/gdb/syscalls/amd64-linux.xml


typedef struct simterpose_data simterpose_data_t;
simterpose_data_t* global_data;


struct time_desc{
  pid_t pid;
  double start_time;
};

struct port_desc{
  int port_num;
  int real_port;
  int option;
  int amount_socket;
  struct infos_socket* bind_socket;
};

struct translate_desc{
  int port_num;
  unsigned int ip;
};

struct simterpose_station{
  unsigned int ip;
  xbt_dict_t port;
};

struct simterpose_data{
  xbt_dynar_t launching_time;
  process_descriptor *process_desc[MAX_PID];
  xbt_dict_t list_station;
  xbt_dict_t list_ip;
  xbt_dict_t list_translate;
  time_t init_time;
  int child_amount;
  float flops_per_second;
  float micro_s_per_flop;
};

void add_to_sched_list(pid_t pid);

#endif
