#ifndef __TIME_PROC_H_
#define __TIME_PROC_H_

#define PROC_RECVMSG            0x000200
#define PROC_READ               0x000400
#define PROC_RECVFROM           0x000800


#define PROC_NO_STATE           0x000000
#define PROC_SELECT             0x000010
#define PROC_POLL               0x000020
#define PROC_CONNECT            0x000040
#define PROC_ACCEPT		        0x000080
#define PROC_CONNECT_DONE       0x000100
#define PROC_RECV            (PROC_RECVMSG | PROC_RECVFROM | PROC_READ)

#define STATE_MASK              0x00FFF0

#define PROC_IDLE_IN_TASK       0x00100

#define PROC_NO_TIMEOUT         0
#define PROC_IN_TIMEOUT         1
#define PROC_TIMEOUT_EXPIRE     2


#define FD_STDIN                0x00
#define FD_STDOUT               0x01
#define FD_STDERR               0x02
#define FD_CLASSIC              0x04
#define FD_SOCKET               0x08

typedef struct process_descriptor process_descriptor_t;

typedef struct {
  int type;
  process_descriptor_t *proc;
  int fd;
  int pid;
} fd_descriptor_t;

#include "args_trace.h"
#include "simdag/simdag.h"
#include "sockets.h"
#include "simterpose.h"

#include <sys/types.h>

struct process_descriptor {
  pid_t pid;
  pid_t tgid;
  long long int cpu_time;
  char *name;
  FILE *trace;
  double next_event;
  SD_workstation_t host;
  SD_task_t last_computation_task;
  fd_descriptor_t **fd_list;
  int in_syscall;

  int mediate_state;
  unsigned int is_idling:1;
  unsigned int in_timeout:2;
  unsigned int scheduled:1;     // in sched_list
  unsigned int in_idle_list:1;
  unsigned int on_simulation:1;
  unsigned int on_mediation:1;  // in mediate_list


  int state;
  syscall_arg_u sysarg;
};


process_descriptor_t *process_descriptor_new(char *name, pid_t pid);

process_descriptor_t *process_get_descriptor(pid_t pid);

void process_set_descriptor(pid_t pid, process_descriptor_t * proc);

void process_idle_start(process_descriptor_t * proc);

int process_is_idle(process_descriptor_t * proc);

void process_fork(pid_t new_pid, pid_t pid_fork);

int process_update_cputime(process_descriptor_t * proc, long long int cputime_elapsed);

void process_clone(pid_t new_pid, pid_t pid_cloned, unsigned long flags);

int process_get_state(process_descriptor_t * proc);

void process_reset_state(process_descriptor_t * proc);

void process_set_state(process_descriptor_t * proc, int state);

void process_die(pid_t pid);

void process_on_simulation(process_descriptor_t * proc, int val);

void process_on_mediation(process_descriptor_t * proc);

void process_end_mediation(process_descriptor_t * proc);

int process_get_free_fd(process_descriptor_t * proc);

#endif
