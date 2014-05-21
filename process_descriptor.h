#ifndef __TIME_PROC_H_
#define __TIME_PROC_H_

#define SYSCALL_IN              0x1
#define SYSCALL_OUT             0x0

#define PROC_RECVMSG            0x000200
#define PROC_READ               0x000400
#define PROC_RECVFROM           0x000800


#define PROC_NO_STATE           0x000000
#define PROC_SELECT             0x000010
#define PROC_POLL               0x000020
#define PROC_CONNECT            0x000040
#define PROC_ACCEPT_IN          0x000080
#define PROC_CONNECT_DONE       0x000100
#define PROC_RECVFROM_IN        (PROC_RECVFROM | SYSCALL_IN)
#define PROC_RECVFROM_OUT       (PROC_RECVFROM | SYSCALL_OUT)
#define PROC_READ_IN            (PROC_READ | SYSCALL_IN)
#define PROC_READ_OUT           (PROC_READ | SYSCALL_OUT)
#define PROC_RECVMSG_IN         (PROC_RECVMSG | SYSCALL_IN)
#define PROC_RECVMSG_OUT        (PROC_RECVMSG | SYSCALL_OUT)
#define PROC_RECV_IN            (PROC_RECVMSG_IN | PROC_RECVFROM_IN | PROC_READ_IN)

#define STATE_MASK              0x00FFF0

#define PROC_IDLE_IN_TASK       0x00100

#define PROC_NO_IDLE            0
#define PROC_IDLE               1

#define PROC_NO_TIMEOUT         0
#define PROC_IN_TIMEOUT         1
#define PROC_TIMEOUT_EXPIRE     2


#define FD_STDIN                0x00
#define FD_STDOUT               0x01
#define FD_STDERR               0x02
#define FD_CLASSIC              0x04
#define FD_SOCKET               0x08


typedef struct process_descriptor process_descriptor;
typedef struct fd_s fd_s;

struct fd_s {
  int type;
  process_descriptor *proc;
  int fd;
  int pid;
};

#include "args_trace.h"
#include "simdag/simdag.h"
#include "sockets.h"
#include "run_trace.h"

#include <sys/types.h>



struct process_descriptor {
  pid_t pid;
  pid_t tgid;
  int mediate_state;
  long long int cpu_time;
  char *name;
  FILE *trace;
  time_desc *timeout;           //point to the next timeout of process, NULL there is not timeout
  SD_workstation_t station;
  SD_task_t last_computation_task;
  fd_s **fd_list;

  unsigned int idle:1;
  unsigned int in_timeout:2;
  unsigned int scheduled:1;
  unsigned int idle_list:1;
  unsigned int on_simulation:1;
  unsigned int on_mediation:1;


  int state;
  syscall_arg_u sysarg;
};


process_descriptor *process_descriptor_new(char *name, pid_t pid);

process_descriptor *process_get_descriptor(pid_t pid);

void process_set_descriptor(pid_t pid, process_descriptor * proc);

void process_set_idle(process_descriptor * proc, int idle_state);

int process_get_idle(process_descriptor * proc);

void process_fork(pid_t new_pid, pid_t pid_fork);

int process_update_cputime(process_descriptor * proc, long long int cputime_elapsed);

int process_in_syscall(process_descriptor * proc);

void process_set_in_syscall(process_descriptor * proc);

void process_set_out_syscall(process_descriptor * proc);

void process_clone(pid_t new_pid, pid_t pid_cloned, unsigned long flags);

int process_get_state(process_descriptor * proc);

void process_reset_state(process_descriptor * proc);

void process_set_state(process_descriptor * proc, int state);

void process_die(pid_t pid);

void process_on_simulation(process_descriptor * proc, int val);

void process_on_mediation(process_descriptor * proc);

void process_end_mediation(process_descriptor * proc);

int process_get_free_fd(process_descriptor * proc);

#endif
