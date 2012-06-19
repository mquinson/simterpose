#ifndef __SYSDEP_H_ 
#define __SYSDEP_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>
#include <linux/netlink.h>

#define SIZE_PARAM_TRACE 1024
#define MAX_PROCS 512


struct time_process{
  pid_t pid;
  long long int last_cputime;
};

#endif
