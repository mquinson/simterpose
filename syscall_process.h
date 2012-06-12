#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

int process_send_call(int pid, int sockfd, int ret);

int process_recv_call(int pid, int sockfd, int ret);

int process_fork_call(int pid);

#endif