#ifndef INCLUDED_SYSCALL_PROCESS
#define INCLUDED_SYSCALL_PROCESS

int process_send_call(int pid, int sockfd, int ret);

#endif