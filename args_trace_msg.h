#ifndef __ARGS_TRACE_MSG_H
#define __ARGS_TRACE_MSG_H


#include "syscall_data_msg.h"
#include "ptrace_utils_msg.h"

extern int nb_procs;

/*void get_args_bind_connect(pid_t child, int syscall, reg_s * reg, syscall_arg_u * arg);

void get_args_accept(pid_t child, reg_s * reg, syscall_arg_u * arg);*/

void get_args_listen(pid_t child, reg_s * reg, syscall_arg_u * sysarg);

void get_args_select(pid_t child, reg_s * r, syscall_arg_u * sysarg);

void get_args_setsockopt(pid_t pid, reg_s * reg, syscall_arg_u * sysarg);

void get_args_getsockopt(pid_t child, reg_s * reg, syscall_arg_u * sysarg);

/*void get_args_sendto(pid_t child, reg_s * reg, syscall_arg_u * sysarg);

void get_args_recvfrom(pid_t child, reg_s * reg, syscall_arg_u * sysarg);*/

void get_args_recvmsg(pid_t child, reg_s * reg, syscall_arg_u * sysarg);

void get_args_sendmsg(pid_t child, reg_s * reg, syscall_arg_u * sysarg);

void get_args_poll(pid_t child, reg_s * arg, syscall_arg_u * sysarg);

void get_args_fcntl(pid_t pid, reg_s * reg, syscall_arg_u * sysarg);

void get_args_read(pid_t pid, reg_s * reg, syscall_arg_u * sysarg);

void get_args_write(pid_t pid, reg_s * reg, syscall_arg_u * sysarg);

void sys_build_select(pid_t pid, syscall_arg_u * sysarg, int match);

void sys_build_recvmsg(pid_t pid, syscall_arg_u * sysarg);

void sys_build_poll(pid_t pid, syscall_arg_u * sysarg, int match);
/*
void sys_translate_accept(pid_t pid, syscall_arg_u * sysarg);

void sys_translate_connect_in(pid_t pid, syscall_arg_u * sysarg);

void sys_translate_connect_out(pid_t pid, syscall_arg_u * sysarg);

void sys_translate_sendto_in(pid_t pid, syscall_arg_u * sysarg);

void sys_translate_sendto_out(pid_t pid, syscall_arg_u * sysarg);

void sys_translate_recvfrom_in(pid_t pid, syscall_arg_u * arg);

void sys_translate_recvfrom_out(pid_t pid, syscall_arg_u * sysarg);*/

#endif
