#ifndef __ARGS_TRACE_MSG_H
#define __ARGS_TRACE_H


#include "syscall_data.h"
#include "ptrace_utils.h"
#include "process_descriptor.h"

extern int nb_procs;

void get_args_bind_connect(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * arg);

void get_args_accept(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * arg);

void get_args_listen(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_select(process_descriptor_t * proc, reg_s * r, syscall_arg_u * sysarg);

void get_args_setsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_getsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_sendto(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_recvfrom(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_sendmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_poll(process_descriptor_t * proc, reg_s * arg, syscall_arg_u * sysarg);

void get_args_fcntl(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_read(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_write(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_clone(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void sys_build_select(process_descriptor_t * proc, syscall_arg_u * sysarg, int match);

void sys_build_recvmsg(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_build_poll(process_descriptor_t * proc, syscall_arg_u * sysarg, int match);

void sys_translate_accept(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_translate_connect_in(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_translate_connect_out(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_translate_sendto_in(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_translate_sendto_out(process_descriptor_t * proc, syscall_arg_u * sysarg);

void sys_translate_recvfrom_in(process_descriptor_t * proc, syscall_arg_u * arg);

void sys_translate_recvfrom_out(process_descriptor_t * proc, syscall_arg_u * sysarg);

#endif
