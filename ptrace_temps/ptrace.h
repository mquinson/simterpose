#ifndef __PTRACE_H 
#define __PTRACE_H


typedef struct{
  unsigned long reg_orig;
  unsigned long ret;
  unsigned long arg1;
  unsigned long arg2;
  unsigned long arg3;
  unsigned long arg4;
  unsigned long arg5;
  unsigned long arg6;
}reg_s;


typedef struct {
	time_t t;
	void * t_dest;
	time_t ret;
}time_arg_t;

typedef union{
  time_arg_t time;
}syscall_arg_u;

void get_args_time(pid_t pid, reg_s *reg, syscall_arg_u *sysarg);
void ptrace_neutralize_syscall(const pid_t pid);
void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long result);



#endif
