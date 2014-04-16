#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include "ptrace.h"


void get_args_time(pid_t pid, reg_s *reg, syscall_arg_u *sysarg)
{
	time_arg_t arg = &(sysarg->time);
  
  arg->ret = reg->ret;
  arg->t_dest = (void*) reg->arg1;
	if(arg->t_dest < (void*)0x100)
		arg->t_dest = 0;
	printf("time destination %p \n", arg->t_dest);
}

void ptrace_neutralize_syscall(const pid_t pid){
	printf("neutralize syscall \n");
  	struct user_regs_struct regs;
	int status;
	if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
		printf(" [%d] ptrace getregs %i\n", pid, strerror(errno));
		printf("Impossible to continue\n");
	}
	regs.orig_rax = 184;
	if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
		printf(" [%d] ptrace getregs %i\n", pid, strerror(errno));
		printf("Impossible to continue\n");
	}
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL); //resume syscall
	waitpid(pid, &status, 0);
}


void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long result){
	printf("restore syscall \n");
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    printf(" [%d] ptrace getregs %i\n", pid, strerror(errno));
    printf("Impossible to continue\n");
  }
  
  regs.orig_rax = syscall;
  regs.rax = result;
  
  if (ptrace(PTRACE_SETREGS, pid,NULL, &regs)==-1) {
    printf(" [%d] ptrace getregs %i\n", pid, strerror(errno));
    printf("Impossible to continue\n");
  }
}

int main(int argc, char *argv[]){

	if (argc<2) {
		 printf("usage : ./ptrace application\n");
		exit(1);
	}  
  	char *application;
	application=argv[1];

	pid_t child;
	int status;

	reg_s arg;
	struct timeval tv;
	
	child = fork();
	if(child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1) {
			perror("ptrace traceme");
			exit(1);
		}
		if (execv(application, &argv[2])==-1) {
			perror("execl");
			exit(1);
		}
	}
    	else {
	wait(&status);

	// Resume the child
	if (ptrace(PTRACE_SYSCALL, child, 0, 0)==-1) {
		perror("ptrace syscall");
		exit(1);
	}

	while(1) {
		child = waitpid(-1, &status, __WALL);
		if (child == -1) {
			perror("wait");
			exit(1);
		}

		if (WIFEXITED(status)) {
			printf("[%d] Child is dead\n",child);
			continue;
		}

		
  		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, child,NULL, &regs)==-1) {
			perror("ptrace getregs");
			exit(1);
		}

		  arg.reg_orig=regs.orig_rax;
		  arg.ret=regs.rax;
		  arg.arg1=regs.rdi;
		  arg.arg2=regs.rsi;
		  arg.arg3=regs.rdx;
		  arg.arg4=regs.r10;
		  arg.arg5=regs.r8;
		  arg.arg6=regs.r9;

		switch (arg.reg_orig){
			/*case SYS_read:
				printf("syscall read %ld \n", reg_orig);
			break;
			case SYS_write:
				printf("syscall write %ld \n", reg_orig);
			break;
			case SYS_open:
				printf("syscall open %ld \n", reg_orig);
			break;
			case SYS_close:
				printf("syscall close %ld \n", reg_orig);
			break;
			case SYS_exit:
				printf("syscall exit %ld \n", reg_orig);
			break;
			case SYS_execve:
				printf("syscall execve %ld \n", reg_orig);
			break;
			case SYS_mmap :
				printf("syscall mmap  %ld \n", reg_orig);
			break;
			case SYS_munmap :
				printf("syscall munmap  %ld \n", reg_orig);
			break;
			case SYS_mprotect :
				printf("syscall mprotect  %ld \n", reg_orig);
			break;
			case SYS_brk :
				printf("syscall brk  %ld \n", reg_orig);
			break;
			case SYS_fstat:
				printf("syscall fstat %ld \n", reg_orig);
			break;*/
			case SYS_gettimeofday:
				printf("appel à gettimeofday\n");

				syscall_arg_u *sysarg = NULL;
				get_args_time(child, &arg, sysarg);

				ptrace_neutralize_syscall(child);
				time_t ret = 1397660562;
				ptrace_restore_syscall(child, SYS_gettimeofday, ret);

				ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    				waitpid(child, &status, 0);
	
			break;
			/*default :
				printf("syscall inconnu: %ld \n", reg_orig);
			break;*/

		}
		if (ptrace(PTRACE_SYSCALL, child, NULL, NULL)==-1) {
			perror("ptrace syscall");
			exit(1);
		}
	}
    }
    return 0;
}
