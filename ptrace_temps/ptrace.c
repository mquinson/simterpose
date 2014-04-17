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
#include <sys/time.h>
#include <errno.h>
#include "ptrace.h"

void ptrace_get_register(const pid_t pid, reg_s* arg)
{
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs) == -1) {
    printf(" [%d] ptrace getregs %d\n", pid, strerror(errno));
  }
	
  arg->reg_orig=regs.orig_rax;
  arg->ret=regs.rax;
  arg->arg1=regs.rdi; // timeval
  arg->arg2=regs.rsi; // timezone
  arg->arg3=regs.rdx;
  arg->arg4=regs.r10;
  arg->arg5=regs.r8;
  arg->arg6=regs.r9;
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


void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long arg1){
	printf("restore syscall \n");
  struct user_regs_struct regs;
  
  if (ptrace(PTRACE_GETREGS, pid,NULL, &regs)==-1) {
    printf(" [%d] ptrace getregs %i\n", pid, strerror(errno));
    printf("Impossible to continue\n");
  }
  
  regs.orig_rax = syscall;
  regs.rdi = arg1;
  
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
	reg_s DEB; // debug
	struct timeval tv;
	time_t sec = 0;
        suseconds_t usec;
	
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

		
  	
 		ptrace_get_register(child, &arg);
		switch (arg.reg_orig){

		case SYS_gettimeofday:

			sec = ptrace(PTRACE_PEEKDATA, child, arg.arg1, 0);
                    usec = ptrace(PTRACE_PEEKDATA, child, arg.arg1 + sizeof(time_t), 0);

 #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ret, NULL);
                    fprintf(stderr, "tt: gettimeofday(tv->tv_sec=%ld,tv->tv_usec=%ld)=%ld --> *tv={%ld,%ld}\n", sec, usec, retval, sec + sec_offset, usec + usec_offset);
#endif

                    sec += 1000;
                    usec += 500000;
                    ptrace(PTRACE_POKEDATA, child, arg.arg1, sec);
                    ptrace(PTRACE_POKEDATA, child, arg.arg1 + sizeof(time_t), usec);

			

			//ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			//waitpid(child, &status, 0);

		break;
		default :
			//printf("syscall : %ld \n", arg.reg_orig);
		break;

		}
		if (ptrace(PTRACE_SYSCALL, child, NULL, NULL)==-1) {
			perror("ptrace syscall");
			exit(1);
		}
		//waitpid(child, &status, 0);
	}
    }
    return 0;
}
