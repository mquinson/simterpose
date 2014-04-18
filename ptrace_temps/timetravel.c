/**
 * Executable wrapper to fake syscall results returning absolute time
 * information. Calls to SYS_gettimeofday and YS_clock_gettime are intercepted.
 *
 * NOTE: will not work for all calls on kernels implementing
 * vsyscalls. (vdso=0 vsyscal=natural)
 **/

#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#define SYSCALL_NUM ORIG_RAX
#define SYSCALL_RET RAX
#define SYSCALL_ARG1 rdi
#define SYSCALL_ARG2 rsi

#define DEBUG

int
main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s factor executable\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* calculate timespec arguments */
    int fact = atoi(argv[1]);

    #ifdef DEBUG
    fprintf(stderr, "Multiplying gettimeofday and clock_gettime syscalls by %d \n\n", fact);
    #endif

    char* executable = argv[2];

    pid_t pid = fork();
    switch (pid) {
    case -1:
        /* failed */
        perror("couldn't fork");
        return EXIT_FAILURE;
    case 0:
        /* child */
        if (ptrace(PTRACE_TRACEME, 0, (char*) 1, 0) < 0) {
            perror("ptrace(PTRACE_TRACEME, ...)");
            return EXIT_FAILURE;
        }
        kill(getpid(), SIGSTOP);
        execv(executable, &argv[3]);
        perror(executable);
        _exit(1);
        break;
    default:
      {
        /* parent */

        int insyscall = 0;
        long syscallno;
        long retval;
        time_t sec = 0;
        long nsec = 0;
        suseconds_t usec;
        struct user_regs_struct regs;
        int status;
        for (;;) {
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) /* process exit */
                break;

            syscallno = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_NUM, 0);

            switch (syscallno) {
              case SYS_gettimeofday:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* struct timeval* tv parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1, 0);
                    usec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1 + sizeof(time_t), 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "gettimeofday: sec=%ld, usec=%ld --> %ld, %ld \n", sec, usec, sec * fact, usec * fact);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                  sec *= fact;
                  usec *= fact;
			/*sec = 1500;
			usec = 5;*/
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG1, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG1 + sizeof(time_t), usec);
                }
                break;


		case SYS_clock_gettime:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* struct timespec* tp parameter is in SECOND parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2, 0);
                    nsec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "clock_gettime: sec=%ld, nsec=%ld --> %ld, %ld \n", sec, nsec, sec *fact, nsec*fact);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec *=fact;
                    nsec *=fact; 
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), nsec);
                }
                break;

            }

            if (ptrace(PTRACE_SYSCALL, pid, (char*) 1, 0) < 0) {
                perror("resume: ptrace(PTRACE_SYSCALL, ...)");
                return EXIT_FAILURE;
            }
        }
        ptrace(PTRACE_DETACH, pid, (char*) 1, 0);
        break;
      }
    }
    return EXIT_SUCCESS;
}
