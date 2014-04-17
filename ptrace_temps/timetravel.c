/**
 * Executable wrapper to fake syscall results returning absolute time
 * information. Calls to SYS_gettimeofday, SYS_clock_gettime, and SYS_time are
 * intercepted.
 *
 * NOTE: will not work for all calls on kernels (e.g. some x86_64) implementing
 * vsyscalls.
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
        fprintf(stderr, "usage: %s offset executable\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* calculate timespec arguments */
    double offset = atof(argv[1]);
    time_t sec_offset = rint(offset);
    long nsec_offset = 1000000000 * (offset - sec_offset);
    suseconds_t usec_offset = 1000000 * (offset - sec_offset);

    #ifdef DEBUG
    fprintf(stderr, "Offsetting gettimeofday and clock_gettime syscalls by %lds+%ldns\n", sec_offset, nsec_offset);
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
        #ifdef DEBUG
        long retval;
        #endif
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
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: gettimeofday(tv=%lld,tz=%lld)\n", regs.SYSCALL_ARG1, regs.SYSCALL_ARG2);
                    #endif
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
                    fprintf(stderr, "tt: gettimeofday(tv->tv_sec=%ld,tv->tv_usec=%ld)=%ld --> *tv={%ld,%ld}\n", sec, usec, retval, sec * sec_offset, usec * usec_offset);
                    #endif

printf(" sec: %ld ,sec_offset %ld, usec_offset %ld \n",sec, sec_offset, usec_offset);
                    /* add adjustment and modify the result of the syscall */
                    sec *= sec_offset;
                    usec *= usec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG1, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG1 + sizeof(time_t), usec);
                }
                break;
              case SYS_clock_gettime:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: clock_gettime(clockid=%lld,tp=0x%x)\n", regs.SYSCALL_ARG1, (unsigned int) regs.SYSCALL_ARG2);
                    #endif
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* struct timespec* tp parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2, 0);
                    nsec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "tt: clock_gettime(tp->tv_sec=%ld,tp->tv_nsec=%ld)=%ld --> *tp={%ld,%ld}\n", sec, nsec, retval, sec + sec_offset, nsec + nsec_offset);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec += sec_offset;
                    nsec += nsec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2 + sizeof(time_t), nsec);
                }
                break;
              case SYS_time:
                if (insyscall == 0) {
                    /* entry */
                    insyscall = 1;
                    #ifdef DEBUG
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    fprintf(stderr, "tt: time(t=0x%x)\n", (unsigned int) regs.SYSCALL_ARG1);
                    #endif
                }
                else {
                    /* exit */
                    insyscall = 0;

                    /* time_t* t parameter is in first parameter */
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                    sec = ptrace(PTRACE_PEEKDATA, pid, regs.SYSCALL_ARG1, 0);

                    #ifdef DEBUG
                    retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * SYSCALL_RET, NULL);
                    fprintf(stderr, "tt: time(*t=%ld)=%ld --> *t=%ld\n", sec, retval, sec + sec_offset);
                    #endif

                    /* add adjustment and modify the result of the syscall */
                    sec += sec_offset;
                    ptrace(PTRACE_POKEDATA, pid, regs.SYSCALL_ARG2, sec);
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
