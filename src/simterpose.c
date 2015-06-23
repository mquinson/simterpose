/* simterpose - Emulate real applications on top of SimGrid */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.            */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPLv2) which comes with this package. */


#include <simgrid/msg.h>

#include <sys/ptrace.h>
#include <sys/personality.h>
#include <wait.h>
#include <errno.h>
#include <unistd.h>

#include "communication.h"
#include "cputimer.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "ptrace_utils.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_process.h"


XBT_LOG_NEW_DEFAULT_CATEGORY(simterpose, "Main simterpose log channel");
int strace_option = 0;

static void usage(char *progName, int retcode)
{
  printf("usage : %s  [-s] [-p flops_power] platform_file.xml deployment_file.xml\n", progName);
  exit(retcode);
}

/* Helper function to convert string to double */
static inline float str_to_double(const char *string)
{
  char *endptr;
  double value = strtof(string, &endptr);
  xbt_assert(*endptr == '\0', "%s is not a double", string);
  return value;
}

/* A little handler for the Ctrl-C */
static void sigint_handler(int sig)
{
  XBT_ERROR("Interruption request by user. Current time of simulation %lf", MSG_get_clock());
  XBT_ERROR("Killing processes...");

  MSG_process_killall(0);
  comm_exit();
  socket_exit();
  cputimer_exit(global_timer);
  simterpose_globals_exit();

  xbt_die("Done");
}

/* A little handler for segfaults */
static void sigsegv_handler(int sig)
{
  fprintf(stderr, "Segfault. Current time of simulation %lf\n", MSG_get_clock());
  fprintf(stderr, "Killing processes...\n");

  MSG_process_killall(0);
  comm_exit();
  socket_exit();
  cputimer_exit(global_timer);
  simterpose_globals_exit();

  xbt_die("Done");
}

int main(int argc, char *argv[])
{
  float msec_per_flop = 0;
  int flop_option = 0;

  MSG_init(&argc, argv);

  // Install our SIGSEGV handler
  struct sigaction nvt_sg, old_sg;
  memset(&nvt_sg, 0, sizeof(nvt_sg));
  nvt_sg.sa_handler = &sigsegv_handler;
  sigaction(SIGSEGV, &nvt_sg, &old_sg);

  // Install our SIGINT handler
  struct sigaction nvt, old;
  memset(&nvt, 0, sizeof(nvt));
  nvt.sa_handler = &sigint_handler;
  sigaction(SIGINT, &nvt, &old);


  if (argc < 3) {
    usage(argv[0], 1);
  } else {
    int c;
    while ((c = getopt(argc, argv, "s+p:")) != EOF) {
      switch (c) {
      case 's':
        strace_option = 1;
        break;
      case 'p':
        flop_option = 1;
        msec_per_flop = 1000000 / str_to_double(optarg);
        XBT_INFO("Setting reference power to %s flop/s", optarg);
        break;

      default:
        usage(argv[0], 0);
        break;
      }
    }
  }

  if (!flop_option)
    benchmark_matrix_product(&msec_per_flop);

  simterpose_globals_init(msec_per_flop);
  init_socket_gestion();
  comm_init();

  global_timer = cputimer_new();
  cputimer_init(global_timer);

  const char *platform_file = argv[optind];
  const char *application_file = argv[optind + 1];

  MSG_create_environment(platform_file);
  init_host_list();

  MSG_function_register_default(simterpose_process_runner);
  MSG_launch_application(application_file);

  if (strace_option) {
    xbt_log_appender_set(&_simgrid_log_category__simterpose, xbt_log_appender_strace_new());
    xbt_log_layout_set(&_simgrid_log_category__simterpose, xbt_log_layout_simple_new(NULL));
    xbt_log_additivity_set(&_simgrid_log_category__simterpose, 0);
  }

  msg_error_t res = MSG_main();
  const char *interposer_name =
#ifdef address_translation
    "Address translation (connect pipes instead of sockets)";
#else
  "Full mediation (peek/poke every data)";
#endif
  XBT_INFO("End of simulation. Simulated time: %lf. Used interposer: %s", MSG_get_clock(), interposer_name);

  comm_exit();
  socket_exit();
  cputimer_exit(global_timer);
  simterpose_globals_exit();
  MSG_process_killall(0);

  if (res == MSG_OK)
    return 0;
  else
    return 1;
}

/** @brief Default function called to handle processes */
int simterpose_process_runner(int argc, char *argv[])
{
  int status;
  int tracked_pid = fork();
  if (tracked_pid == 0) {
    // Close the NETLINK socket if any that would offset our fd values
    cputimer_exit(global_timer);

    // In strace mode, we also need to close all strace_out files that were opened for the previous childs
    if (strace_option) {
      void *process;
      unsigned int cpt;
      xbt_dynar_foreach(MSG_processes_as_dynar(), cpt, process) {
        process_descriptor_t * p=(process_descriptor_t *)MSG_process_get_data(process);
        if (!p)
          continue;
        fclose( p->strace_out );
        p->strace_out = NULL;
      }
    }

    // End of cleanups; we are in the child
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      xbt_die("Error when calling ptrace(TRACEME). Bailing out! (%s)", strerror(errno));
    }

    // Ask Linux to not randomize our stacks
    personality(personality(0xffffffff) | ADDR_NO_RANDOMIZE);

    // Wait for master
    kill(getpid(), SIGSTOP);

    xbt_dynar_t cmdline_dynar = xbt_dynar_new(sizeof(char *), NULL);
    int i;
    for (i = 0; i < argc; i++)
      xbt_dynar_push(cmdline_dynar, &argv[i]);
    char *cmdline_str = xbt_str_join(cmdline_dynar, " ");
    char **cmdline_array = (char **) xbt_dynar_to_array(cmdline_dynar);

    // XBT_INFO("Process %d is starting child: %s", getpid(), cmdline_str);
    XBT_INFO("Process is starting child: %s", cmdline_str);

    execv(cmdline_array[0], cmdline_array);     // If successful, the execution flow does not go any further here

    xbt_die("Error while starting %s: %s (full cmdline: %s)", cmdline_array[0], strerror(errno), cmdline_str);
  }
  // We are still in simterpose, so we are the thread that is the representative of the external process
  MSG_process_set_data(MSG_process_self(),
    process_descriptor_new(MSG_host_get_name(MSG_host_self()), argv[0], tracked_pid));

  // Wait for the traced to start
  int res = waitpid(tracked_pid, &status, __WALL);
  if (res < 0)
    perror("waitpid failed");

  // Trace the child and all upcoming granchilds
  increment_nb_setoptions();
  if (ptrace(PTRACE_SETOPTIONS, tracked_pid, NULL,
    PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC |
    PTRACE_O_TRACESYSGOOD)
      == -1) {
    xbt_die("Error in setoptions, bailing out now. (%s)",strerror(errno));
  }

  process_descriptor_t *proc = MSG_process_get_data(MSG_process_self());

  // Main loop where we track our external process and do the simcall that represent its syscalls
  int proc_next_state = PROCESS_CONTINUE;
  while (proc_next_state != PROCESS_DEAD) {
    XBT_DEBUG("Starting treatment");

    pid_t pid = proc->pid;
    ptrace_resume_process(pid);
    if (waitpid(pid, &(proc->status), __WALL) < 0)
      xbt_die(" [%d] waitpid %s %d\n", pid, strerror(errno), errno);
    proc_next_state = process_handle(proc);

    XBT_DEBUG("End of treatment, status = %s ", state_names[proc_next_state]);
  }
  process_die(proc);
  return 0;
}

/** @brief runner called to handle clone processes */
int main_loop(int argc, char *argv[])
{
  process_descriptor_t *proc = MSG_process_get_data(MSG_process_self());

  int proc_next_state = PROCESS_CONTINUE;
  do {
    XBT_DEBUG("Starting treatment (pid = %d)", proc->pid);

    // wait for the process to be created before trying to resume it
    waitpid(-1, &(proc->status), __WALL);

    ptrace_resume_process(proc->pid);
    if (waitpid(proc->pid, &(proc->status), __WALL) < 0)
      xbt_die(" [%d] waitpid %s %d\n", proc->pid, strerror(errno), errno);
    proc_next_state = process_handle(proc);

    XBT_DEBUG("End of treatment, status = %s", state_names[proc_next_state]);
  } while (proc_next_state != PROCESS_DEAD);
  return 0;
}
