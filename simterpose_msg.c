/* simterpose_msg - simterpose intercepter based on MSG                     */

/* Copyright (c) 2014. The SimGrid Team. All right reserved.                */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPL) which comes with this package. */

#include <sys/ptrace.h>
#include <wait.h>
#include <errno.h>
#include <unistd.h>

#include <msg/msg.h>
#include <xbt.h>
#include "simterpose_msg.h"
#include "sockets_msg.h"
#include "cputimer_msg.h"
#include "communication_msg.h"
#include "data_utils_msg.h"
#include "ptrace_utils_msg.h"
#include "syscall_process_msg.h"
#include "process_descriptor_msg.h"

XBT_LOG_NEW_DEFAULT_CATEGORY(simterpose, "High-level simterpose category");
int strace_option = 0;

static void usage(char *progName, int retcode)
{
  printf("usage : %s  [-s] [-p flops_power] platform_file.xml deployment_file.xml\n", progName);
  exit(retcode);
}

static inline float str_to_double(const char *string)
{
  char *endptr;
  double value = strtof(string, &endptr);
  xbt_assert(*endptr == '\0', "%s is not a double", string);
  return value;
}

int main(int argc, char *argv[])
{
  float msec_per_flop = 0;      // variable not used
  int flop_option = 0;
  xbt_log_control_set("simterpose.:debug");
  MSG_init(&argc, argv);

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

  msg_error_t res = MSG_main();
  XBT_INFO("Simulated time: %g", MSG_get_clock());

  if (res == MSG_OK)
    return 0;
  else
    return 1;
}

static int simterpose_process_runner(int argc, char *argv[])
{
  int status;
  int tracked_pid = fork();
  if (tracked_pid == 0) {
    // in child
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme");
      exit(1);
    }
    xbt_dynar_t cmdline_dynar = xbt_dynar_new(sizeof(char *), NULL);
    int i;
    for (i = 0; i < argc; i++)
      xbt_dynar_push(cmdline_dynar, &argv[i]);
    char *cmdline_str = xbt_str_join(cmdline_dynar, " ");
    char **cmdline_array = (char **) xbt_dynar_to_array(cmdline_dynar);

    XBT_INFO("Process %d is starting child: %s", getpid(), cmdline_str);

    // FIXME: what's the point of setting the description right before reseting the memory with execv??
    process_set_descriptor(process_descriptor_new(MSG_host_get_name(MSG_host_self()), getpid()));

    execv(cmdline_array[0], cmdline_array);     // If successful, the execution flow does not go any further here

    fprintf(stderr, "Error while starting %s: %s (full cmdline: %s)", cmdline_array[0], strerror(errno), cmdline_str);
    exit(1);
  }
  // We are still in simterpose, so we are the thread that is the representative of the external process

  // Wait for the traceme to apply (ie, for the child to start)
  waitpid(tracked_pid, &status, 0);
  process_set_descriptor(process_descriptor_new(MSG_host_get_name(MSG_host_self()), tracked_pid));

  // Trace the child and all upcoming granchilds
  if (ptrace(PTRACE_SETOPTIONS, tracked_pid, NULL,
             PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)
      == -1) {
    perror("Error setoptions");
    exit(1);
  }

  double clock = MSG_get_clock();
  process_descriptor_t *proc = MSG_process_get_data(MSG_process_self());

  // Main loop where we track our external process and do the simcall that represent its syscalls
  while (1) {

	  	XBT_DEBUG("Starting treatment");
	  	int proc_next_state = process_handle_active(proc);

	  //	double clock = MSG_get_clock();
	  	while(proc_next_state == PROCESS_ON_MEDIATION){
	  		if (proc->mediate_state)
	  			proc_next_state = process_handle_mediate(proc);
	  		else
	  			proc_next_state = process_handle_active(proc);

		  	XBT_DEBUG("while status = %s", state_names[proc_next_state]);

	  		if (MSG_get_clock() == clock) {
	  		  MSG_process_sleep(0.1);
	  		  clock = MSG_get_clock();
	  		}
	 	}
	  	XBT_DEBUG("End of treatment, status = %s", state_names[proc_next_state]);
  }
  return 0;
}
