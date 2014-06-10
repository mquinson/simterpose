/* simterpose -- main launcher of simterpose                               */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#include <unistd.h>
#include <float.h>
#include <math.h>

#include "args_trace.h"
#include "cputimer.h"
#include "process_descriptor.h"
#include "simterpose.h"
#include <xbt/ex.h>
#include <xbt/fifo.h>
#include <xbt/log.h>
#include "data_utils.h"
#include "parser.h"
#include "communication.h"
#include "syscall_process.h"

#define equal_d(X, Y) (fabs(X-Y) < 1e-9)

#define BUFFER_SIZE 512

XBT_LOG_NEW_CATEGORY(SIMTERPOSE, "Simterpose log");
XBT_LOG_NEW_DEFAULT_SUBCATEGORY(RUN_TRACE, SIMTERPOSE, "run_trace debug");

xbt_dynar_t sched_list;
xbt_dynar_t mediate_list;

static void remove_from_mediate_list(pid_t pid)
{
  process_descriptor_t *proc = process_get_descriptor(pid);
  int i = xbt_dynar_search_or_negative(mediate_list, &proc);
  xbt_assert(i >= 0, "Pid not found in mediate list. Inconsistency found in model");

  xbt_dynar_remove_at(mediate_list, i, NULL);
  proc->in_mediate_list = 0;
}

static void add_to_mediate(pid_t pid)
{
  process_descriptor_t *proc = process_get_descriptor(pid);
  if (proc->in_mediate_list)
    return;
  proc->in_mediate_list = 1;
  xbt_dynar_push(mediate_list, &proc);

  XBT_DEBUG("Add process %d to mediate list", proc->pid);
}

//Verify is the process is not already scheduled before adding
void add_to_sched_list(pid_t pid)
{
  process_descriptor_t *proc = process_get_descriptor(pid);
  if (proc->in_sched_list || proc->on_simulation)
    return;

  proc->in_sched_list = 1;
  xbt_dynar_push(sched_list, &proc);
  XBT_DEBUG("Add process %d to sched_list", pid);

  if (proc->in_mediate_list)
    remove_from_mediate_list(pid);
}

static void move_mediate_to_sched()
{
  while (!xbt_dynar_is_empty(mediate_list)) {
    process_descriptor_t *proc;
    xbt_dynar_shift(mediate_list, &proc);

    proc->in_mediate_list = 0;
    proc->in_sched_list = 1;

    xbt_dynar_push(sched_list, &proc);
    XBT_DEBUG("Move mediated process %d to scheduling", proc->pid);
  }
}

/* A little handler for the Ctrl-C */
static void sigint_handler(int sig)
{
  XBT_ERROR("Interruption request by user. Current time of simulation %lf", SD_get_clock());
  XBT_ERROR("Detaching all processes ...");
  move_mediate_to_sched();
  while (FES_contains_events()) {
    int temp_pid = FES_pop_next_pid();
    add_to_sched_list(temp_pid);
  }
  while (!xbt_dynar_is_empty(sched_list)) {
    process_descriptor_t *proc;
    xbt_dynar_shift(sched_list, &proc);
    ptrace_detach_process(proc->pid);
    process_die(proc->pid);
  }

  XBT_ERROR("Closing everything ...");
  xbt_dynar_free(&sched_list);
  xbt_dynar_free(&mediate_list);
  comm_exit();
  socket_exit();
  cputimer_exit(global_timer);
  simterpose_globals_exit();
  SD_exit();

  xbt_die("Done");
}

int main(int argc, char *argv[])
{

  uid_t uid = getuid(), euid = geteuid();
  if (uid > 0 && uid == euid)
    xbt_die("Simterpose must be run with the super-user privileges.");

  xbt_log_control_set("SIMTERPOSE.:info");
  //xbt_log_control_set("RUN_TRACE.:debug");
  //xbt_log_control_set("ARGS_TRACE.:debug");
  //xbt_log_control_set("SYSCALL_PROCESS.:debug");
  //xbt_log_control_set("CALC_TIMES_PROC.:error");
  //xbt_log_control_set("COMMUNICATION.:debug");
  //xbt_log_control_set("TASK.:debug");
  //xbt_log_control_set("PTRACE_UTILS.:debug");

  simterpose_init(argc, argv);

  // Install our SIGINT handler
  struct sigaction nvt, old;
  memset(&nvt, 0, sizeof(nvt));
  nvt.sa_handler = &sigint_handler;
  sigaction(SIGINT, &nvt, &old);

  double max_duration = 0;

  sched_list = xbt_dynar_new(sizeof(process_descriptor_t *), NULL);
  mediate_list = xbt_dynar_new(sizeof(process_descriptor_t *), NULL);

  int child_amount = 0;
  do {
    // Compute how long the simulation should run
    //       - if we have a timeout ongoing, that will be the duration
    //   - if not, then simulate for -1, which in SD means "as long as you can"
    //   - simulating for at most 0 means to run only the tasks that are immediately runnable
    double next_event_date = FES_peek_next_date();
    if (next_event_date != -1)
      max_duration = next_event_date - SD_get_clock();
    else
      max_duration = -1;

    if (fabs(max_duration) < 1e-9)
      max_duration = 0.;

    //XBT_DEBUG("Next simulation time %.9lf (%.9lf - %.9lf)", max_duration, get_next_start_time(), SD_get_clock());
    if (max_duration < 0 && max_duration != -1) {
      xbt_die("Next simulation time going negative, aborting");
    }

    xbt_dynar_t arr = SD_simulate(max_duration);
    // The simulation time did advance. We are now in the future :)

    //Now we gonna handle each son for which a watching task is over
    SD_task_t task_over = NULL;
    while (!xbt_dynar_is_empty(arr)) {
      xbt_dynar_shift(arr, &task_over);
      XBT_DEBUG("(%lu) A task is returned: %s (%d)", xbt_dynar_length(arr), SD_task_get_name(task_over),
                SD_task_get_state(task_over));
      if (SD_task_get_state(task_over) != SD_DONE)
        continue;
      XBT_DEBUG("A task is over: %s", SD_task_get_name(task_over));
      //If data is not null, we schedule the process
      if (SD_task_get_data(task_over) != NULL) {
        pid_t pid = *(pid_t *) SD_task_get_data(task_over);
        XBT_DEBUG("End of task for %d", (int) pid);
        process_get_descriptor(pid)->on_simulation = 0;
        add_to_sched_list(pid);
      }
      SD_task_destroy(task_over);
    }
    xbt_dynar_free(&arr);

    //Now adding all mediated process to the scheduled list
    move_mediate_to_sched();

    XBT_DEBUG("Starting the waiting process that are now ready");
    while (FES_contains_events() && equal_d(SD_get_clock(), FES_peek_next_date())) {
      int temp_pid = FES_pop_next_pid();
      add_to_sched_list(temp_pid);
      process_descriptor_t *proc = process_get_descriptor(temp_pid);
      if (proc->in_timeout == PROC_NO_TIMEOUT)
        ++child_amount;
      //XBT_DEBUG("In_timeout = %d", proc->in_timeout);

      XBT_DEBUG("child_amount = %d", child_amount);
    }

    XBT_DEBUG("Size of sched_list %lu", xbt_dynar_length(sched_list));

    //Now we have global list of process_data, we have to handle them
    while (!xbt_dynar_is_empty(sched_list)) {

      process_descriptor_t *proc;
      xbt_dynar_shift(sched_list, &proc);
      //  XBT_DEBUG("Scheduling process %d", pid);
      XBT_DEBUG("Scheduling process");
      proc->in_sched_list = 0;

      XBT_DEBUG("Starting treatment");
      int proc_next_state;
      pid_t pid = proc->pid;

      if (proc->mediate_state)
        proc_next_state = process_handle_mediate(proc);
      else
        proc_next_state = process_handle_active(proc);

      XBT_DEBUG("End of treatment, status = %s", state_names[proc_next_state]);
      if (proc_next_state == PROCESS_DEAD) {
        process_die(pid);
        --child_amount;
      } else if (proc_next_state == PROCESS_ON_MEDIATION)
        add_to_mediate(pid);
    }

    XBT_DEBUG("child_amount = %d", child_amount);
  } while (child_amount);

  xbt_dynar_free(&sched_list);
  xbt_dynar_free(&mediate_list);
  comm_exit();
  socket_exit();
  cputimer_exit(global_timer);
  const char *interposer_name =
#ifdef address_translation
      "Address translation (connect pipes instead of sockets)";
#else
      "Full mediation (peek/poke every data)";
#endif

  XBT_INFO("End of simulation. Simulated time: %lf. Used interposer: %s", SD_get_clock(), interposer_name);
  XBT_INFO
      ("Total amount of ptrace(): %d (peek/poke: %d/%d, getregs/setregs: %d/%d, detach: %d, syscall: %d, geteventmsg: %d, setoption: %d)",
       get_nb_peek() + get_nb_poke() + get_nb_getregs() + get_nb_setregs() + get_nb_detach() + get_nb_syscall() +
       get_nb_geteventmsg() + get_nb_setoptions(), get_nb_peek(), get_nb_poke(), get_nb_getregs(), get_nb_setregs(),
       get_nb_detach(), get_nb_syscall(), get_nb_geteventmsg(), get_nb_setoptions());

  simterpose_globals_exit();
  SD_exit();
  return 0;
}
