#include <unistd.h>
#include <float.h>
#include <math.h>

#include "args_trace.h"
#include "calc_times_proc.h"
#include "process_descriptor.h"
#include "run_trace.h"
#include "xbt/fifo.h"
#include "xbt/log.h"
#include "data_utils.h"
#include "parser.h"
#include "init.h"
#include "communication.h"
#include "syscall_process.h"

#define equal_d(X, Y) (fabs(X-Y) < 1e-9)

#define BUFFER_SIZE 512

XBT_LOG_NEW_CATEGORY(ST, "Simterpose log");
XBT_LOG_NEW_DEFAULT_SUBCATEGORY(RUN_TRACE, ST, "run_trace debug");

void sig_int(int sig)
{
  XBT_ERROR("Interruption request by user");
  XBT_ERROR("Current time of simulation %lf", SD_get_clock());
  exit(0);
}


void print_trace_header(FILE* trace)
{
  fprintf(trace,"%8s %12s %8s %10s %10s %21s %21s\n","pidX", "syscall", "pidY", "return","diff_cpu","local_addr:port", "remote_addr:port");
}

xbt_dynar_t idle_process;
xbt_dynar_t sched_list;
xbt_dynar_t mediate_list;


void remove_from_idle_list(pid_t pid)
{
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(idle_process, &pid);
    xbt_dynar_remove_at(idle_process, i, NULL);
    process_descriptor *proc = process_get_descriptor(pid);
    proc->idle_list=0;
  }
  CATCH(e){
    xbt_die("Pid not found in list. Inconsistance found in model");
  } 
}

void remove_from_mediate_list(pid_t pid)
{
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(mediate_list, &pid);
    xbt_dynar_remove_at(mediate_list, i, NULL);
    process_descriptor *proc = process_get_descriptor(pid);
    proc->on_mediation=0;
  }
  CATCH(e){
    xbt_die("Pid not found in list. Inconsistance found in model");
  } 
}


void add_to_idle(pid_t pid)
{
  process_descriptor* proc = process_get_descriptor(pid);
  if(proc->idle_list)
    return;
  if(proc->on_mediation)
    THROW_IMPOSSIBLE;
  proc->idle_list=1;
  XBT_DEBUG("Add process %d to idle list", pid);
  xbt_dynar_push_as(idle_process, pid_t, pid);
}

void add_to_mediate(pid_t pid)
{
  process_descriptor* proc = process_get_descriptor(pid);
  if(proc->on_mediation)
    return;
  if(proc->idle_list)
    THROW_IMPOSSIBLE;
  proc->on_mediation=1;
  
  xbt_dynar_push_as(mediate_list, pid_t, pid);
}

//Verify is the process is not already scheduled before adding
void add_to_sched_list(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
  if(proc->scheduled || proc->on_simulation)
    return;
  
  proc->scheduled =1;
  xbt_dynar_push_as(sched_list, pid_t, pid);
  
  XBT_DEBUG("Add process %d to sched_list", pid);
  if(proc->idle_list)
    remove_from_idle_list(pid);
  else if(proc->on_mediation)
    remove_from_mediate_list(pid);
}


void move_idle_to_sched()
{
  pid_t pid;
  while(!xbt_dynar_is_empty(idle_process))
  {
    xbt_dynar_shift(idle_process, &pid);
    process_descriptor *proc = process_get_descriptor(pid);
    
    proc->idle_list = 0;
    XBT_DEBUG("Move idle process %d on sched_list", pid);
    proc->scheduled = 1;
    xbt_dynar_push_as(sched_list, pid_t, pid);
  }
}

void move_mediate_to_sched()
{
  pid_t pid;
  while(!xbt_dynar_is_empty(mediate_list))
  {
    xbt_dynar_shift(mediate_list, &pid);
    process_descriptor *proc = process_get_descriptor(pid);
    
    proc->on_mediation = 0;
    proc->scheduled = 1;
    XBT_DEBUG("Move mediate process to sched %d", pid);
    
    xbt_dynar_push_as(sched_list, pid_t, pid);
  }
}



int main(int argc, char *argv[]) { 

xbt_log_control_set("ST.:debug"); /*

xbt_log_control_set("RUN_TRACE.:debug"); 
//xbt_log_control_set("BENCHMARK.:debug");
xbt_log_control_set("ARGS_TRACE.:debug");
xbt_log_control_set("SYSCALL_PROCESS.:debug");/*
xbt_log_control_set("CALC_TIMES_PROC.:error");
xbt_log_control_set("COMMUNICATION.:debug");
xbt_log_control_set("TASK.:debug");
xbt_log_control_set("PTRACE_UTILS.:debug");
// */

nb_peek=0;
nb_poke=0;
nb_getregs=0;
nb_setregs=0;
nb_syscall=0;
nb_traceme=0;
nb_setoptions=0;
nb_detach=0;
nb_geteventmsg=0;

  simterpose_init(argc, argv);

  struct sigaction nvt, old;
  memset(&nvt, 0, sizeof(nvt));
  nvt.sa_handler = &sig_int;
  
  sigaction(SIGINT, &nvt, &old);
  
  double time_to_simulate=0;
  
//   int indice = 10000;
  
  idle_process = xbt_dynar_new(sizeof(pid_t), NULL);
  sched_list = xbt_dynar_new(sizeof(pid_t), NULL);
  mediate_list = xbt_dynar_new(sizeof(pid_t), NULL);
  int i = 10; //debug
  int child_amount=0;
  do{
    //We calculate the time of simulation.
    double next_start_time = get_next_start_time();
    if(next_start_time != -1)
      time_to_simulate= next_start_time - SD_get_clock();
    else
      time_to_simulate = -1;
    
    if(fabs(time_to_simulate) < 1e-9)
      time_to_simulate =0.;
    
	//XBT_DEBUG("Next simulation time %.9lf (%.9lf - %.9lf)", time_to_simulate, get_next_start_time(), SD_get_clock());
    if(time_to_simulate < 0 && time_to_simulate != -1)
    {
      XBT_ERROR("Next simulation time going negative, aborting");
      THROW_IMPOSSIBLE;
    }
    
    xbt_dynar_t arr = SD_simulate(time_to_simulate);
	//XBT_DEBUG("NEW TURN %.9lf", SD_get_clock());
    
    //Now we gonna handle each son for which a watching task is over
    SD_task_t task_over = NULL;
    while(!xbt_dynar_is_empty(arr))
    {
      xbt_dynar_shift(arr, &task_over);
     XBT_DEBUG("(%lu) A task is returned: %s (%d)",xbt_dynar_length(arr), SD_task_get_name(task_over), SD_task_get_state(task_over));
      if(SD_task_get_state(task_over) != SD_DONE)
        continue;
      XBT_DEBUG("A task is over: %s", SD_task_get_name(task_over));
      int* data = (int *)SD_task_get_data(task_over);
      //If data is not null, we schedule the process
      if(data != NULL)
      {
       XBT_DEBUG("End of task for %d", *data);
        process_on_simulation(process_get_descriptor(*data), 0);
        add_to_sched_list(*data); 
      }
      SD_task_destroy(task_over);
    }
    xbt_dynar_free(&arr);
    
    //Now adding all idle process to the scheduled list
    move_idle_to_sched();
    move_mediate_to_sched();

    while(has_sleeping_to_launch())
    {
      XBT_DEBUG("Trying to add waiting process");
      //if we have to launch them to this turn
      if(equal_d(SD_get_clock(),get_next_start_time()))
      {
        int temp_pid = pop_next_pid();
        add_to_sched_list(temp_pid);
        process_descriptor* proc = process_get_descriptor(temp_pid);
        if(proc->in_timeout == PROC_NO_TIMEOUT)
          ++child_amount;
	//XBT_DEBUG("In_timeout = %d", proc->in_timeout);

	XBT_DEBUG("child_amount = %d", child_amount);
      }
      else
        break;
    }
     XBT_DEBUG("Size of sched_list %lu", xbt_dynar_length(sched_list));
    
    //Now we have global list of process_data, we have to handle them
    while(!xbt_dynar_is_empty(sched_list))
    {
      
      pid_t pid;
      xbt_dynar_shift (sched_list, &pid);
      process_descriptor* proc = process_get_descriptor(pid);
      XBT_DEBUG("Scheduling process %d", pid);
      proc->scheduled = 0;
      
      XBT_DEBUG("Starting treatment");
      int status;
      
      if(proc->mediate_state)
        status = process_handle_mediate(pid);
      else if(process_get_idle(proc) == PROC_IDLE)
        status = process_handle_idle(pid);
        
      else
        status = process_handle_active(pid);
      

       XBT_DEBUG("End of treatment, status = %d", status);
      if(status == PROCESS_IDLE_STATE)
      {
	  XBT_DEBUG("status = PROCESS_IDLE_STATE");
        process_set_idle(proc, PROC_IDLE);
        add_to_idle(pid);
      }
      else if( status == PROCESS_DEAD)
      {
	  XBT_DEBUG("status = PROCESS_DEAD");
        process_die(pid);
        --child_amount;
      }
      else if(status == PROCESS_ON_MEDIATION)
      {
	  XBT_DEBUG("status = PROCESS_ON_MEDIATION");
        add_to_mediate(pid);
      }
	else if(status == PROCESS_TASK_FOUND)
      {
	   XBT_DEBUG("status = PROCESS_TASK_FOUND");
      }
	else if(status == PROCESS_ON_COMPUTATION)
      {
	  XBT_DEBUG("status = PROCESS_ON_COMPUTATION");
      }
    }


//     --indice;
//     if(!indice)
//     {
//       fprintf(stderr, "End of loop (left %d): Simulation time : %lf\n",global_data->child_amount, SD_get_clock());
//       indice = 10000;
//     }
//       if(SD_get_clock() > 1000)
//         break;

	XBT_DEBUG("child_amount = %d", child_amount);
	i--;
  }while(child_amount); //i);//
  

  finish_cputime();
  
  XBT_INFO("End of simulation. Time : %lf", SD_get_clock());
#ifdef address_translation
  XBT_INFO("Address translation used");
#else
  XBT_INFO("Full mediation used");
#endif
	XBT_DEBUG("%d peek et %d poke ", nb_peek, nb_poke);
	XBT_DEBUG("%d getregs et %d setregs", nb_getregs, nb_setregs);
	XBT_DEBUG("%d traceme et %d detach ", nb_traceme, nb_detach);
	XBT_DEBUG("%d syscall, %d geteventmsg et %d setoptions ", nb_syscall, nb_geteventmsg, nb_setoptions);
	XBT_INFO("nb total de ptrace() = %d ", nb_peek+nb_poke+nb_getregs+nb_setregs+nb_traceme+nb_detach+nb_syscall+nb_geteventmsg+nb_setoptions);
  
  SD_exit();
  destroy_global_data();
  xbt_dynar_free(&sched_list);
  xbt_dynar_free(&idle_process);
  xbt_dynar_free(&mediate_list);
  comm_exit();
  socket_exit();
  finish_cputime();
  printf("End of simulation\n");
  return 0;
}
