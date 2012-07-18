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

#define equal_d(X, Y) (fabs(X-Y) < FLT_EPSILON)

#define BUFFER_SIZE 512

XBT_LOG_NEW_CATEGORY(SIMTERPOSE, "Simterpose log");


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
//   printf("Add process %d to idle list\n", pid);
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

//Verify is the process is not already schedule before adding
void add_to_sched_list(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
  if(proc->scheduled || proc->on_simulation)
    return;
  
  proc->scheduled =1;
  xbt_dynar_push_as(sched_list, pid_t, pid);
  
//   printf("Add process %d to sched_list\n", pid);
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
//     printf("Move process %d on sched_list\n", pid);
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
    
    xbt_dynar_push_as(sched_list, pid_t, pid);
  }
}



int main(int argc, char *argv[]) { 
  
  simterpose_init(argc, argv);

  double time_to_simulate=0;
  
  idle_process = xbt_dynar_new(sizeof(pid_t), NULL);
  sched_list = xbt_dynar_new(sizeof(pid_t), NULL);
  mediate_list = xbt_dynar_new(sizeof(pid_t), NULL);
  
  do{
    //We calculate the time of simulation.
    time_to_simulate= get_next_start_time() - SD_get_clock();
    if(fabs(time_to_simulate) < FLT_EPSILON)
      time_to_simulate =0.;
    printf("Next simulation time %lf\n", time_to_simulate);
    xbt_dynar_t arr = SD_simulate(time_to_simulate);
    printf("NEW TURN %lf\n", SD_get_clock());
    
    //Now we gonna handle each son for which a watching task is over
    SD_task_t task_over = NULL;
//     printf("Handle task end\n");
    while(!xbt_dynar_is_empty(arr))
    {
      xbt_dynar_shift(arr, &task_over);
      if(SD_task_get_state(task_over) != SD_DONE)
        continue;
      int* data = (int *)SD_task_get_data(task_over);
      //If data is null, we schedule the process
      if(data != NULL)
      {
        process_on_simulation(*data, 0);
        add_to_sched_list(*data);
      }
    }
    
//     printf("Handle idle task\n");
    //Now adding all idle process to the scheduled list
    move_idle_to_sched();
    move_mediate_to_sched();

    while(has_sleeping_to_launch())
    {
//       printf("Trying to add in wait process\n");
      //if we have to launch them to this turn
      if(equal_d(SD_get_clock(),get_next_start_time()))
      {
        int temp_pid = pop_next_pid();
        add_to_sched_list(temp_pid);
        process_descriptor* proc = process_get_descriptor(temp_pid);
        if(proc->in_timeout == PROC_NO_TIMEOUT)
          ++global_data->child_amount;
//         printf("In_timeout = %d\n", proc->in_timeout);
      }
      else
        break;
    }
//     printf("Size of sched_list %ldu\n", xbt_dynar_length(sched_list));
    
    //Now we have global list of process_data, we have to handle them
    while(!xbt_dynar_is_empty(sched_list))
    {
      
      pid_t pid;
      xbt_dynar_shift (sched_list, &pid);
      process_descriptor* proc = process_get_descriptor(pid);
      proc->scheduled = 0;
//       printf("Scheduling process %d\n", pid);    
      int status;
      
      if(process_get_idle(pid) == PROC_IDLE)
        status = process_handle_idle(pid);
        
      else
        status = process_handle_active(pid);
      

      if(status == PROCESS_IDLE_STATE)
      {
        process_set_idle(pid, PROC_IDLE);
        add_to_idle(pid);
      }
      else if( status == PROCESS_DEAD)
      {
        process_die(pid);
        --global_data->child_amount;
      }
      else if(status == PROCESS_ON_MEDIATION)
      {
        add_to_mediate(pid);
      }
      else
        process_set_idle(pid, PROC_NO_IDLE);
    }
    
    printf("End of loop (left %d): Simulation time : %lf\n",global_data->child_amount, SD_get_clock());
  }while(global_data->child_amount);
  

  finish_cputime();
  
  printf("End of simulation. Time : %lf\n", SD_get_clock());
  
  SD_exit();
  destroy_global_data();
  return 0;
}
