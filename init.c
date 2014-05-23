#include "parser.h"             /* for launcher proc desc */
#include "simterpose.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "xbt.h"
#include "simdag/simdag.h"
#include "data_utils.h"
#include "cputimer.h"
#include "init.h"
#include "sysdep.h"
#include <xbt/config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SIMTERPOSE);

extern xbt_cfg_t _sg_cfg_set;

static void benchmark_matrix_product(float *msec_per_flop);

void init_station_list()
{
  xbt_dict_t list_s = simterpose_get_station_list();
  xbt_dict_t list_ip = simterpose_get_ip_list();

  xbt_dynar_t no_ip_list = xbt_dynar_new(sizeof(int), NULL);
  xbt_dynar_t ip_list = xbt_dynar_new(sizeof(unsigned int), NULL);

  const SD_workstation_t *work_list = SD_workstation_get_list();
  int i;

  int size = SD_workstation_get_number();

  for (i = 0; i < size; ++i) {
    //simterpose_station *temp = malloc(sizeof(simterpose_station));
    const char *prop = SD_workstation_get_property_value(work_list[i], "ip");
    //if there are no ip set, we store them to attribute one after.
    if (prop == NULL) {
      xbt_dynar_push_as(no_ip_list, int, i);
      continue;
    } else {
      simterpose_station *temp = malloc(sizeof(simterpose_station));
      temp->ip = inet_addr(prop);
      temp->port = xbt_dict_new_homogeneous(free);
      xbt_dict_set(list_s, SD_workstation_get_name(work_list[i]), temp, NULL);
      xbt_dict_set(list_ip, prop, strdup(SD_workstation_get_name(work_list[i])), NULL);
      xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
    }
  }

  unsigned int temp_ip = 1;
  xbt_ex_t e;
  //Now we have to attribute ip to workstation which haven't have one
  while (!xbt_dynar_is_empty(no_ip_list)) {
    int i;
    xbt_dynar_shift(no_ip_list, &i);

    //Now verify that ip address is not already use
    int found = 1;
    while (found) {
      TRY {
        xbt_dynar_search(ip_list, &temp_ip);
        ++temp_ip;
      }
      CATCH(e) {
        xbt_ex_free(e);
        found = 0;
      }
    }
    struct in_addr in = { temp_ip };
    simterpose_station *temp = malloc(sizeof(simterpose_station));
    temp->ip = temp_ip;
    temp->port = xbt_dict_new_homogeneous(NULL);
    xbt_dict_set(list_s, SD_workstation_get_name(work_list[i]), temp, NULL);
    xbt_dict_set(list_ip, inet_ntoa(in), strdup(SD_workstation_get_name(work_list[i])), NULL);
    xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
  }

  xbt_dynar_free(&ip_list);
  xbt_dynar_free(&no_ip_list);
}

static inline float str_to_double(const char *string)
{
  char *endptr;
  double value = strtof(string, &endptr);
  xbt_assert(*endptr == '\0',  "%s is not a double", string);
  return value;
}

void usage(char *progName)
{
  printf("usage : %s [-p flops_power] platform_file.xml deployment_file.xml\n", progName);
}

void simterpose_init(int argc, char **argv)
{
  float msec_per_flop = 0;
  int flop_option = 0;

  // Initialize SimGrid (and consume the SG command-line options)
  SD_init(&argc, argv);

  // Initialize simterpose
  if (argc < 3) {
    usage(argv[0]);
    exit(1);
  } else {
    int c;
    while ((c = getopt(argc, argv, "+p:")) != EOF) {
      switch (c) {
      case 'p':
        flop_option = 1;
        msec_per_flop = 1000000 / str_to_double(optarg);
        XBT_INFO("Setting reference power to %s flop/s", optarg);

        break;

      default:
        usage(argv[0]);
        break;
      }
    }

  }

  if (argc - optind < 2) {
    usage(argv[0]);
    exit(1);
  }

  if (!flop_option)
    benchmark_matrix_product(&msec_per_flop);


  init_global_data(msec_per_flop);

  init_socket_gestion();
  init_comm();
  cputimer_init();               // creates socket

  SD_create_environment(argv[optind]);
  parse_deployment_file(argv[optind + 1]);

  init_station_list();
  start_processes();
}


void fprint_array(FILE * file, char **array)
{
  int i = 0;
  while (1) {
    fprintf(file, "%s", array[i]);
    printf("[%s]", array[i]);
    ++i;
    if (array[i] != NULL) {
      printf(" ");
      fprintf(file, " ");
    } else
      break;
  }
  fprintf(file, "\n");
  printf("(fin de commande)\n");
  fflush(file);
}


void run_until_exec(pid_t pid)
{
  int exec_found = 0;
  int exec_passed = 0;
  int status;

  //First we run process until we found the first exec.
  reg_s arg;
  while (!exec_found) {
    waitpid(pid, &status, 0);
    ptrace_get_register(pid, &arg);
    if (arg.reg_orig == SYS_execve) {
      exec_found = 1;
    }
    //Here we can run even if we found an execve because we trap the syscall when it came from process
    ptrace_resume_process(pid);
  }

  //Second we bring process to the first syscall which is not an execve
  while (!exec_passed) {
    waitpid(pid, &status, 0);
    ptrace_get_register(pid, &arg);
    if (arg.reg_orig != SYS_execve)
      exec_passed = 1;
    else
      ptrace_resume_process(pid);
  }
}



void start_processes()
{
  int status;

  //First we make pipe for communication and we start running the launcher
  int comm_launcher[2];
  pipe(comm_launcher);


  int launcherpid = fork();

  if (launcherpid == 0) {

    close(0);
    dup2(comm_launcher[0], 0);

    close(comm_launcher[1]);
    close(comm_launcher[0]);

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme");
      exit(1);
    }
    nb_traceme++;

    if (execl("launcher", "launcher", NULL) == -1) {
      perror("execl");
      exit(1);
    }

  } else {

    close(comm_launcher[0]);

    // wait for the launcher child to be blocked by ptrace(TRACEME)
    waitpid(launcherpid, &status, 0);
    if (WIFSIGNALED(status))
    	XBT_ERROR("Launcher got a signal %d",WTERMSIG(status));
    if (WIFEXITED(status))
    	XBT_ERROR("Launched returned %d",WEXITSTATUS(status));

    // Trace the launcher, and all its son
    if (ptrace
        (PTRACE_SETOPTIONS, launcherpid, NULL,
         PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE) == -1) {
      perror("Error setoptions");
      exit(1);
    }
    nb_setoptions++;

    FILE *launcher_pipe = NULL;
    launcher_pipe = fdopen(comm_launcher[1], "w");

    int amount_process_launch = 0;
    int amount = parser_get_amount();

    //We write the amount of process to launch for the launcher
    fprintf(launcher_pipe, "%d\n", amount);
    fflush(launcher_pipe);

    //Now we launch all process and let them blocked on the first syscall following the exec
    while (amount_process_launch < amount) {
      process_descriptor *proc;
      fprint_array(launcher_pipe, parser_get_commandline(amount_process_launch));

      int forked = 0;
      pid_t new_pid;
      while (!forked) {
        ptrace_resume_process(launcherpid);

        waitpid(launcherpid, &status, 0);

        // check if it's a fork
        int stat16 = status >> 16;

        if (stat16 == PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16 == PTRACE_EVENT_CLONE) {
          new_pid = ptrace_get_pid_fork(launcherpid);
          proc = process_descriptor_new(parser_get_workstation(amount_process_launch), new_pid);
          process_set_descriptor(new_pid, proc);
          forked = 1;
        }
      }
      //resume fork syscall
      ptrace_resume_process(launcherpid);

      run_until_exec(new_pid);
      process_set_in_syscall(proc);

      add_launching_time(new_pid, parser_get_start_time(amount_process_launch));

      ++amount_process_launch;
    }
    parser_free_all();
    fclose(launcher_pipe);
  }

  //Now we detach launcher because we don't need it anymore
  ptrace_detach_process(launcherpid);
}

/* Get the power of the current machine from a simple matrix product operation */
static void benchmark_matrix_product(float *msec_per_flop)
{
  srand(time(NULL));
  int matrixSize = rand() % 20 + 500;

  int i, j;


  float **matrix1 = malloc(sizeof(float *) * matrixSize);
  float **matrix2 = malloc(sizeof(float *) * matrixSize);
  float **matrix_result = malloc(sizeof(float *) * matrixSize);

  // Warmup the caches
  for (i = 0; i < matrixSize; ++i) {
    matrix1[i] = malloc(sizeof(float) * matrixSize);
    matrix2[i] = malloc(sizeof(float) * matrixSize);
    matrix_result[i] = malloc(sizeof(float) * matrixSize);
    for (j = 0; j < matrixSize; ++j) {
      matrix1[i][j] = rand() % 20;
      matrix2[i][j] = rand() % 20;
      matrix_result[i][j] = rand() % 20;
    }
  }

  long long int times[3];
  long long int result;

  pid_t pid = getpid();

  cputimer_init();

  // run the experiment for real
  cputimer_get(pid, times);
    long long int initialTime = times[1] + times[2];
    int i_result, j_result;

    for (j_result = 0; j_result < matrixSize; ++j_result) {
      for (i_result = 0; i_result < matrixSize; ++i_result) {
        for (i = 0; i < matrixSize; ++i) {
          matrix_result[j_result][i_result] =
              matrix_result[i_result][j_result] + matrix1[i_result][i] * matrix2[i][j_result];
        }
      }
    }


    cputimer_get(pid, times);
    result = (times[1] + times[2]) - initialTime;
    XBT_DEBUG("Duration of benchmark : %lld", result);

    *msec_per_flop = ((float) result) / (2. * matrixSize * matrixSize * matrixSize);
    float flop_per_sec = (1000000.) / (*msec_per_flop);

    XBT_INFO("Your machine was benchmarked at %.0f flop/s (use -p %.0f to avoid that benchmarking)", flop_per_sec, flop_per_sec);

  cputimer_exit();
}
