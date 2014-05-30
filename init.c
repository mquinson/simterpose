#include "parser.h"             /* for launcher proc desc */
#include "simterpose.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "xbt.h"
#include "simdag/simdag.h"
#include "data_utils.h"
#include "cputimer.h"
#include "sysdep.h"
#include <xbt/config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SIMTERPOSE);

int strace_option = 0;

static void benchmark_matrix_product(float *msec_per_flop);
static void start_all_processes(void);
static void init_host_list(void);

static inline float str_to_double(const char *string)
{
  char *endptr;
  double value = strtof(string, &endptr);
  xbt_assert(*endptr == '\0', "%s is not a double", string);
  return value;
}

static void usage(char *progName, int retcode)
{
  printf("usage : %s [-s] [-p flops_power] platform_file.xml deployment_file.xml\n", progName);
  exit(retcode);
}

void simterpose_init(int argc, char **argv)
{
  float msec_per_flop = 0;
  int flop_option = 0;

  // Initialize SimGrid (and consume the SG command-line options)
  SD_init(&argc, argv);

  // Initialize simterpose
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

  if (argc - optind < 2) {
    usage(argv[0], 1);
  }

  if (!flop_option)
    benchmark_matrix_product(&msec_per_flop);

  simterpose_globals_init(msec_per_flop);

  init_socket_gestion();
  comm_init();

  global_timer = cputimer_new();
  cputimer_init(global_timer);

  SD_create_environment(argv[optind]);
  parse_deployment_file(argv[optind + 1]);

  init_host_list();
  start_all_processes();
}

static void init_host_list()
{
  xbt_dict_t list_s = simterpose_get_host_list();
  xbt_dict_t list_ip = simterpose_get_ip_list();

  xbt_dynar_t no_ip_list = xbt_dynar_new(sizeof(int), NULL);
  xbt_dynar_t ip_list = xbt_dynar_new(sizeof(unsigned int), NULL);

  const SD_workstation_t *work_list = SD_workstation_get_list();
  int i;

  int size = SD_workstation_get_number();

  for (i = 0; i < size; ++i) {
    //simterpose_host *temp = malloc(sizeof(simterpose_host_t));
    const char *prop = SD_workstation_get_property_value(work_list[i], "ip");
    //if there are no ip set, we store them to attribute one after.
    if (prop == NULL) {
      xbt_dynar_push_as(no_ip_list, int, i);
      continue;
    } else {
      simterpose_host_t *temp = malloc(sizeof(simterpose_host_t));
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
    simterpose_host_t *temp = malloc(sizeof(simterpose_host_t));
    temp->ip = temp_ip;
    temp->port = xbt_dict_new_homogeneous(NULL);
    xbt_dict_set(list_s, SD_workstation_get_name(work_list[i]), temp, NULL);
    xbt_dict_set(list_ip, inet_ntoa(in), strdup(SD_workstation_get_name(work_list[i])), NULL);
    xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
  }

  xbt_dynar_free(&ip_list);
  xbt_dynar_free(&no_ip_list);
}

static void start_all_processes()
{
  int rank;

  for (rank = 0; rank < parser_get_amount(); rank++) {
    int status;
    int new_pid = fork();
    if (new_pid == 0) {
      // in child
      if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace traceme");
        exit(1);
      }

      xbt_dynar_t cmdline_dynar = parser_get_commandline(rank);
      char *cmdline_str = xbt_str_join(cmdline_dynar, " ");
      char **cmdline_array = (char **) xbt_dynar_to_array(cmdline_dynar);

      fprintf(stderr, "Process %d is starting child: %s\n", getpid(), cmdline_str);

      if (execv(cmdline_array[0], cmdline_array) == -1) {
        fprintf(stderr, "Error while starting %s: %s (full cmdline: %s)\n", cmdline_array[0], strerror(errno),
                cmdline_str);
        exit(1);
      }

    } else {
      // still in simterpose. wait for the traceme to apply (ie, for child to start)
      waitpid(new_pid, &status, 0);

      //Trace the child and all upcoming granchilds
      if (ptrace(PTRACE_SETOPTIONS, new_pid, NULL,
                 PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)
          == -1) {
        perror("Error setoptions");
        exit(1);
      }
      increment_nb_setoptions();

      process_set_descriptor(new_pid, process_descriptor_new(parser_get_workstation(rank), new_pid));
      FES_schedule_at(new_pid, parser_get_start_time(rank));
    }
  }                             // End of loop over all ranks to start
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

  xbt_cpu_timer_t timer_benchmark = cputimer_new();
  cputimer_init(timer_benchmark);

  // run the experiment for real
  cputimer_get(pid, times, timer_benchmark);
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

  cputimer_get(pid, times, timer_benchmark);
  result = (times[1] + times[2]) - initialTime;
  XBT_DEBUG("Duration of benchmark : %lld", result);

  *msec_per_flop = ((float) result) / (2. * matrixSize * matrixSize * matrixSize);
  float flop_per_sec = (1000000.) / (*msec_per_flop);

  XBT_INFO("Your machine was benchmarked at %.0f flop/s (use -p %.0f to avoid that benchmarking)", flop_per_sec,
           flop_per_sec);

  cputimer_exit(timer_benchmark);
}
