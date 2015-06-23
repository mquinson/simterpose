/* data utils -- Contains SimTerpose global data such as hosts and
   ports */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <xbt.h>

#include "data_utils.h"
#include "process_descriptor.h"
#include "cputimer.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(DATA_UTILS, simterpose, "data_utils log");

struct simterpose_globals {
  xbt_dict_t list_host;
  xbt_dict_t list_ip;
  xbt_dict_t list_translate;
  int nb_peek;
  int nb_poke;
  int nb_getregs;
  int nb_setregs;
  int nb_syscall;
  int nb_setoptions;
  int nb_detach;
  int nb_geteventmsg;
};
typedef struct simterpose_globals simterpose_data_t;
simterpose_data_t *global_data;

/** @brief initialize SimTerpose global data */
void simterpose_globals_init(float msec_per_flop)
{
  global_data = xbt_new0(simterpose_data_t,1);

  global_data->list_host = xbt_dict_new_homogeneous(&destroy_simterpose_host);
  global_data->list_ip = xbt_dict_new_homogeneous(&free);
  global_data->list_translate = xbt_dict_new_homogeneous(&free);

  global_data->nb_peek = 0;
  global_data->nb_poke = 0;
  global_data->nb_getregs = 0;
  global_data->nb_setregs = 0;
  global_data->nb_syscall = 0;
  global_data->nb_setoptions = 0;
  global_data->nb_detach = 0;
  global_data->nb_geteventmsg = 0;
}

/** @brief free SimTerpose global data */
void simterpose_globals_exit()
{
  xbt_dict_free(&(global_data->list_host));
  xbt_dict_free(&(global_data->list_ip));
  xbt_dict_free(&(global_data->list_translate));
  free(global_data);
}

/** @brief retrieve the number of calls to PTRACE_PEEKDATA */
int get_nb_peek(void)
{
  return global_data->nb_peek;
}

/** @brief retrieve the number of calls to PTRACE_POKEDATA */
int get_nb_poke()
{
  return global_data->nb_poke;
}

/** @brief retrieve the number of calls to PTRACE_GETREGS */
int get_nb_getregs()
{
  return global_data->nb_getregs;
}

/** @brief retrieve the number of calls to PTRACE_SETREGS */
int get_nb_setregs()
{
  return global_data->nb_setregs;
}

/** @brief retrieve the number of calls to PTRACE_SYSCALL */
int get_nb_syscall()
{
  return global_data->nb_syscall;
}

/** @brief retrieve the number of calls to PTRACE_SETOPTIONS */
int get_nb_setoptions()
{
  return global_data->nb_setoptions;
}

/** @brief retrieve the number of calls to PTRACE_DETACH */
int get_nb_detach()
{
  return global_data->nb_detach;
}

/** @brief retrieve the number of calls to PTRACE_GETEVENTMSG */
int get_nb_geteventmsg()
{
  return global_data->nb_geteventmsg;
}

/** @brief increment the number of calls to PTRACE_PEEKDATA */
void increment_nb_peek()
{
  global_data->nb_peek++;
}

/** @brief increment the number of calls to PTRACE_POKEDATA */
void increment_nb_poke()
{
  global_data->nb_poke++;
}

/** @brief increment the number of calls to PTRACE_GETREGS */
void increment_nb_getregs()
{
  global_data->nb_getregs++;
}

/** @brief increment the number of calls to PTRACE_SETREGS */
void increment_nb_setregs()
{
  global_data->nb_setregs++;
}

/** @brief increment the number of calls to PTRACE_SYSCALL */
void increment_nb_syscall()
{
  global_data->nb_syscall++;
}

/** @brief increment the number of calls to PTRACE_SETOPTIONS */
void increment_nb_setoptions()
{
  global_data->nb_setoptions++;
}

/** @brief increment the number of calls to PTRACE_DETACH */
void increment_nb_detach()
{
  global_data->nb_detach++;
}

/** @brief increment the number of calls to PTRACE_GETEVENTMSG */
void increment_nb_geteventmsg()
{
  global_data->nb_geteventmsg++;
}

/** @brief function called to free a host when it is removed from the host list */
void destroy_simterpose_host(void *data)
{
  simterpose_host_t *host = (simterpose_host_t *) data;
  xbt_dict_free(&(host->port));
  free(host);
}

/** @brief check if the port is used on the given host */
int is_port_in_use(msg_host_t host, int port)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  return (xbt_dict_get_or_null(temp->port, buff) != NULL);
}

/** @brief register the port to the host, if not already used */
void register_port(msg_host_t host, int port)
{
  //try to see if port isn't already use.
  simterpose_host_t *host_desc = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *temp = NULL;


  if ((temp = (port_desc_t *) xbt_dict_get_or_null(host_desc->port, buff))) {
    ++(temp->amount_socket);
  } else {
    temp = xbt_malloc0(sizeof(port_desc_t));
    temp->port_num = port;
    temp->option = 0;
    temp->amount_socket = 1;
    temp->bind_socket = NULL;

    xbt_dict_set(host_desc->port, buff, temp, NULL);
  }
}

/** @brief put the socket and port in binding state */
void set_port_on_binding(msg_host_t host, int port, struct infos_socket *is, int device)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (!desc)
    return;
  desc->option = desc->option | PORT_BIND | device;
  desc->bind_socket = is;
  is->ref_nb++;
}

/** @brief get the bound socket corresponding to the given port on the given host*/
struct infos_socket *get_binding_socket_host(msg_host_t host, int port, int device)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL || !(desc->option & PORT_BIND))
    return NULL;

  if (!(device & desc->option))
    return NULL;

  return desc->bind_socket;
}

/** @brief put the real port corresponding to the simulated port into port_desc_t */
void set_real_port(msg_host_t host, int port, int real_port)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL)
    return;
  XBT_DEBUG("Set correspondence %d <-> %d (real) for %s", port, real_port, MSG_host_get_name(host));
  desc->real_port = real_port;
}

/** @brief retrieve the ip of the given host */
unsigned int get_ip_of_host(msg_host_t host)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  return temp->ip;
}

/** @brief retrieve the host corresponding to the given ip */
msg_host_t get_host_by_ip(unsigned int ip)
{
  struct in_addr in = { ip };
  char *name = xbt_dict_get_or_null(global_data->list_ip, inet_ntoa(in));
  if (!name)
    return NULL;

  return MSG_get_host_by_name(name);
}

/** @brief get a random unused port */
int get_random_port(msg_host_t host)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  unsigned short port = 0;
  --port;

  while (1) {
    char buff[6];
    sprintf(buff, "%d", port);
    if (xbt_dict_get_or_null(temp->port, buff))
      --port;
    else
      break;
  }

  return port;
}

/** @brief the socket doesn't use the port anymore, remove it from port_desc_t */
void unset_socket(pid_t pid, struct infos_socket *is)
{
  msg_host_t host = is->host;
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));

  char buff[6];
  sprintf(buff, "%d", is->port_local);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (!desc) {
    fprintf(stderr, "No descriptor found for port %s\n", buff);
    return;
  }

  if (is == desc->bind_socket) {
    is->ref_nb--;
    desc->bind_socket = NULL;
  }

  --desc->amount_socket;
  if (desc->amount_socket)
    return;

  //if this is the last socket to use the port, we have to remove it from dict
  xbt_dict_remove(temp->port, buff);
}

/** @brief add a new correspondence between real and simulated ip/port to the translation list  */
void add_new_translation(int real_port, int translated_port, unsigned int translated_ip)
{
  XBT_DEBUG("Add new translation %d->%d", real_port, translated_port);
  translate_desc_t *temp = xbt_malloc0(sizeof(translate_desc_t));
  temp->port_num = translated_port;
  temp->ip = translated_ip;

  char buff[6];
  sprintf(buff, "%d", real_port);

  xbt_dict_set(global_data->list_translate, buff, temp, NULL);
}

/** @brief retrieve the simulated ip/port corresponding to the given (real) one */
translate_desc_t *get_translation(int real_port)
{
  XBT_DEBUG("Get translation for port %d", real_port);
  char buff[6];
  sprintf(buff, "%d", real_port);

  return xbt_dict_get_or_null(global_data->list_translate, buff);
}

/** @brief retrieve the real port corresponding to the given (simulated) ip/port */
int get_real_port(process_descriptor_t * proc, unsigned int ip, int port)
{
  simterpose_host_t *temp = NULL;
  if (ip == inet_addr("127.0.0.1")) {
    XBT_DEBUG("We are on local network %d\n", port);
    temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(proc->host));
  } else
    temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(get_host_by_ip(ip)));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL)
    return -1;

  XBT_DEBUG("Return %d", desc->real_port);
  return desc->real_port;
}

/** @brief retrieve the list of all MSG hosts */
xbt_dict_t simterpose_get_host_list()
{
  return global_data->list_host;
}

/** @brief retrieve the ip list */
xbt_dict_t simterpose_get_ip_list()
{
  return global_data->list_ip;
}


/* @brief Get the power of the current machine from a simple matrix product operation */
void benchmark_matrix_product(float *msec_per_flop)
{
  srand(time(NULL));
  int matrixSize = rand() % 20 + 500;

  int i, j;


  float **matrix1 = xbt_new0(float *, matrixSize);
  float **matrix2 = xbt_new0(float *, matrixSize);
  float **matrix_result = xbt_new0(float *, matrixSize);

  // Warmup the caches
  for (i = 0; i < matrixSize; ++i) {
    matrix1[i] = xbt_new0(float, matrixSize);
    matrix2[i] = xbt_new0(float, matrixSize);
    matrix_result[i] = xbt_new0(float, matrixSize);
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

  // Run the experiment for real
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
  //XBT_INFO("Duration of benchmark : %lld", result);

  *msec_per_flop = ((float) result) / (2. * matrixSize * matrixSize * matrixSize);
  //  float flop_per_sec = (1000000.) / (*msec_per_flop);

  //XBT_INFO("Your machine was benchmarked at %.0f flop/s (use -p %.0f to avoid that benchmarking)", flop_per_sec,flop_per_sec);

  cputimer_exit(timer_benchmark);
}

/** @brief initialize the host list
 *
 * We retrieve the host list from the MSG environment, which was previously
 * created thanks to the platform file */
void init_host_list()
{
  xbt_dict_t list_s = simterpose_get_host_list();
  xbt_dict_t list_ip = simterpose_get_ip_list();

  xbt_dynar_t no_ip_list = xbt_dynar_new(sizeof(int), NULL);
  xbt_dynar_t ip_list = xbt_dynar_new(sizeof(unsigned int), NULL);

  xbt_dynar_t host_list = MSG_hosts_as_dynar();
  const msg_host_t *work_list = xbt_dynar_to_array(host_list);
  int i;

  int size = MSG_get_host_number();

  for (i = 0; i < size; ++i) {
    const char *prop = MSG_host_get_property_value(work_list[i], "ip");
    // If the host doesn't have an ip yet, we store it to attribute one later.
    if (prop == NULL) {
      xbt_dynar_push_as(no_ip_list, int, i);
      continue;
    } else {
      simterpose_host_t *temp = xbt_malloc0(sizeof(simterpose_host_t));
      temp->ip = inet_addr(prop);
      temp->port = xbt_dict_new_homogeneous(free);
      xbt_dict_set(list_s, MSG_host_get_name(work_list[i]), temp, NULL);
      xbt_dict_set(list_ip, prop, xbt_strdup(MSG_host_get_name(work_list[i])), NULL);
      xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
    }
  }

  unsigned int temp_ip = 1;
  xbt_ex_t e;
  // Now we have to give an ip to the workstations that don't have one
  while (!xbt_dynar_is_empty(no_ip_list)) {
    int i;
    xbt_dynar_shift(no_ip_list, &i);

    // Check that the ip is not used
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
    simterpose_host_t *temp = xbt_new0(simterpose_host_t,1);
    temp->ip = temp_ip;
    temp->port = xbt_dict_new_homogeneous(NULL);
    xbt_dict_set(list_s, MSG_host_get_name(work_list[i]), temp, NULL);
    xbt_dict_set(list_ip, inet_ntoa(in), xbt_strdup(MSG_host_get_name(work_list[i])), NULL);
    xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
  }

  xbt_dynar_free(&ip_list);
  xbt_dynar_free(&no_ip_list);
}
