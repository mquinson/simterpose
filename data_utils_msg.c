#include "simterpose_msg.h"
#include "data_utils_msg.h"
#include "process_descriptor_msg.h"
#include "cputimer_msg.h"
#include "xbt.h"
#include "sockets_msg.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(DATA_UTILS_MSG, simterpose, "data_utils log");

struct simterpose_globals {
  xbt_dynar_t future_events_set;
  process_descriptor_t *process_desc[MAX_PID];
  xbt_dict_t list_host;
  xbt_dict_t list_ip;
  xbt_dict_t list_translate;
  time_t init_time;
  int child_amount;
  float msec_per_flop;
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

void simterpose_globals_init(float msec_per_flop)
{
  global_data = malloc(sizeof(simterpose_data_t));
  global_data->msec_per_flop = msec_per_flop;

  global_data->child_amount = 0;
  global_data->list_host = xbt_dict_new_homogeneous(&destroy_simterpose_host);
  global_data->list_ip = xbt_dict_new_homogeneous(&free);
  global_data->list_translate = xbt_dict_new_homogeneous(&free);
  global_data->init_time = time(NULL);

  int i;
  for (i = 0; i < MAX_PID; ++i) {
    global_data->process_desc[i] = NULL;
  }
  global_data->nb_peek = 0;
  global_data->nb_poke = 0;
  global_data->nb_getregs = 0;
  global_data->nb_setregs = 0;
  global_data->nb_syscall = 0;
  global_data->nb_setoptions = 0;
  global_data->nb_detach = 0;
  global_data->nb_geteventmsg = 0;
}

int get_nb_peek(void)
{
  return global_data->nb_peek;
}

int get_nb_poke()
{
  return global_data->nb_poke;
}

int get_nb_getregs()
{
  return global_data->nb_getregs;
}

int get_nb_setregs()
{
  return global_data->nb_setregs;
}

int get_nb_syscall()
{
  return global_data->nb_syscall;
}

int get_nb_setoptions()
{
  return global_data->nb_setoptions;
}

int get_nb_detach()
{
  return global_data->nb_detach;
}

int get_nb_geteventmsg()
{
  return global_data->nb_geteventmsg;
}

void increment_nb_peek()
{
  global_data->nb_peek++;
}

void increment_nb_poke()
{
  global_data->nb_poke++;
}

void increment_nb_getregs()
{
  global_data->nb_getregs++;
}

void increment_nb_setregs()
{
  global_data->nb_setregs++;
}

void increment_nb_syscall()
{
  global_data->nb_syscall++;
}

void increment_nb_setoptions()
{
  global_data->nb_setoptions++;
}

void increment_nb_detach()
{
  global_data->nb_detach++;
}

void increment_nb_geteventmsg()
{
  global_data->nb_geteventmsg++;
}

void simterpose_globals_exit()
{
  xbt_dynar_free(&(global_data->future_events_set));
  xbt_dict_free(&(global_data->list_host));
  xbt_dict_free(&(global_data->list_ip));
  xbt_dict_free(&(global_data->list_translate));
  free(global_data);
}

void destroy_simterpose_host(void *data)
{
  simterpose_host_t *host = (simterpose_host_t *) data;
  xbt_dict_free(&(host->port));
  free(host);
}

int is_port_in_use(msg_host_t host, int port)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  return (xbt_dict_get_or_null(temp->port, buff) != NULL);
}

void register_port(msg_host_t host, int port)
{
  //try to see if port isn't already use.
  simterpose_host_t *host_desc =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *temp = NULL;


  if ((temp = (port_desc_t *) xbt_dict_get_or_null(host_desc->port, buff))) {
    ++(temp->amount_socket);
  } else {
    temp = malloc(sizeof(port_desc_t));
    temp->port_num = port;
    temp->option = 0;
    temp->amount_socket = 1;
    temp->bind_socket = NULL;

    xbt_dict_set(host_desc->port, buff, temp, NULL);
  }
}

int get_port_option(msg_host_t host, int port)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (!desc)
    return 0;
  else
    return desc->option;
}

void set_port_option(msg_host_t host, int port, int option)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (desc)
    desc->option = option;
}

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
}

struct infos_socket *get_binding_socket(unsigned int ip, int port, int nature)
{
  struct in_addr in = { ip };
  char *ip_dot = inet_ntoa(in);

  char *host_name = xbt_dict_get(global_data->list_ip, ip_dot);
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, host_name);
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);


  if (desc == NULL || !(desc->option & PORT_BIND))
    return NULL;

  if (!(nature & desc->option))
    return NULL;

  return desc->bind_socket;
}

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

void set_real_port(msg_host_t host, int port, int real_port)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL)
    return;
  XBT_DEBUG("Set correspondance %d <-> %d (real) for %s",port, real_port, MSG_host_get_name(host));
  desc->real_port = real_port;
}

unsigned int get_ip_of_host(msg_host_t host)
{
  simterpose_host_t *temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, MSG_host_get_name(host));
  return temp->ip;
}

msg_host_t get_host_by_ip(unsigned int ip)
{
  struct in_addr in = { ip };
  char *name = xbt_dict_get_or_null(global_data->list_ip, inet_ntoa(in));
  if (!name)
    return NULL;

  return MSG_get_host_by_name(name);
}

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

  if (is == desc->bind_socket)
    desc->bind_socket = NULL;

  --desc->amount_socket;
  if (desc->amount_socket)
    return;

  //if this is the last socket to use te port, we have to remove it from dict
  xbt_dict_remove(temp->port, buff);
}


time_t get_simulated_timestamp()
{
  return global_data->init_time + MSG_get_clock();
}

void add_new_translation(int real_port, int translated_port, unsigned int translated_ip)
{
	XBT_DEBUG("Add new translation %d->%d", real_port, translated_port);
  translate_desc_t *temp = malloc(sizeof(translate_desc_t));
  temp->port_num = translated_port;
  temp->ip = translated_ip;

  char buff[6];
  sprintf(buff, "%d", real_port);

  xbt_dict_set(global_data->list_translate, buff, temp, NULL);
}


translate_desc_t *get_translation(int real_port)
{
XBT_DEBUG("Get translation for port %d", real_port);
  char buff[6];
  sprintf(buff, "%d", real_port);

  return xbt_dict_get_or_null(global_data->list_translate, buff);
}

int get_real_port(process_descriptor_t *proc, unsigned int ip, int port)
{
// struct in_addr in = {ip};
// XBT_DEBUG("Searching for real port of %s:%d", inet_ntoa(in), port);
  simterpose_host_t *temp = NULL;
  if (ip == inet_addr("127.0.0.1")) {
XBT_DEBUG("We are on local network %d\n",port);
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

double simterpose_get_msec_per_flop()
{
  return global_data->msec_per_flop;
}

xbt_dict_t simterpose_get_host_list()
{
  return global_data->list_host;
}

xbt_dict_t simterpose_get_ip_list()
{
  return global_data->list_ip;
}


/* Get the power of the current machine from a simple matrix product operation */
void benchmark_matrix_product(float *msec_per_flop)
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
  XBT_INFO("Duration of benchmark : %lld", result);

  *msec_per_flop = ((float) result) / (2. * matrixSize * matrixSize * matrixSize);
  float flop_per_sec = (1000000.) / (*msec_per_flop);

  XBT_INFO("Your machine was benchmarked at %.0f flop/s (use -p %.0f to avoid that benchmarking)", flop_per_sec,
           flop_per_sec);

  cputimer_exit(timer_benchmark);
}

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
    //if there are no ip set, we store them to attribute one after.
    if (prop == NULL) {
      xbt_dynar_push_as(no_ip_list, int, i);
      continue;
    } else {
      simterpose_host_t *temp = malloc(sizeof(simterpose_host_t));
      temp->ip = inet_addr(prop);
      temp->port = xbt_dict_new_homogeneous(free);
      xbt_dict_set(list_s, MSG_host_get_name(work_list[i]), temp, NULL);
      xbt_dict_set(list_ip, prop, strdup(MSG_host_get_name(work_list[i])), NULL);
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
    xbt_dict_set(list_s, MSG_host_get_name(work_list[i]), temp, NULL);
    xbt_dict_set(list_ip, inet_ntoa(in), strdup(MSG_host_get_name(work_list[i])), NULL);
    xbt_dynar_push_as(ip_list, unsigned int, temp->ip);
  }

  xbt_dynar_free(&ip_list);
  xbt_dynar_free(&no_ip_list);
}

