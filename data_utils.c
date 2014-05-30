#include "simterpose.h"
#include "data_utils.h"
#include "process_descriptor.h"
#include "xbt.h"
#include "sockets.h"
#include "simdag/simdag.h"      /* For SD_get_clock() */

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
  global_data->future_events_set = xbt_dynar_new(sizeof(process_descriptor_t *), NULL);
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

int get_nb_peek(void){
	return global_data->nb_peek;
}

int get_nb_poke(){
	return global_data->nb_poke;
}

int get_nb_getregs(){
	return global_data->nb_getregs;
}

int get_nb_setregs(){
	return global_data->nb_setregs;
}

int get_nb_syscall(){
	return global_data->nb_syscall;
}

int get_nb_setoptions(){
	return global_data->nb_setoptions;
}

int get_nb_detach(){
	return global_data->nb_detach;
}

int get_nb_geteventmsg(){
	return global_data->nb_geteventmsg;
}

void increment_nb_peek(){
	global_data->nb_peek++;
}

void increment_nb_poke(){
	global_data->nb_poke++;
}

void increment_nb_getregs(){
	global_data->nb_getregs++;
}

void increment_nb_setregs(){
	global_data->nb_setregs++;
}

void increment_nb_syscall(){
	global_data->nb_syscall++;
}

void increment_nb_setoptions(){
	global_data->nb_setoptions++;
}

void increment_nb_detach(){
	global_data->nb_detach++;
}

void increment_nb_geteventmsg(){
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

double FES_peek_next_date()
{
  if (xbt_dynar_is_empty(global_data->future_events_set))
    return -1;

  process_descriptor_t **p = (process_descriptor_t **) xbt_dynar_get_ptr(global_data->future_events_set, 0);
//   printf("Next start_time %lf\n", (*t)->start_time);
  return (*p)->next_event;
}

pid_t FES_pop_next_pid()
{
  process_descriptor_t *proc = NULL;
  xbt_dynar_shift(global_data->future_events_set, &proc);
  int res = proc->pid;

  if (proc->in_timeout == PROC_IN_TIMEOUT)
    proc->in_timeout = PROC_TIMEOUT_EXPIRE;
  proc->timeout = NULL;

  return res;
}

void FES_schedule_at(pid_t pid, double start_time)
{
	process_descriptor_t *proc = process_get_descriptor(pid);
  proc->next_event = start_time;

  xbt_dynar_push(global_data->future_events_set, &proc);
}

void FES_schedule_now(pid_t pid)
{
  process_descriptor_t *proc = process_get_descriptor(pid);
  proc->next_event = SD_get_clock();

  xbt_dynar_unshift(global_data->future_events_set, &proc);
}

int FES_contains_events()
{
  return !xbt_dynar_is_empty(global_data->future_events_set);
}

void FES_push_timeout(pid_t pid, double start_time)
{

  if (start_time == SD_get_clock())
    start_time += 0.0001;
//   printf("Add new timeout of %lf for %d\n", start_time, pid);

  process_descriptor_t *proc = process_get_descriptor(pid);
  proc->next_event = start_time;
  proc->in_timeout = PROC_IN_TIMEOUT;

  int i = 0;
  while (i < xbt_dynar_length(global_data->future_events_set)) {
	process_descriptor_t **p = xbt_dynar_get_ptr(global_data->future_events_set, i);
    if (start_time < (*p)->next_event)
      break;
    ++i;
  }
  xbt_dynar_insert_at(global_data->future_events_set, i, &proc);
}

void FES_remove_timeout(pid_t pid)
{
  process_descriptor_t *proc = process_get_descriptor(pid);
  proc->in_timeout = PROC_NO_TIMEOUT;

  xbt_ex_t e;
  TRY {
    int i = xbt_dynar_search(global_data->future_events_set, &proc);
    xbt_dynar_remove_at(global_data->future_events_set, i, NULL);
  }
  CATCH(e) {
    printf("Timeout not found %d\n", xbt_dynar_is_empty(global_data->future_events_set));
  }
}

int is_port_in_use(SD_workstation_t host, int port)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  return (xbt_dict_get_or_null(temp->port, buff) != NULL);
}

void register_port(SD_workstation_t host, int port)
{
  //try to see if port isn't already use.
  simterpose_host_t *host_desc =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
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

int get_port_option(SD_workstation_t host, int port)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (!desc)
    return 0;
  else
    return desc->option;
}

void set_port_option(SD_workstation_t host, int port, int option)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);

  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);
  if (desc)
    desc->option = option;
}

void set_port_on_binding(SD_workstation_t host, int port, struct infos_socket *is, int device)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
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

struct infos_socket *get_binding_socket_host(SD_workstation_t host, int port, int device)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL || !(desc->option & PORT_BIND))
    return NULL;

  if (!(device & desc->option))
    return NULL;

  return desc->bind_socket;
}

void set_real_port(SD_workstation_t host, int port, int real_port)
{

  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL)
    return;
//   printf("Set correspondance %d <-> %d (real) for %s\n",port, real_port, SD_workstation_get_name(station));
  desc->real_port = real_port;
}

unsigned int get_ip_of_host(SD_workstation_t host)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
  return temp->ip;
}

SD_workstation_t get_host_by_ip(unsigned int ip)
{
  struct in_addr in = { ip };
  char *name = xbt_dict_get_or_null(global_data->list_ip, inet_ntoa(in));
  if (!name)
    return NULL;

  return SD_workstation_get_by_name(name);
}

int get_random_port(SD_workstation_t host)
{
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));
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
  SD_workstation_t host = is->host;
  simterpose_host_t *temp =
      (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(host));

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
  return global_data->init_time + SD_get_clock();
}

void add_new_translation(int real_port, int translated_port, unsigned int translated_ip)
{
//   printf("Add new translation %d->%d\n", real_port, translated_port);
  translate_desc_t *temp = malloc(sizeof(translate_desc_t));
  temp->port_num = translated_port;
  temp->ip = translated_ip;

  char buff[6];
  sprintf(buff, "%d", real_port);

  xbt_dict_set(global_data->list_translate, buff, temp, NULL);
}


translate_desc_t *get_translation(int real_port)
{
//   printf("Get translation for port %d\n", real_port);
  char buff[6];
  sprintf(buff, "%d", real_port);

  return xbt_dict_get_or_null(global_data->list_translate, buff);
}

int get_real_port(pid_t pid, unsigned int ip, int port)
{
//   printf("Searching for ral port of %s:%d\n", inet_ntoa(in), port);
  simterpose_host_t *temp = NULL;
  if (ip == inet_addr("127.0.0.1")) {
//     printf("We are on local network %d\n",port);
    process_descriptor_t *proc = process_get_descriptor(pid);
    temp = (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(proc->host));
  } else
    temp =
        (simterpose_host_t *) xbt_dict_get(global_data->list_host, SD_workstation_get_name(get_host_by_ip(ip)));
  char buff[6];
  sprintf(buff, "%d", port);
  port_desc_t *desc = xbt_dict_get_or_null(temp->port, buff);

  if (desc == NULL)
    return -1;

//   printf("Return %d\n", desc->real_port);
  return desc->real_port;
}

process_descriptor_t *process_get_descriptor(pid_t pid)
{
  return global_data->process_desc[pid];
}

void process_set_descriptor(pid_t pid, process_descriptor_t * proc)
{
  global_data->process_desc[pid] = proc;
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
