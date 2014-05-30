#ifndef SIMTERPOSE_GLOBALS_H
#define SIMTERPOSE_GLOBALS_H

#include <sys/types.h>
#include "simdag/simdag.h"
#include "sockets.h"

void simterpose_globals_init(float msec_per_flop);
void simterpose_globals_exit(void);

int get_nb_peek(void);

int get_nb_poke(void);

int get_nb_getregs(void);

int get_nb_setregs(void);

int get_nb_syscall(void);

int get_nb_setoptions(void);

int get_nb_detach(void);

int get_nb_geteventmsg(void);

void increment_nb_peek(void);

void increment_nb_poke(void);

void increment_nb_getregs(void);

void increment_nb_setregs(void);

void increment_nb_syscall(void);

void increment_nb_setoptions(void);

void increment_nb_detach(void);

void increment_nb_geteventmsg(void);

double simterpose_get_msec_per_flop(void);

xbt_dict_t simterpose_get_host_list(void);
xbt_dict_t simterpose_get_ip_list(void);

double update_simulation_clock(void);

pid_t FES_pop_next_pid(void);

double FES_peek_next_date(void);

void FES_schedule_at(pid_t pid, double start_time);

void FES_schedule_now(pid_t pid);

int FES_contains_events(void);

void FES_push_timeout(pid_t pid, double start_time);

void FES_remove_timeout(pid_t pid);

void destroy_simterpose_host(void *host);

int is_port_in_use(SD_workstation_t host, int port);

void register_port(SD_workstation_t host, int port);

int get_port_option(SD_workstation_t host, int port);

void set_port_option(SD_workstation_t host, int port, int option);

void set_port_on_binding(SD_workstation_t host, int port, struct infos_socket *is, int device);

struct infos_socket *get_binding_socket(unsigned int ip, int port, int nature);

struct infos_socket *get_binding_socket_host(SD_workstation_t host, int port, int device);

unsigned int get_ip_of_host(SD_workstation_t host);

SD_workstation_t get_host_by_ip(unsigned int ip);

int get_random_port(SD_workstation_t host);

void unset_socket(pid_t pid, struct infos_socket *is);

time_t get_simulated_timestamp(void);

void set_real_port(SD_workstation_t host, int port, int real_port);

void add_new_translation(int real_port, int translated_port, unsigned int translated_ip);

translate_desc_t *get_translation(int real_port);

int get_real_port(pid_t pid, unsigned int ip, int port);

#endif                          /* SIMTERPOSE_GLOBALS_H */
