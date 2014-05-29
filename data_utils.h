#ifndef SIMTERPOSE_GLOBALS_H
#define SIMTERPOSE_GLOBALS_H

#include <sys/types.h>
#include "simdag/simdag.h"
#include "sockets.h"

void simterpose_globals_init(float msec_per_flop);
void simterpose_globals_exit(void);

double simterpose_get_msec_per_flop(void);

xbt_dict_t simterpose_get_station_list(void);
xbt_dict_t simterpose_get_ip_list(void);

double update_simulation_clock(void);

pid_t pop_next_pid(void);

double get_next_start_time(void);

void add_launching_time(pid_t pid, double start_time);

void set_next_launchment(pid_t pid);

int has_sleeping_to_launch(void);

void add_timeout(pid_t pid, double start_time);

void remove_timeout(pid_t pid);

void destroy_simterpose_station(void *station);

int is_port_in_use(SD_workstation_t station, int port);

void register_port(SD_workstation_t station, int port);

int get_port_option(SD_workstation_t station, int port);

void set_port_option(SD_workstation_t station, int port, int option);

void set_port_on_binding(SD_workstation_t station, int port, struct infos_socket *is, int device);

struct infos_socket *get_binding_socket(unsigned int ip, int port, int nature);

struct infos_socket *get_binding_socket_workstation(SD_workstation_t station, int port, int device);

unsigned int get_ip_of_station(SD_workstation_t station);

SD_workstation_t get_station_by_ip(unsigned int ip);

int get_random_port(SD_workstation_t station);

void unset_socket(pid_t pid, struct infos_socket *is);

time_t get_simulated_timestamp(void);

void set_real_port(SD_workstation_t station, int port, int real_port);

void add_new_translation(int real_port, int translated_port, unsigned int translated_ip);

translate_desc_t *get_translation(int real_port);

int get_real_port(pid_t pid, unsigned int ip, int port);

#endif                          /* SIMTERPOSE_GLOBALS_H */
