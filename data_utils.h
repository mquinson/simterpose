#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include <sys/types.h>
#include "simdag/simdag.h"
#include "sockets.h"

void init_global_data();

double update_simulation_clock();

pid_t pop_next_pid();

double get_next_start_time();

void add_launching_time(pid_t pid, double start_time);

void set_next_launchment(pid_t pid);

int has_sleeping_to_launch();

void add_timeout(pid_t pid, double start_time);

void remove_timeout(pid_t pid);

void destroy_global_data();

void destroy_simterpose_station(void *station);

int is_port_in_use(SD_workstation_t station, int port);

void register_port(SD_workstation_t station, int port);

int get_port_option(SD_workstation_t station, int port);

void set_port_option(SD_workstation_t station, int port, int option);

void set_port_on_binding(SD_workstation_t station, int port, struct infos_socket* is, int device);

struct infos_socket *get_binding_socket(unsigned int ip, int port, int nature);

struct infos_socket *get_binding_socket_workstation(SD_workstation_t station , int port, int device);

unsigned int get_ip_of_station(SD_workstation_t station);

SD_workstation_t get_station_by_ip(unsigned int ip);

int get_random_port(SD_workstation_t station);

#endif