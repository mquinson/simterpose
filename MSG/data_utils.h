#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include <sys/types.h>
#include "simdag/simdag.h"
#include "sockets.h"

void simterpose_globals_init();

double update_simulation_clock();

pid_t pop_next_pid();

double get_next_start_time();

void add_launching_time(pid_t pid, double start_time);

void set_next_launchment(pid_t pid);

int has_sleeping_to_launch();

void add_timeout(pid_t pid, double start_time);

void remove_timeout(pid_t pid);

void simterpose_globals_exit();

void destroy_simterpose_station(void *station);

int is_port_in_use(msg_host_t host, int port);

void register_port(msg_host_t host, int port);

int get_port_option(msg_host_t host, int port);

void set_port_option(msg_host_t host, int port, int option);

void set_port_on_binding(msg_host_t host, int port, struct infos_socket* is, int device);

struct infos_socket *get_binding_socket(unsigned int ip, int port, int nature);

struct infos_socket *get_binding_socket_host(msg_host_t host , int port, int device);

unsigned int get_ip_of_host(msg_host_t host);

msg_host_t get_host_by_ip(unsigned int ip);

int get_random_port(msg_host_t host);

void unset_socket(pid_t pid, struct infos_socket* is);

time_t get_simulated_timestamp();

void set_real_port(msg_host_t host, int port, int real_port);

void add_new_translation(int real_port, int translated_port, unsigned int translated_ip);

translate_desc* get_translation(int real_port);

int get_real_port(pid_t pid, unsigned int ip, int port);

#endif
