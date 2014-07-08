OBJS = args_trace_msg.o communication_msg.o cputimer_msg.o data_utils_msg.o print_syscall_msg.o \
process_descriptor_msg.o ptrace_utils_msg.o simterpose_msg.o sockets_msg.o syscall_process_msg.o task_msg.o

CFLAGS = -Wall -Werror -g -I/opt/simgrid/include/
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L/opt/simgrid/lib/ -lsimgrid -lm

all : simterpose_msg applications/client applications/server applications/client_msg applications/server_msg

simterpose_msg: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

simterpose_msg.o: simterpose_msg.c simterpose_msg.h process_descriptor_msg.h \
	data_utils_msg.h syscall_process_msg.h  print_syscall_msg.h
args_trace_msg.o: args_trace_msg.c args_trace_msg.h ptrace_utils_msg.h sysdep.h syscall_data_msg.h
ptrace_utils_msg.o: ptrace_utils_msg.c ptrace_utils_msg.h sysdep.h
process_descriptor_msg.o: process_descriptor_msg.c process_descriptor_msg.h
syscall_process_msg.o: syscall_process_msg.c syscall_process_msg.h sockets_msg.h simterpose_msg.h \
	ptrace_utils_msg.h process_descriptor_msg.h args_trace_msg.h print_syscall_msg.h
data_utils_msg.o : data_utils_msg.c data_utils_msg.h sysdep.h process_descriptor_msg.h cputimer_msg.h
task_msg.o: task_msg.c task_msg.h simterpose_msg.h data_utils_msg.h sockets_msg.h process_descriptor_msg.h communication_msg.h
print_syscall_msg.o: print_syscall_msg.c print_syscall_msg.h syscall_data_msg.h  sockets_msg.h
sockets_msg.o: sockets_msg.c sockets_msg.h simterpose_msg.h sysdep.h communication_msg.h
communication_msg.o: communication_msg.c communication_msg.h sockets_msg.h

#################################################
applications/client: applications/client.c
	make -C applications client
applications/server: applications/server.c
	make -C applications server
applications/client_msg: applications/client_msg.c
	make -C applications client_msg
applications/server_msg: applications/server_msg.c
	make -C applications server_msg

clean:
	rm -rf simterpose_msg *.o
	make -C applications clean	
	