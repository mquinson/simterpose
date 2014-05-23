OBJS = args_trace.o cputimer.o process_descriptor.o ptrace_utils.o sockets.o insert_trace.o simterpose.o syscall_process.o \
	data_utils.o task.o parser.o init.o communication.o print_syscall.o

CFLAGS = -Wall -Werror -g -I/opt/simgrid/include/ 
CC=gcc

LDFLAGS= -L/opt/simgrid/lib/ -lsimgrid -lm

all : simterpose launcher applications/client applications/server

simterpose: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

simterpose.o: simterpose.c simterpose.h cputimer.h process_descriptor.h  init.h\
		data_utils.h parser.h communication.h syscall_process.h  print_syscall.h
args_trace.o: args_trace.c args_trace.h ptrace_utils.h sysdep.h sockets.h communication.h syscall_data.h
calc_times_proc.o: calc_times_proc.c cputimer.h sysdep.h
insert_trace.o: insert_trace.c insert_trace.h sockets.h cputimer.h process_descriptor.h simterpose.h task.h
ptrace_utils.o: ptrace_utils.c ptrace_utils.h sysdep.h
process_descriptor.o: process_descriptor.c process_descriptor.h simterpose.h sockets.h data_utils.h
syscall_process.o: syscall_process.c syscall_process.h insert_trace.h sockets.h simterpose.h ptrace_utils.h \
		process_descriptor.h args_trace.h task.h communication.h print_syscall.h\
		syscall_data.h
data_utils.o : data_utils.c data_utils.h simterpose.h sysdep.h process_descriptor.h
task.o: task.c task.h simterpose.h data_utils.h sockets.h process_descriptor.h communication.h
parser.o: parser.c parser.h
print_syscall.o: print_syscall.c print_syscall.h syscall_data.h sockets.h
init.o: init.c init.h parser.h process_descriptor.h simterpose.h ptrace_utils.h data_utils.h\
		cputimer.h
sockets.o: sockets.c sockets.h simterpose.h sysdep.h task.h insert_trace.h communication.h
communication.o: communication.c communication.h sockets.h

#################################################
# launcher section
launcher: launcher.o
	$(CC) $(CFLAGS) -o launcher launcher.o $(LDFLAGS) 

launcher.o: launcher.c
	$(CC) $(CFLAGS) -c $< -o $@

#################################################
applications/client: applications/client.c
	make -C applications client
applications/server: applications/server.c
	make -C applications server


clean:
	rm -rf simterpose launcher *.o


