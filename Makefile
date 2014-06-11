OBJS = args_trace.o cputimer.o process_descriptor.o ptrace_utils.o sockets.o insert_trace.o simterpose.o syscall_process.o \
	data_utils.o task.o parser.o init.o communication.o print_syscall.o

CFLAGS = -Wall -Werror -g -I/opt/simgrid/include/
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L/opt/simgrid/lib/ -lsimgrid -lm

all : simterpose simterpose_msg applications/client applications/server

simterpose: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

simterpose.o: simterpose.c simterpose.h cputimer.h process_descriptor.h \
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
init.o: init.c parser.h process_descriptor.h simterpose.h ptrace_utils.h data_utils.h\
		cputimer.h
sockets.o: sockets.c sockets.h simterpose.h sysdep.h task.h insert_trace.h communication.h
communication.o: communication.c communication.h sockets.h

#################################################
applications/client: applications/client.c
	make -C applications client
applications/server: applications/server.c
	make -C applications server


clean:
	rm -rf simterpose simterpose_msg *.o
	make -C applications clean	
#################################################
simterpose_msg: args_trace_msg.o data_utils_msg.o print_syscall_msg.o process_descriptor_msg.o ptrace_utils_msg.o simterpose_msg.o \
sockets_msg.o syscall_process_msg.o
	$(CC) $^ -o $@ $(LDFLAGS)
	
simterpose_msg.o: simterpose_msg.c simterpose_msg.h process_descriptor_msg.h \
	data_utils_msg.h syscall_process_msg.h  print_syscall_msg.h
args_trace_msg.o: args_trace_msg.c args_trace_msg.h ptrace_utils_msg.h sysdep.h syscall_data_msg.h
ptrace_utils_msg.o: ptrace_utils_msg.c ptrace_utils_msg.h sysdep.h
process_descriptor_msg.o: process_descriptor_msg.c process_descriptor_msg.h
syscall_process_msg.o: syscall_process_msg.c syscall_process_msg.h sockets_msg.h simterpose_msg.h ptrace_utils_msg.h \
	process_descriptor_msg.h args_trace_msg.h print_syscall_msg.h
data_utils_msg.o : data_utils_msg.c data_utils_msg.h sysdep.h process_descriptor_msg.h
print_syscall_msg.o: print_syscall_msg.c print_syscall_msg.h syscall_data_msg.h  sockets_msg.h
sockets_msg.o: sockets_msg.c sockets_msg.h simterpose_msg.h sysdep.h
