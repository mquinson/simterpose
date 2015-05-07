OBJS = args_trace.o communication.o cputimer.o data_utils.o print_syscall.o \
       process_descriptor.o ptrace_utils.o simterpose.o sockets.o \
       sys_memory.o sys_network.o sys_process.o \
       xbt_log_strace.o  syscall_process.o  

CFLAGS = -Wall -Werror -g -I/opt/simgrid/include/
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L/opt/simgrid/lib/ -lsimgrid -lm

all : simterpose

simterpose: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

simterpose.o: simterpose.c simterpose.h 
args_trace.o: args_trace.c args_trace.h 
ptrace_utils.o: ptrace_utils.c ptrace_utils.h
process_descriptor.o: process_descriptor.c process_descriptor.h
syscall_process.o: syscall_process.c syscall_process.h 
data_utils.o : data_utils.c data_utils.h 
print_syscall.o: print_syscall.c print_syscall.h 
sockets.o: sockets.c sockets.h 
communication.o: communication.c communication.h
sys_memory.o: sys_memory.c sys_memory.h
sys_network.o: sys_network.c sys_network.h
sys_process.o: sys_process.c sys_process.h

#################################################

clean:
	rm -rf simterpose *.o *~
