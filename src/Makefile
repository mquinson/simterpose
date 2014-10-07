OBJS = args_trace.o communication.o cputimer.o data_utils.o print_syscall.o \
       process_descriptor.o ptrace_utils.o simterpose.o sockets.o syscall_process.o \
       sys_mem.o sys_process.o \
       xbt_log_strace.o

CFLAGS = -Wall -Werror -g -I/opt/simgrid/include/
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L/opt/simgrid/lib/ -lsimgrid -lm

all : simterpose

simterpose: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

simterpose.o: simterpose.c simterpose.h process_descriptor.h \
	data_utils.h syscall_process.h  print_syscall.h
args_trace.o: args_trace.c args_trace.h ptrace_utils.h sysdep.h syscall_data.h
ptrace_utils.o: ptrace_utils.c ptrace_utils.h sysdep.h
process_descriptor.o: process_descriptor.c process_descriptor.h
syscall_process.o: syscall_process.c syscall_process.h sockets.h simterpose.h \
	ptrace_utils.h process_descriptor.h args_trace.h print_syscall.h
data_utils.o : data_utils.c data_utils.h sysdep.h process_descriptor.h cputimer.h
print_syscall.o: print_syscall.c print_syscall.h syscall_data.h  sockets.h
sockets.o: sockets.c sockets.h simterpose.h sysdep.h communication.h
communication.o: communication.c communication.h sockets.h
sys_mem.o: sys_mem.c syscall_process.h
sys_process.o: sys_process.c syscall_process.h

#################################################

clean:
	rm -rf simterpose *.o *~
	