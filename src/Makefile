OBJS = args_trace.o communication.o cputimer.o data_utils.o \
print_syscall.o process_descriptor.o ptrace_utils.o simterpose.o \
 sockets.o syscall_process.o sys_accept.o sys_bind.o sys_brk.o sys_clone.o sys_close.o \
 sys_connect.o sys_create.o sys_dup2.o sys_execve.o sys_exit.o \
sys_fcntl.o sys_getpeername.o sys_getsockopt.o sys_listen.o sys_open.o sys_pipe.o sys_pool.o sys_read.o sys_recvfrom.o sys_recvmsg.o sys_select.o \
sys_sendmsg.o sys_sendto.o sys_setsockopt.o sys_shutdown.o sys_socket.o sys_write.o sys_network.o sys_process.o \
 xbt_log_strace.o

CFLAGS = -Wall -Werror -g -I/opt/Simgrid/include/ 
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L/opt/Simgrid/lib/ -lsimgrid -lm

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
sys_accept.o: sys_accept.c sys_accept.h
sys_bind.o: sys_bind.c sys_bind.h
sys_brk.o: sys_brk.c sys_brk.h
sys_clone.o: sys_clone.c sys_clone.h
sys_close.o: sys_close.c sys_close.h
sys_connect.o: sys_connect.c sys_connect.h
sys_create.o: sys_create.c sys_create.h
sys_dup2.o: sys_dup2.c sys_dup2.h
sys_execve.o: sys_execve.c sys_execve.h
sys_exit.o: sys_exit.c sys_exit.h
sys_fcntl.o: sys_fcntl.c sys_fcntl.h
sys_getpeername.o: sys_getpeername.c sys_getpeername.h
sys_getsockopt.o: sys_getsockopt.c sys_getsockopt.h
sys_listen.o: sys_listen.c sys_listen.h
sys_open.o: sys_open.c sys_open.h
sys_pipe.o: sys_pipe.c sys_pipe.h
sys_pool.o: sys_pool.c sys_pool.h
sys_read.o: sys_read.c sys_read.h
sys_recvfrom.o: sys_recvfrom.c sys_recvfrom.h
sys_recvmsg.o: sys_recvmsg.c sys_recvmsg.h
sys_select.o: sys_select.c sys_select.h
sys_sendmsg.o: sys_sendmsg.c sys_sendmsg.h
sys_sendto.o: sys_sendto.c sys_sendto.h
sys_setsockopt.o: sys_setsockopt.c sys_setsockopt.h
sys_shutdown.o: sys_shutdown.c sys_shutdown.h
sys_socket.o: sys_socket.c sys_socket.h
sys_write.o: sys_write.c sys_write.h
sys_network.o: sys_network.c sys_network.h
sys_process.o: sys_process.c sys_process.h

#################################################

clean:
	rm -rf simterpose *.o *~

