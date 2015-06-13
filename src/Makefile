SIM_DIR=/opt/Simgrid
INC=include
OBJ=../object

OBJS = $(OBJ)/args_trace.o $(OBJ)/communication.o $(OBJ)/cputimer.o \
 $(OBJ)/data_utils.o $(OBJ)/print_syscall.o $(OBJ)/process_descriptor.o \
 $(OBJ)/ptrace_utils.o $(OBJ)/simterpose.o $(OBJ)/sockets.o \
 $(OBJ)/syscall_process.o \
 $(OBJ)/sys_accept.o $(OBJ)/sys_bind.o $(OBJ)/sys_brk.o $(OBJ)/sys_clone.o \
 $(OBJ)/sys_close.o $(OBJ)/sys_connect.o $(OBJ)/sys_create.o $(OBJ)/sys_dup2.o \
 $(OBJ)/sys_execve.o $(OBJ)/sys_exit.o $(OBJ)/sys_fcntl.o $(OBJ)/sys_getpeername.o \
 $(OBJ)/sys_getsockopt.o $(OBJ)/sys_listen.o $(OBJ)/sys_open.o $(OBJ)/sys_pipe.o \
 $(OBJ)/sys_pool.o $(OBJ)/sys_read.o $(OBJ)/sys_recvfrom.o $(OBJ)/sys_recvmsg.o \
 $(OBJ)/sys_select.o $(OBJ)/sys_sendmsg.o $(OBJ)/sys_sendto.o \
 $(OBJ)/sys_setsockopt.o $(OBJ)/sys_shutdown.o $(OBJ)/sys_socket.o \
 $(OBJ)/sys_write.o \
 $(OBJ)/xbt_log_strace.o

CFLAGS = -Wall -Werror -g -I$(SIM_DIR)/include/ -I$(INC)
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

CC=gcc

LDFLAGS= -L$(SIM_DIR)/lib/ -lsimgrid -lm

all : dir simterpose

dir:
	@mkdir -p $(OBJ)

simterpose: $(OBJS)
	$(CC) -o ../$@ $^ $(LDFLAGS)

$(OBJ)/%.o: %.c
	$(CC)  -o $@ -c $< $(CFLAGS)

# $(OBJ)/simterpose.o: simterpose.c $(INC)/simterpose.h
# $(OBJ)/args_trace.o: args_trace.c $(INC)/args_trace.h
# $(OBJ)/ptrace_utils.o: ptrace_utils.c $(INC)/ptrace_utils.h
# $(OBJ)/process_descriptor.o: process_descriptor.c $(INC)/process_descriptor.h
# $(OBJ)/syscall_process.o: syscall_process.c $(INC)/syscall_process.h
# $(OBJ)/data_utils.o : data_utils.c $(INC)/data_utils.h
# $(OBJ)/print_syscall.o: print_syscall.c $(INC)/print_syscall.h
# $(OBJ)/sockets.o: sockets.c $(INC)/sockets.h
# $(OBJ)/communication.o: communication.c $(INC)/communication.h
# $(OBJ)/sys_accept.o: sys_accept.c $(INC)/sys_accept.h
# $(OBJ)/sys_bind.o: sys_bind.c $(INC)/sys_bind.h
# $(OBJ)/sys_brk.o: sys_brk.c $(INC)/sys_brk.h
# $(OBJ)/sys_clone.o: sys_clone.c $(INC)/sys_clone.h
# $(OBJ)/sys_close.o: sys_close.c $(INC)/sys_close.h
# $(OBJ)/sys_connect.o: sys_connect.c $(INC)/sys_connect.h
# sys_create.o: sys_create.c $(INC)/sys_create.h
# sys_dup2.o: sys_dup2.c $(INC)/sys_dup2.h
# sys_execve.o: sys_execve.c $(INC)/sys_execve.h
# sys_exit.o: sys_exit.c $(INC)/sys_exit.h
# sys_fcntl.o: sys_fcntl.c $(INC)/sys_fcntl.h
# sys_getpeername.o: sys_getpeername.c $(INC)/sys_getpeername.h
# sys_getsockopt.o: sys_getsockopt.c $(INC)/sys_getsockopt.h
# sys_listen.o: sys_listen.c $(INC)/sys_listen.h
# sys_open.o: sys_open.c $(INC)/sys_open.h
# sys_pipe.o: sys_pipe.c $(INC)/sys_pipe.h
# sys_pool.o: sys_pool.c $(INC)/sys_pool.h
# sys_read.o: sys_read.c $(INC)/sys_read.h
# sys_recvfrom.o: sys_recvfrom.c $(INC)/sys_recvfrom.h
# sys_recvmsg.o: sys_recvmsg.c $(INC)/sys_recvmsg.h
# sys_select.o: sys_select.c $(INC)/sys_select.h
# sys_sendmsg.o: sys_sendmsg.c $(INC)/sys_sendmsg.h
# sys_sendto.o: sys_sendto.c $(INC)/sys_sendto.h
# sys_setsockopt.o: sys_setsockopt.c $(INC)/sys_setsockopt.h
# sys_shutdown.o: sys_shutdown.c $(INC)/sys_shutdown.h
# sys_socket.o: sys_socket.c $(INC)/sys_socket.h
# sys_write.o: sys_write.c $(INC)/sys_write.h

#################################################

clean:
	rm -rf simterpose $(OBJ)/*.o *~

