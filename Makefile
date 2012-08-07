OBJS = args_trace.o calc_times_proc.o process_descriptor.o ptrace_utils.o sockets.o insert_trace.o run_trace.o benchmark.o syscall_process.o replay.o\
	data_utils.o task.o parser.o init.o communication.o print_syscall.o

CFLAGS = -Wall -g
CC=gcc 

LDFLAGS= -lsimgrid -lm

all : run_trace launcher

run_trace: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

run_trace.o: run_trace.c run_trace.h calc_times_proc.h process_descriptor.h  init.h\
		data_utils.h parser.h communication.h syscall_process.h  print_syscall.h
	$(CC) $(CFLAGS) -c $< -o $@

args_trace.o: args_trace.c args_trace.h ptrace_utils.h sysdep.h sockets.h communication.h syscall_data.h
	$(CC) $(CFLAGS) -c $< -o $@

benchmark.o: benchmark.c benchmark.h calc_times_proc.h 
	$(CC) $(CFLAGS) -c $< -o $@

calc_times_proc.o: calc_times_proc.c calc_times_proc.h sysdep.h
	$(CC) $(CFLAGS) -c $< -o $@

insert_trace.o: insert_trace.c insert_trace.h sockets.h calc_times_proc.h process_descriptor.h run_trace.h \
		task.h
	$(CC) $(CFLAGS) -c $< -o $@

ptrace_utils.o: ptrace_utils.c ptrace_utils.h sysdep.h
	$(CC) $(CFLAGS) -c $< -o $@

process_descriptor.o: process_descriptor.c process_descriptor.h run_trace.h sockets.h data_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

syscall_process.o: syscall_process.c syscall_process.h insert_trace.h sockets.h run_trace.h ptrace_utils.h \
		process_descriptor.h args_trace.h task.h communication.h syscall_list.h print_syscall.h\
		syscall_data.h
	$(CC) $(CFLAGS) -c $< -o $@

#replay.o : replay.c replay.h
#	$(CC) $(CFLAGS) -c $< -o $@

data_utils.o : data_utils.c data_utils.h run_trace.h sysdep.h process_descriptor.h
	$(CC) $(CFLAGS) -c $< -o $@

task.o: task.c task.h run_trace.h data_utils.h sockets.h process_descriptor.h communication.h
	$(CC) $(CFLAGS) -c $< -o $@

parser.o: parser.c parser.h
	$(CC) $(CFLAGS) -c $< -o $@

print_syscall.o: print_syscall.c print_syscall.h syscall_data.h sockets.h
	$(CC) $(CFLAGS) -c $< -o $@

init.o: init.c init.h parser.h process_descriptor.h run_trace.h ptrace_utils.h data_utils.h\
		calc_times_proc.h benchmark.h
	$(CC) $(CFLAGS) -c $< -o $@

sockets.o: sockets.c sockets.h run_trace.h sysdep.h task.h insert_trace.h communication.h
	$(CC) $(CFLAGS) -c $< -o $@

communication.o: communication.c communication.h sockets.h
	$(CC) $(CFLAGS) -c $< -o $@

#################################################
# launcher section
launcher: launcher.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o launcher launcher.o

launcher.o: launcher.c
	$(CC) $(CFLAGS) -c $< -o $@

#################################################


#################################################
# benchmark test section
benchmark: run_benchmark.o benchmark.o calc_times_proc.o
	$(CC) $^ -o $@ $(LDFLAGS)

run_benchmark.o: run_benchmark.c
	$(CC) $(CFLAGS) -c $< -o $@

#################################################

clean:
	rm -rf run_trace benchmark launcher *.o


