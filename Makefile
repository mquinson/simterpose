OBJS = args_trace.o syscalls_io.o calc_times_proc.o times_proc.o peek_data.o sockets.o insert_trace.o run_trace.o benchmark.o syscall_process.o replay.o data_utils.o

CFLAGS = -Wall -g 
CC=gcc

LDFLAGS= -lsimgrid

all : run_trace benchmark launcher

run_trace: $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

run_trace.o: run_trace.c run_trace.h insert_trace.h sysdep.h sockets.h syscalls_io.h calc_times_proc.h times_proc.h benchmark.h args_trace.h peek_data.h syscall_process.h replay.h\
		data_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

args_trace.o: args_trace.c args_trace.h peek_data.h sysdep.h sockets.h
	$(CC) $(CFLAGS) -c $< -o $@

benchmark.o: benchmark.c benchmark.h sysdep.h calc_times_proc.h 
	$(CC) $(CFLAGS) -c $< -o $@

calc_times_proc.o: calc_times_proc.c calc_times_proc.h sysdep.h sockets.h
	$(CC) $(CFLAGS) -c $< -o $@

insert_trace.o: insert_trace.c insert_trace.h sysdep.h sockets.h syscalls_io.h calc_times_proc.h times_proc.h run_trace.h
	$(CC) $(CFLAGS) -c $< -o $@

peek_data.o: peek_data.c peek_data.h sysdep.h
	$(CC) $(CFLAGS) -c $< -o $@

sockets.o: sockets.c sockets.h sysdep.h run_trace.h
	$(CC) $(CFLAGS) -c $< -o $@

syscalls_io.o: syscalls_io.c syscalls_io.h run_trace.h data_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

times_proc.o: times_proc.c times_proc.h sysdep.h
	$(CC) $(CFLAGS) -c $< -o $@

syscall_process.o: syscall_process.c syscall_process.h insert_trace.h sockets.h run_trace.h
	$(CC) $(CFLAGS) -c $< -o $@

replay.o : replay.c replay.h
	$(CC) $(CFLAGS) -c $< -o $@

data_utils.o : data_utils.c data_utils.h run_trace.h
	$(CC) $(CFLAGS) -c $< -o $@


#################################################
# launcher section
launcher: launcher.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o launcher launcher.c

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


