#!/bin/bash

set -e # fail fast

make -C ../src/ simterpose
make -C apps/ time

# Allow to use another folder thant /opt/Simgrid to execute
sim_dir=$1

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$2

LD_LIBRARY_PATH=$sim_dir/lib/
LD_LIBRARY_PATH=../src/lib_time.so:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH
# export LD_PRELOAD=../src/lib_time.so
sudo LD_PRELOAD=../src/lib_time.so $runner ../src/simterpose -s multicore_machine.xml time.xml
