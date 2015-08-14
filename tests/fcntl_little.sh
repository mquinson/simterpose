#!/bin/bash

set -e # fail fast

rm -f simterpose-fcntl_little.log
make -C ../src/ simterpose
make -C apps/   fcntl_little

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$1

LD_LIBRARY_PATH=$sim_dir/lib/
export LD_LIBRARY_PATH

sudo LD_PRELOAD=../src/libsgtime.so $runner ../src/simterpose -s multicore_machine.xml fcntl_little.xml
