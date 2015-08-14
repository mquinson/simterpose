#!/bin/bash

set -e # fail fast

rm -f simterpose-sys_file.log
make -C ../src/ simterpose
make -C apps/ sys_file

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$1

LD_LIBRARY_PATH=$sim_dir/lib/
export LD_LIBRARY_PATH

# sudo $runner ../src/simterpose -s multicore_machine.xml sys_file.xml
sudo LD_PRELOAD=../src/libsgtime.so  $runner ../src/simterpose -s multicore_machine.xml sys_file.xml
