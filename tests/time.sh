#!/bin/bash

set -e # fail fast

rm -f simterpose-time.log
make -C ../src/ simterpose
make -C apps/ time

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

debug=$2

LD_LIBRARY_PATH=$sim_dir/lib/
export LD_LIBRARY_PATH

if [ "$1" != "LD_PRELOAD" ]; then 
echo -e "You cannot launch this script without LD_PRELOAD and the interception library libsgtime.so \nUse LD_PRELOAD=../src/libsgtime.so \nOtherwise FIXME!"
else
sudo LD_PRELOAD=../src/libsgtime.so $debug ../src/simterpose -s multicore_machine.xml time.xml
fi
