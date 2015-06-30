#!/bin/sh

set -e

# Allow to use another folder thant /opt/Simgrid to execute
sim_dir=$1

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$2

LD_LIBRARY_PATH=$sim_dir/lib/
export LD_LIBRARY_PATH

sudo $runner ../src/simterpose -s platform.xml python-pp.xml \
  --log=simterpose.:debug --log=simix_synchro.:debug \
  --log=msg.:debug --log=simix.:debug
#--log=root.fmt:"'%l: [%c/%p]: %m%n'"
# --log=root.fmt:"'[%P on %h]: %m%n'"
