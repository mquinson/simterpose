#!/bin/bash

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="python-pp/sum_primes.py" start_time="0.00">
    <argument value="4"/>
  </process>
</platform>
EOF

# Allow to use another folder thant /opt/Simgrid to execute
sim_dir=$1

# Allow to run under valgrind or gdb easily
export VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
runner=$2

sudo  LD_LIBRARY_PATH=$sim_dir/lib/ $runner ../simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  # --log=root.fmt:"'[%P on %h]: %m%n'"

rm deploy_temp.xml
