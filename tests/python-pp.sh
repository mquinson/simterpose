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

if [ $# -ne 1 ]; then
echo 'Please enter one argument to specify the version of SimGrid that you want to use:'
echo '"new_version" for the last version or "old_version" for another one'
exit
fi

if [[ $1 == "new_version" ]]; then  
# To compile with a new version of SimGrid
sudo  LD_LIBRARY_PATH=/opt/Simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  # --log=root.fmt:"'[%P on %h]: %m%n'"
else
# To compile with an old version of SimGrid
sudo LD_LIBRARY_PATH=/opt/simgrid/lib/  ../src/simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  # --log=root.fmt:"'[%P on %h]: %m%n'
fi

rm deploy_temp.xml
