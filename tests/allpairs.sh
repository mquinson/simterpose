#!/bin/bash

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="/usr/bin/allpairs_master" start_time="0.00">
    <argument value="applications/allpairs/set.list"/>
    <argument value="applications/allpairs/set.list"/>
    <argument value="applications/allpairs/compare"/>
  </process>
  <process host="Jupiter" function="/usr/bin/work_queue_worker" start_time="2.0">
    <argument value="localhost"/>
    <argument value="9123"/>
  </process>
</platform>
EOF

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  # --log=root.fmt:"'[%P on %h]: %m%n'"

rm deploy_temp.xml