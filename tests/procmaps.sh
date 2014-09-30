#!/bin/bash

set -e # fail fast

make -C ../src/ simterpose

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="/bin/cat" start_time="0.00">
    <argument value="/proc/self/maps"/> <!-- Port -->
  </process>
</platform>
EOF

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml #--log=simterpose.:debug #--log=simix_synchro.:debug  --log=msg.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'" #--log=simix.:debug
ret=$?

rm deploy_temp.xml

exit $ret