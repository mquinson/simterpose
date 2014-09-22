#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml allpairs_deploy.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  # --log=root.fmt:"'[%P on %h]: %m%n'"