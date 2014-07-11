#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ./simterpose -s plat.xml deploy_allpairs.xml --log=simterpose.:debug --log=simix_synchro.:debug  --log=msg.:debug --log=simix.:debug  #--log=root.fmt:"'%l: [%c/%p]: %m%n'"
