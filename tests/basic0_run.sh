#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml basic0_deploy.xml #--log=simterpose.:debug #--log=simix_synchro.:debug  --log=msg.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'" #--log=simix.:debug