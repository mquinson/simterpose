#!/bin/sh

#selon les arguments
# argument 1 = nb experience
# argument 2 = script
# argument 3 = LD_PRELOAD ou pas
# argument 4 = debug

# boucle sur le nombre d'experience
for i in `seq 1 $1`
do
    ./$2 $3 $4 1>mesure/$2.$i.1.txt 2>mesure/$2.$i.2.txt
done


