#!/bin/bash

for i in $( ls examples/*.ioc.xml | sed 's/examples\///' | sed 's/\.ioc\.xml//'); do
    echo Updating example: $i
    python openioc_to_stix.py -i examples/${i}.ioc.xml -o examples/${i}.stix.xml
done
