#!/bin/bash
# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

for i in $( ls examples/*.ioc.xml | sed 's/examples\///' | sed 's/\.ioc\.xml//'); do
    echo Updating example: $i
    python openioc-to-stix.py -i examples/${i}.ioc.xml -o examples/${i}.stix.xml
done
