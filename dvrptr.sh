#!/bin/bash

while [ 1 ];
do
        /usr/local/bin/dvrptr /usr/local/etc/dvrptr.cfg > /var/log/dvrptr.log 2>&1
        sleep 3
done

exit 0

