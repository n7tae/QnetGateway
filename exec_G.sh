#!/bin/sh
qnvoice ${2} gatewayrestart.dat 'Gateway Restart'
sleep 5
systemctl restart qngateway
