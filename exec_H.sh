#!/bin/sh
qnvoice ${2} shutdown.dat 'System Shutdown'
sleep 5
shutdown -h now
